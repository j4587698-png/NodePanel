using System.Threading.Channels;

namespace NodePanel.Core.Runtime;

// Aligns with xray-core transport/internet/splithttp/upload_queue.go:
// packet-up uploads are reordered by seq, while stream-up switches to a single reader.
internal sealed class RuntimeSplitHttpUploadQueue : IAsyncDisposable
{
    private readonly object _syncRoot = new();
    private readonly Channel<RuntimeSplitHttpUploadEntry> _entries;
    private readonly PriorityQueue<RuntimeSplitHttpUploadPacket, ulong> _heap = new();
    private readonly int _maxPackets;
    private Stream? _reader;
    private ulong _nextSequence;
    private bool _streamQueued;
    private bool _completed;
    private bool _disposed;

    public RuntimeSplitHttpUploadQueue(int maxPackets)
    {
        ArgumentOutOfRangeException.ThrowIfNegative(maxPackets);

        _maxPackets = maxPackets;
        _entries = Channel.CreateBounded<RuntimeSplitHttpUploadEntry>(
            new BoundedChannelOptions(Math.Max(1, maxPackets))
            {
                SingleReader = true,
                SingleWriter = false,
                FullMode = BoundedChannelFullMode.Wait
            });
    }

    public async ValueTask PushPayloadAsync(
        ReadOnlyMemory<byte> payload,
        ulong sequence,
        CancellationToken cancellationToken = default)
    {
        ThrowIfDisposed();
        if (payload.IsEmpty)
        {
            return;
        }

        await EnqueueAsync(
                RuntimeSplitHttpUploadEntry.CreatePayload(payload.ToArray(), sequence),
                cancellationToken)
            .ConfigureAwait(false);
    }

    public async ValueTask PushStreamAsync(
        Stream reader,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(reader);

        ThrowIfDisposed();
        try
        {
            await EnqueueAsync(
                    RuntimeSplitHttpUploadEntry.CreateReader(reader),
                    cancellationToken)
                .ConfigureAwait(false);
        }
        catch
        {
            await reader.DisposeAsync().ConfigureAwait(false);
            throw;
        }
    }

    public async ValueTask<int> ReadAsync(
        Memory<byte> buffer,
        CancellationToken cancellationToken = default)
    {
        ThrowIfDisposed();
        if (buffer.IsEmpty)
        {
            return 0;
        }

        while (true)
        {
            var reader = GetCurrentReader();
            if (reader is not null)
            {
                return await reader.ReadAsync(buffer, cancellationToken).ConfigureAwait(false);
            }

            if (IsCompletedWithoutReader())
            {
                return 0;
            }

            if (_heap.Count == 0)
            {
                var entry = await ReadNextEntryAsync(cancellationToken).ConfigureAwait(false);
                if (entry is null)
                {
                    return 0;
                }

                if (entry.Reader is not null)
                {
                    if (_heap.Count != 0)
                    {
                        throw new InvalidOperationException("SplitHTTP upload queue cannot mix stream-up and packet-up entries.");
                    }

                    SetCurrentReader(entry.Reader);
                    return await entry.Reader.ReadAsync(buffer, cancellationToken).ConfigureAwait(false);
                }

                _heap.Enqueue(
                    new RuntimeSplitHttpUploadPacket(entry.Payload!, entry.Sequence),
                    entry.Sequence);
            }

            while (_heap.Count > 0)
            {
                var packet = _heap.Dequeue();
                if (packet.Sequence == _nextSequence)
                {
                    var count = Math.Min(buffer.Length, packet.Payload.Length);
                    packet.Payload.AsSpan(0, count).CopyTo(buffer.Span);

                    if (count < packet.Payload.Length)
                    {
                        _heap.Enqueue(
                            new RuntimeSplitHttpUploadPacket(packet.Payload[count..], packet.Sequence),
                            packet.Sequence);
                    }
                    else
                    {
                        _nextSequence = packet.Sequence + 1;
                    }

                    return count;
                }

                if (packet.Sequence > _nextSequence)
                {
                    if (_heap.Count > _maxPackets)
                    {
                        throw new InvalidOperationException("SplitHTTP packet queue is too large.");
                    }

                    _heap.Enqueue(packet, packet.Sequence);

                    var entry = await ReadNextEntryAsync(cancellationToken).ConfigureAwait(false);
                    if (entry is null)
                    {
                        return 0;
                    }

                    if (entry.Reader is not null)
                    {
                        throw new InvalidOperationException("SplitHTTP upload queue cannot mix stream-up and packet-up entries.");
                    }

                    _heap.Enqueue(
                        new RuntimeSplitHttpUploadPacket(entry.Payload!, entry.Sequence),
                        entry.Sequence);
                    continue;
                }
            }
        }
    }

    public void Complete()
    {
        if (!TryBeginComplete(out var reader, out var pendingReaders))
        {
            return;
        }

        DisposeReaderSync(reader);
        DisposePendingReadersSync(pendingReaders);
    }

    public async ValueTask DisposeAsync()
    {
        if (!TryBeginDispose(out var reader, out var pendingReaders))
        {
            return;
        }

        if (reader is not null)
        {
            await reader.DisposeAsync().ConfigureAwait(false);
        }

        for (var index = 0; index < pendingReaders.Count; index++)
        {
            await pendingReaders[index].DisposeAsync().ConfigureAwait(false);
        }
    }

    private async ValueTask EnqueueAsync(
        RuntimeSplitHttpUploadEntry entry,
        CancellationToken cancellationToken)
    {
        var marksStreaming = entry.Reader is not null;
        lock (_syncRoot)
        {
            ThrowIfCompletedNoLock();
            if (_streamQueued)
            {
                throw new InvalidOperationException("SplitHTTP upload queue already switched to stream-up mode.");
            }

            if (marksStreaming)
            {
                _streamQueued = true;
            }
        }

        try
        {
            await _entries.Writer.WriteAsync(entry, cancellationToken).ConfigureAwait(false);
        }
        catch
        {
            if (marksStreaming)
            {
                lock (_syncRoot)
                {
                    if (!_completed && !_disposed)
                    {
                        _streamQueued = false;
                    }
                }
            }

            throw;
        }
    }

    private async ValueTask<RuntimeSplitHttpUploadEntry?> ReadNextEntryAsync(CancellationToken cancellationToken)
    {
        while (await _entries.Reader.WaitToReadAsync(cancellationToken).ConfigureAwait(false))
        {
            if (_entries.Reader.TryRead(out var entry))
            {
                return entry;
            }
        }

        return null;
    }

    private Stream? GetCurrentReader()
    {
        lock (_syncRoot)
        {
            return _reader;
        }
    }

    private void SetCurrentReader(Stream reader)
    {
        lock (_syncRoot)
        {
            _reader = reader;
        }
    }

    private bool IsCompletedWithoutReader()
    {
        lock (_syncRoot)
        {
            return _completed && _reader is null;
        }
    }

    private bool TryBeginComplete(
        out Stream? reader,
        out List<Stream> pendingReaders)
    {
        reader = null;
        pendingReaders = [];

        lock (_syncRoot)
        {
            if (_completed)
            {
                return false;
            }

            _completed = true;
            reader = _reader;
            _reader = null;
            _entries.Writer.TryComplete();
        }

        while (_entries.Reader.TryRead(out var entry))
        {
            if (entry.Reader is not null)
            {
                pendingReaders.Add(entry.Reader);
            }
        }

        return true;
    }

    private bool TryBeginDispose(
        out Stream? reader,
        out List<Stream> pendingReaders)
    {
        reader = null;
        pendingReaders = [];

        lock (_syncRoot)
        {
            if (_disposed)
            {
                return false;
            }

            _disposed = true;
            _completed = true;
            reader = _reader;
            _reader = null;
            _entries.Writer.TryComplete();
        }

        while (_entries.Reader.TryRead(out var entry))
        {
            if (entry.Reader is not null)
            {
                pendingReaders.Add(entry.Reader);
            }
        }

        return true;
    }

    private static void DisposeReaderSync(Stream? reader)
    {
        if (reader is null)
        {
            return;
        }

        reader.Dispose();
    }

    private static void DisposePendingReadersSync(IReadOnlyList<Stream> readers)
    {
        for (var index = 0; index < readers.Count; index++)
        {
            readers[index].Dispose();
        }
    }

    private void ThrowIfDisposed()
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
    }

    private void ThrowIfCompletedNoLock()
    {
        if (_disposed)
        {
            throw new ObjectDisposedException(GetType().FullName);
        }

        if (_completed)
        {
            throw new InvalidOperationException("SplitHTTP upload queue is closed.");
        }
    }

    private sealed record RuntimeSplitHttpUploadPacket(byte[] Payload, ulong Sequence);

    private sealed record RuntimeSplitHttpUploadEntry
    {
        public byte[]? Payload { get; init; }

        public ulong Sequence { get; init; }

        public Stream? Reader { get; init; }

        public static RuntimeSplitHttpUploadEntry CreatePayload(byte[] payload, ulong sequence)
        {
            ArgumentNullException.ThrowIfNull(payload);
            return new RuntimeSplitHttpUploadEntry
            {
                Payload = payload,
                Sequence = sequence
            };
        }

        public static RuntimeSplitHttpUploadEntry CreateReader(Stream reader)
        {
            ArgumentNullException.ThrowIfNull(reader);
            return new RuntimeSplitHttpUploadEntry
            {
                Reader = reader
            };
        }
    }
}

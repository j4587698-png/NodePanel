using System.Buffers.Binary;
using System.Diagnostics;
using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography;

namespace NodePanel.Core.Runtime;

internal sealed class MkcpTransportFactory : IRuntimeInternetTransportFactory
{
    public string Name => RuntimeInternetTransportProtocols.Mkcp;

    public ValueTask ApplyAsync(
        RuntimeInternetConnectionContext context,
        RuntimeInternetStack stack,
        IRuntimeInternetOptions options,
        byte[]? transportInitializationData,
        CancellationToken cancellationToken)
    {
        if (transportInitializationData is not null && transportInitializationData.Length > 0)
        {
            throw new NotSupportedException("mKCP transport does not support transport initialization payloads.");
        }

        return ValueTask.CompletedTask;
    }
}

internal static class RuntimeKcpStreamFactory
{
    public static async ValueTask<Stream> OpenAsync<TOptions>(
        TOptions options,
        IDnsResolver dnsResolver,
        CancellationToken cancellationToken)
        where TOptions : class, IRuntimeGrpcClientDialOptions
    {
        ArgumentNullException.ThrowIfNull(options);
        ArgumentNullException.ThrowIfNull(dnsResolver);

        if (options.TransportStreamFactory is not null)
        {
            throw new NotSupportedException(
                "mKCP transport currently requires a direct UDP socket and does not support custom transport stream factories.");
        }

        var dialContext = OutboundClientDialContext.Resolve(
            options.DialContext,
            options.SourceEndPoint,
            options.LocalEndPoint);
        using var connectCts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        connectCts.CancelAfter(TimeSpan.FromSeconds(options.ConnectTimeoutSeconds));

        var endPoints = await OutboundSocketDialer.ResolveTcpEndPointsAsync(
            dialContext,
            options.ServerHost,
            options.ServerPort,
            AddressFamily.Unspecified,
            dnsResolver,
            connectCts.Token).ConfigureAwait(false);

        Exception? lastError = null;
        foreach (var endPoint in endPoints)
        {
            var socket = OutboundSocketDialer.CreateUdpSocket(
                dialContext,
                options.Via,
                options.ViaCidr,
                endPoint.AddressFamily);

            try
            {
                socket.SendBufferSize = (int)RuntimeKcpDefaults.DefaultWriteBufferBytes;
                socket.ReceiveBufferSize = (int)RuntimeKcpDefaults.DefaultReadBufferBytes;
                await socket.ConnectAsync(endPoint, connectCts.Token).ConfigureAwait(false);
                return new RuntimeKcpConnection(socket);
            }
            catch (OperationCanceledException) when (connectCts.IsCancellationRequested)
            {
                socket.Dispose();
                throw;
            }
            catch (Exception ex)
            {
                lastError = ex;
                socket.Dispose();
            }
        }

        throw lastError ?? new SocketException((int)SocketError.HostNotFound);
    }
}

internal static class RuntimeKcpDefaults
{
    public const uint DefaultMtu = 1350;
    public const uint DefaultTtiMilliseconds = 50;
    public const uint DefaultUplinkCapacityMb = 5;
    public const uint DefaultDownlinkCapacityMb = 20;
    public const uint DefaultWriteBufferBytes = 2 * 1024 * 1024;
    public const uint DefaultReadBufferBytes = 2 * 1024 * 1024;
    public const uint InitialRto = 100;
    public const int IdleCloseMilliseconds = 30_000;
    public const int PingIntervalMilliseconds = 5_000;
    public const int TerminatingIntervalMilliseconds = 1_000;
    public const int CloseDrainMilliseconds = 15_000;
    public const int PeerTerminatingDrainMilliseconds = 4_000;
    public const int TerminatingDrainMilliseconds = 8_000;

    public static uint DataMss => DefaultMtu - RuntimeKcpDataSegment.HeaderSize;

    public static uint GetSendingInFlightSize()
    {
        var denominator = Math.Max(1u, 1000u / DefaultTtiMilliseconds);
        var size = DefaultUplinkCapacityMb * 1024u * 1024u / DefaultMtu / denominator;
        return Math.Max(8u, size);
    }

    public static uint GetSendingBufferSize()
        => DefaultWriteBufferBytes / DefaultMtu;

    public static uint GetReceivingInFlightSize()
    {
        var denominator = Math.Max(1u, 1000u / DefaultTtiMilliseconds);
        var size = DefaultDownlinkCapacityMb * 1024u * 1024u / DefaultMtu / denominator;
        return Math.Max(8u, size);
    }
}

internal enum RuntimeKcpState
{
    Active = 0,
    ReadyToClose = 1,
    PeerClosed = 2,
    Terminating = 3,
    PeerTerminating = 4,
    Terminated = 5
}

internal enum RuntimeKcpCommand : byte
{
    Ack = 0,
    Data = 1,
    Terminate = 2,
    Ping = 3
}

[Flags]
internal enum RuntimeKcpSegmentOption : byte
{
    None = 0,
    Close = 1
}

internal enum RuntimeKcpWireFormat
{
    Unknown = 0,
    ModernRaw = 1,
    LegacySimpleAuth = 2
}

internal abstract class RuntimeKcpSegment
{
    public abstract ushort Conversation { get; set; }

    public abstract RuntimeKcpCommand Command { get; }

    public abstract RuntimeKcpSegmentOption Option { get; set; }

    public abstract int ByteSize { get; }

    public abstract void Serialize(Span<byte> destination);

    public virtual void Release()
    {
    }
}

internal sealed class RuntimeKcpDataSegment : RuntimeKcpSegment
{
    public const int HeaderSize = 18;

    private byte[] _payload = Array.Empty<byte>();

    public override ushort Conversation { get; set; }

    public override RuntimeKcpCommand Command => RuntimeKcpCommand.Data;

    public override RuntimeKcpSegmentOption Option { get; set; }

    public uint Timestamp { get; set; }

    public uint Number { get; set; }

    public uint SendingNext { get; set; }

    internal uint Timeout { get; set; }

    internal uint Transmit { get; set; }

    public ReadOnlyMemory<byte> Payload => _payload;

    public override int ByteSize => HeaderSize + _payload.Length;

    public void SetPayload(byte[] payload)
        => _payload = payload ?? throw new ArgumentNullException(nameof(payload));

    public byte[] DetachPayload()
    {
        var payload = _payload;
        _payload = Array.Empty<byte>();
        return payload;
    }

    public override void Serialize(Span<byte> destination)
    {
        if (destination.Length < ByteSize)
        {
            throw new ArgumentException("Destination buffer is too small for the KCP data segment.", nameof(destination));
        }

        BinaryPrimitives.WriteUInt16BigEndian(destination, Conversation);
        destination[2] = (byte)RuntimeKcpCommand.Data;
        destination[3] = (byte)Option;
        BinaryPrimitives.WriteUInt32BigEndian(destination[4..], Timestamp);
        BinaryPrimitives.WriteUInt32BigEndian(destination[8..], Number);
        BinaryPrimitives.WriteUInt32BigEndian(destination[12..], SendingNext);
        BinaryPrimitives.WriteUInt16BigEndian(destination[16..], checked((ushort)_payload.Length));
        _payload.AsSpan().CopyTo(destination[18..]);
    }

    public override void Release()
        => _payload = Array.Empty<byte>();
}

internal sealed class RuntimeKcpAckSegment : RuntimeKcpSegment
{
    public const int HeaderSize = 17;
    private const int MaxAckNumbers = 128;

    public RuntimeKcpAckSegment(int limit)
    {
        Limit = Math.Clamp(limit, 1, MaxAckNumbers);
    }

    public override ushort Conversation { get; set; }

    public override RuntimeKcpCommand Command => RuntimeKcpCommand.Ack;

    public override RuntimeKcpSegmentOption Option { get; set; }

    public uint ReceivingWindow { get; set; }

    public uint ReceivingNext { get; set; }

    public uint Timestamp { get; set; }

    public List<uint> Numbers { get; } = new(MaxAckNumbers);

    public int Limit { get; }

    public bool IsFull => Numbers.Count >= Limit;

    public bool IsEmpty => Numbers.Count == 0;

    public override int ByteSize => HeaderSize + (Numbers.Count * sizeof(uint));

    public void PutTimestamp(uint timestamp)
    {
        if (unchecked(timestamp - Timestamp) < 0x80000000u)
        {
            Timestamp = timestamp;
        }
    }

    public void PutNumber(uint number)
        => Numbers.Add(number);

    public override void Serialize(Span<byte> destination)
    {
        if (destination.Length < ByteSize)
        {
            throw new ArgumentException("Destination buffer is too small for the KCP ack segment.", nameof(destination));
        }

        BinaryPrimitives.WriteUInt16BigEndian(destination, Conversation);
        destination[2] = (byte)RuntimeKcpCommand.Ack;
        destination[3] = (byte)Option;
        BinaryPrimitives.WriteUInt32BigEndian(destination[4..], ReceivingWindow);
        BinaryPrimitives.WriteUInt32BigEndian(destination[8..], ReceivingNext);
        BinaryPrimitives.WriteUInt32BigEndian(destination[12..], Timestamp);
        destination[16] = checked((byte)Numbers.Count);

        var offset = 17;
        foreach (var number in Numbers)
        {
            BinaryPrimitives.WriteUInt32BigEndian(destination[offset..], number);
            offset += sizeof(uint);
        }
    }
}

internal sealed class RuntimeKcpCommandSegment : RuntimeKcpSegment
{
    public const int ByteSizeValue = 16;

    public override ushort Conversation { get; set; }

    public RuntimeKcpCommand SegmentCommand { get; set; }

    public override RuntimeKcpCommand Command => SegmentCommand;

    public override RuntimeKcpSegmentOption Option { get; set; }

    public uint SendingNext { get; set; }

    public uint ReceivingNext { get; set; }

    public uint PeerRto { get; set; }

    public override int ByteSize => ByteSizeValue;

    public override void Serialize(Span<byte> destination)
    {
        if (destination.Length < ByteSizeValue)
        {
            throw new ArgumentException("Destination buffer is too small for the KCP command segment.", nameof(destination));
        }

        BinaryPrimitives.WriteUInt16BigEndian(destination, Conversation);
        destination[2] = (byte)SegmentCommand;
        destination[3] = (byte)Option;
        BinaryPrimitives.WriteUInt32BigEndian(destination[4..], SendingNext);
        BinaryPrimitives.WriteUInt32BigEndian(destination[8..], ReceivingNext);
        BinaryPrimitives.WriteUInt32BigEndian(destination[12..], PeerRto);
    }
}

internal static class RuntimeKcpPacketReader
{
    public static IReadOnlyList<RuntimeKcpSegment> Read(ReadOnlySpan<byte> payload)
    {
        return TryReadRaw(payload, requireCompletePayload: false, out var segments)
            ? segments
            : Array.Empty<RuntimeKcpSegment>();
    }

    public static bool TryRead(
        ReadOnlySpan<byte> payload,
        RuntimeKcpWireFormat wireFormat,
        out IReadOnlyList<RuntimeKcpSegment> segments)
    {
        switch (wireFormat)
        {
            case RuntimeKcpWireFormat.ModernRaw:
                return TryReadRaw(payload, requireCompletePayload: true, out segments);

            case RuntimeKcpWireFormat.LegacySimpleAuth:
                if (!RuntimeKcpLegacySimpleAuth.TryOpen(payload, out var plainPayload))
                {
                    segments = Array.Empty<RuntimeKcpSegment>();
                    return false;
                }

                return TryReadRaw(plainPayload, requireCompletePayload: true, out segments);

            default:
                segments = Array.Empty<RuntimeKcpSegment>();
                return false;
        }
    }

    public static bool TryReadAny(
        ReadOnlySpan<byte> payload,
        out IReadOnlyList<RuntimeKcpSegment> segments,
        out RuntimeKcpWireFormat wireFormat)
    {
        if (TryRead(payload, RuntimeKcpWireFormat.LegacySimpleAuth, out segments))
        {
            wireFormat = RuntimeKcpWireFormat.LegacySimpleAuth;
            return true;
        }

        if (TryRead(payload, RuntimeKcpWireFormat.ModernRaw, out segments))
        {
            wireFormat = RuntimeKcpWireFormat.ModernRaw;
            return true;
        }

        segments = Array.Empty<RuntimeKcpSegment>();
        wireFormat = RuntimeKcpWireFormat.Unknown;
        return false;
    }

    private static bool TryReadRaw(
        ReadOnlySpan<byte> payload,
        bool requireCompletePayload,
        out IReadOnlyList<RuntimeKcpSegment> segments)
    {
        if (payload.Length == 0)
        {
            segments = Array.Empty<RuntimeKcpSegment>();
            return false;
        }

        List<RuntimeKcpSegment>? parsedSegments = null;
        var remaining = payload;
        while (TryReadSegment(remaining, out var segment, out var consumed))
        {
            parsedSegments ??= new List<RuntimeKcpSegment>(4);
            parsedSegments.Add(segment);

            remaining = remaining[consumed..];
            if (remaining.IsEmpty)
            {
                break;
            }
        }

        if (parsedSegments is null || parsedSegments.Count == 0)
        {
            segments = Array.Empty<RuntimeKcpSegment>();
            return false;
        }

        if (requireCompletePayload && !remaining.IsEmpty)
        {
            ReleaseSegments(parsedSegments);
            segments = Array.Empty<RuntimeKcpSegment>();
            return false;
        }

        segments = parsedSegments;
        return true;
    }

    private static bool TryReadSegment(
        ReadOnlySpan<byte> payload,
        out RuntimeKcpSegment segment,
        out int consumed)
    {
        segment = null!;
        consumed = 0;

        if (payload.Length < 4)
        {
            return false;
        }

        var conversation = BinaryPrimitives.ReadUInt16BigEndian(payload);
        var command = (RuntimeKcpCommand)payload[2];
        var option = (RuntimeKcpSegmentOption)payload[3];
        var body = payload[4..];

        switch (command)
        {
            case RuntimeKcpCommand.Data:
                if (body.Length < 14)
                {
                    return false;
                }

                var dataLength = BinaryPrimitives.ReadUInt16BigEndian(body[12..]);
                if (body.Length < 14 + dataLength)
                {
                    return false;
                }

                var data = new RuntimeKcpDataSegment
                {
                    Conversation = conversation,
                    Option = option,
                    Timestamp = BinaryPrimitives.ReadUInt32BigEndian(body),
                    Number = BinaryPrimitives.ReadUInt32BigEndian(body[4..]),
                    SendingNext = BinaryPrimitives.ReadUInt32BigEndian(body[8..])
                };
                data.SetPayload(body.Slice(14, dataLength).ToArray());
                segment = data;
                consumed = 4 + 14 + dataLength;
                return true;

            case RuntimeKcpCommand.Ack:
                if (body.Length < 13)
                {
                    return false;
                }

                var numberCount = body[12];
                if (body.Length < 13 + (numberCount * sizeof(uint)))
                {
                    return false;
                }

                var ack = new RuntimeKcpAckSegment(Math.Max(1, (int)numberCount))
                {
                    Conversation = conversation,
                    Option = option,
                    ReceivingWindow = BinaryPrimitives.ReadUInt32BigEndian(body),
                    ReceivingNext = BinaryPrimitives.ReadUInt32BigEndian(body[4..]),
                    Timestamp = BinaryPrimitives.ReadUInt32BigEndian(body[8..])
                };

                var offset = 13;
                for (var index = 0; index < numberCount; index++)
                {
                    ack.PutNumber(BinaryPrimitives.ReadUInt32BigEndian(body[offset..]));
                    offset += sizeof(uint);
                }

                segment = ack;
                consumed = 4 + 13 + (numberCount * sizeof(uint));
                return true;

            default:
                if (body.Length < 12)
                {
                    return false;
                }

                segment = new RuntimeKcpCommandSegment
                {
                    Conversation = conversation,
                    SegmentCommand = command,
                    Option = option,
                    SendingNext = BinaryPrimitives.ReadUInt32BigEndian(body),
                    ReceivingNext = BinaryPrimitives.ReadUInt32BigEndian(body[4..]),
                    PeerRto = BinaryPrimitives.ReadUInt32BigEndian(body[8..])
                };
                consumed = RuntimeKcpCommandSegment.ByteSizeValue;
                return true;
        }
    }

    private static void ReleaseSegments(List<RuntimeKcpSegment> segments)
    {
        foreach (var segment in segments)
        {
            segment.Release();
        }
    }
}

internal static class RuntimeKcpLegacySimpleAuth
{
    private const int Overhead = 6;
    private const uint FnvOffsetBasis = 2166136261;
    private const uint FnvPrime = 16777619;

    public static byte[] Seal(ReadOnlySpan<byte> payload)
    {
        var baseLength = checked(payload.Length + Overhead);
        var paddedLength = Align4(baseLength);
        var buffer = new byte[paddedLength];

        BinaryPrimitives.WriteUInt16BigEndian(buffer.AsSpan(4, 2), checked((ushort)payload.Length));
        payload.CopyTo(buffer.AsSpan(6));
        BinaryPrimitives.WriteUInt32BigEndian(
            buffer.AsSpan(0, 4),
            ComputeFnv1a(buffer.AsSpan(4, baseLength - 4)));

        XorForward(buffer);

        if (baseLength == paddedLength)
        {
            return buffer;
        }

        return buffer.AsSpan(0, baseLength).ToArray();
    }

    public static bool TryOpen(ReadOnlySpan<byte> payload, out byte[] plainPayload)
    {
        if (payload.Length <= Overhead)
        {
            plainPayload = Array.Empty<byte>();
            return false;
        }

        var baseLength = payload.Length;
        var paddedLength = Align4(baseLength);
        var buffer = new byte[paddedLength];
        payload.CopyTo(buffer);
        XorBackward(buffer);

        var expectedHash = BinaryPrimitives.ReadUInt32BigEndian(buffer.AsSpan(0, 4));
        var actualHash = ComputeFnv1a(buffer.AsSpan(4, baseLength - 4));
        if (expectedHash != actualHash)
        {
            plainPayload = Array.Empty<byte>();
            return false;
        }

        var payloadLength = BinaryPrimitives.ReadUInt16BigEndian(buffer.AsSpan(4, 2));
        if (baseLength - Overhead != payloadLength)
        {
            plainPayload = Array.Empty<byte>();
            return false;
        }

        plainPayload = buffer.AsSpan(6, payloadLength).ToArray();
        return true;
    }

    private static int Align4(int length)
        => (length + 3) & ~3;

    private static uint ComputeFnv1a(ReadOnlySpan<byte> payload)
    {
        var hash = FnvOffsetBasis;
        foreach (var value in payload)
        {
            hash ^= value;
            hash *= FnvPrime;
        }

        return hash;
    }

    private static void XorForward(Span<byte> payload)
    {
        for (var index = 4; index < payload.Length; index++)
        {
            payload[index] ^= payload[index - 4];
        }
    }

    private static void XorBackward(Span<byte> payload)
    {
        for (var index = payload.Length - 1; index >= 4; index--)
        {
            payload[index] ^= payload[index - 4];
        }
    }
}

internal sealed class RuntimeKcpRoundTripInfo
{
    private readonly object _sync = new();
    private uint _variation;
    private uint _smoothedRtt;
    private uint _timeout;
    private readonly uint _minimumRtt;
    private uint _updatedTimestamp;

    public RuntimeKcpRoundTripInfo(uint initialTimeout, uint minimumRtt)
    {
        _timeout = initialTimeout;
        _minimumRtt = minimumRtt;
    }

    public void UpdatePeerRto(uint timeout, uint current)
    {
        lock (_sync)
        {
            if (current - _updatedTimestamp < 3000u)
            {
                return;
            }

            _updatedTimestamp = current;
            _timeout = timeout;
        }
    }

    public void Update(uint roundTrip, uint current)
    {
        if (roundTrip > 0x7FFFFFFFu)
        {
            return;
        }

        lock (_sync)
        {
            if (_smoothedRtt == 0)
            {
                _smoothedRtt = roundTrip;
                _variation = roundTrip / 2u;
            }
            else
            {
                var delta = _smoothedRtt > roundTrip
                    ? _smoothedRtt - roundTrip
                    : roundTrip - _smoothedRtt;
                _variation = ((3u * _variation) + delta) / 4u;
                _smoothedRtt = ((7u * _smoothedRtt) + roundTrip) / 8u;
                if (_smoothedRtt < _minimumRtt)
                {
                    _smoothedRtt = _minimumRtt;
                }
            }

            var timeout = _minimumRtt < (4u * _variation)
                ? _smoothedRtt + (4u * _variation)
                : _smoothedRtt + _variation;
            if (timeout > 10_000u)
            {
                timeout = 10_000u;
            }

            _timeout = (timeout * 5u) / 4u;
            _updatedTimestamp = current;
        }
    }

    public uint Timeout
    {
        get
        {
            lock (_sync)
            {
                return _timeout;
            }
        }
    }
}

internal sealed class RuntimeKcpSignal : IDisposable
{
    private readonly SemaphoreSlim _semaphore = new(0, int.MaxValue);
    private int _disposed;

    public void Signal()
    {
        if (Volatile.Read(ref _disposed) != 0)
        {
            return;
        }

        try
        {
            _semaphore.Release();
        }
        catch (ObjectDisposedException)
        {
        }
    }

    public Task WaitAsync(CancellationToken cancellationToken)
        => _semaphore.WaitAsync(cancellationToken);

    public void Dispose()
    {
        if (Interlocked.Exchange(ref _disposed, 1) != 0)
        {
            return;
        }

        _semaphore.Dispose();
    }
}

internal sealed class RuntimeKcpSendingWindow
{
    private readonly LinkedList<RuntimeKcpDataSegment> _cache = new();
    private readonly Func<RuntimeKcpDataSegment, bool> _writeSegment;
    private readonly Action<uint>? _onPacketLoss;
    private uint _totalInFlightSize;

    public RuntimeKcpSendingWindow(
        Func<RuntimeKcpDataSegment, bool> writeSegment,
        Action<uint>? onPacketLoss)
    {
        _writeSegment = writeSegment ?? throw new ArgumentNullException(nameof(writeSegment));
        _onPacketLoss = onPacketLoss;
    }

    public uint Count => checked((uint)_cache.Count);

    public bool IsEmpty => _cache.Count == 0;

    public uint FirstNumber
        => _cache.First?.Value.Number
           ?? throw new InvalidOperationException("The KCP sending window is empty.");

    public void Release()
    {
        while (_cache.First is not null)
        {
            _cache.First.Value.Release();
            _cache.RemoveFirst();
        }
    }

    public void Push(uint number, byte[] payload)
    {
        var segment = new RuntimeKcpDataSegment
        {
            Number = number
        };
        segment.SetPayload(payload);
        _cache.AddLast(segment);
    }

    public void Clear(uint unacknowledged)
    {
        while (_cache.First is not null && _cache.First.Value.Number < unacknowledged)
        {
            _cache.First.Value.Release();
            _cache.RemoveFirst();
        }
    }

    public void HandleFastAck(uint number, uint rto)
    {
        if (IsEmpty)
        {
            return;
        }

        Visit(segment =>
        {
            if (number == segment.Number || unchecked(number - segment.Number) > 0x7FFFFFFFu)
            {
                return false;
            }

            if (segment.Transmit > 0 && segment.Timeout > (rto / 3u))
            {
                segment.Timeout -= rto / 3u;
            }

            return true;
        });
    }

    public void Flush(uint current, uint rto, uint maxInFlightSize)
    {
        if (IsEmpty)
        {
            return;
        }

        uint lost = 0;
        uint inFlightSize = 0;

        Visit(segment =>
        {
            if (unchecked(current - segment.Timeout) >= 0x7FFFFFFFu)
            {
                return true;
            }

            if (segment.Transmit == 0)
            {
                _totalInFlightSize++;
            }
            else
            {
                lost++;
            }

            segment.Timeout = current + rto;
            segment.Timestamp = current;
            segment.Transmit++;
            if (!_writeSegment(segment))
            {
                return false;
            }

            inFlightSize++;
            return inFlightSize < maxInFlightSize;
        });

        if (_onPacketLoss is not null && inFlightSize > 0 && _totalInFlightSize > 0)
        {
            _onPacketLoss((lost * 100u) / _totalInFlightSize);
        }
    }

    public bool Remove(uint number)
    {
        for (var node = _cache.First; node is not null; node = node.Next)
        {
            var segment = node.Value;
            if (segment.Number > number)
            {
                return false;
            }

            if (segment.Number != number)
            {
                continue;
            }

            if (_totalInFlightSize > 0)
            {
                _totalInFlightSize--;
            }

            segment.Release();
            _cache.Remove(node);
            return true;
        }

        return false;
    }

    private void Visit(Func<RuntimeKcpDataSegment, bool> visitor)
    {
        for (var node = _cache.First; node is not null; node = node.Next)
        {
            if (!visitor(node.Value))
            {
                break;
            }
        }
    }
}

internal sealed class RuntimeKcpSendingWorker
{
    private readonly object _sync = new();
    private readonly RuntimeKcpConnection _connection;
    private readonly RuntimeKcpSendingWindow _window;
    private uint _firstUnacknowledged;
    private uint _nextNumber;
    private uint _remoteNextNumber = 32;
    private uint _controlWindow = RuntimeKcpDefaults.GetSendingInFlightSize();
    private readonly uint _windowSize = RuntimeKcpDefaults.GetSendingBufferSize();
    private bool _firstUnacknowledgedUpdated;
    private bool _released;

    public RuntimeKcpSendingWorker(RuntimeKcpConnection connection)
    {
        _connection = connection ?? throw new ArgumentNullException(nameof(connection));
        _window = new RuntimeKcpSendingWindow(WriteSegment, OnPacketLoss);
    }

    public void Release()
    {
        lock (_sync)
        {
            _window.Release();
            _released = true;
        }
    }

    public void ProcessReceivingNext(uint nextNumber)
    {
        lock (_sync)
        {
            ProcessReceivingNextCore(nextNumber);
        }
    }

    public void ProcessAckSegment(uint current, RuntimeKcpAckSegment segment, uint rto)
    {
        ArgumentNullException.ThrowIfNull(segment);

        lock (_sync)
        {
            if (_released)
            {
                return;
            }

            if (_remoteNextNumber < segment.ReceivingWindow)
            {
                _remoteNextNumber = segment.ReceivingWindow;
            }

            ProcessReceivingNextCore(segment.ReceivingNext);
            if (segment.IsEmpty)
            {
                return;
            }

            uint maxAck = 0;
            var maxAckRemoved = false;
            foreach (var number in segment.Numbers)
            {
                var removed = ProcessAck(number);
                if (maxAck < number)
                {
                    maxAck = number;
                    maxAckRemoved = removed;
                }
            }

            if (maxAckRemoved)
            {
                _window.HandleFastAck(maxAck, rto);
                if (current >= segment.Timestamp && current - segment.Timestamp < 10_000u)
                {
                    _connection.RoundTrip.Update(current - segment.Timestamp, current);
                }
            }
        }
    }

    public bool Push(byte[] payload)
    {
        ArgumentNullException.ThrowIfNull(payload);

        lock (_sync)
        {
            if (_released)
            {
                return false;
            }

            if (_window.Count > _windowSize)
            {
                return false;
            }

            _window.Push(_nextNumber, payload);
            _nextNumber++;
            return true;
        }
    }

    public void Flush(uint current)
    {
        var updated = false;

        lock (_sync)
        {
            if (_released)
            {
                return;
            }

            var congestionWindow = RuntimeKcpDefaults.GetSendingInFlightSize();
            if (congestionWindow > _remoteNextNumber - _firstUnacknowledged)
            {
                congestionWindow = _remoteNextNumber - _firstUnacknowledged;
            }

            if (congestionWindow > _controlWindow)
            {
                congestionWindow = _controlWindow;
            }

            congestionWindow *= 20u;
            if (!_window.IsEmpty)
            {
                _window.Flush(current, _connection.RoundTrip.Timeout, congestionWindow);
                _firstUnacknowledgedUpdated = false;
            }

            updated = _firstUnacknowledgedUpdated;
            _firstUnacknowledgedUpdated = false;
        }

        if (updated)
        {
            _connection.Ping(current, RuntimeKcpCommand.Ping);
        }
    }

    public void CloseWrite()
    {
        lock (_sync)
        {
            _window.Clear(uint.MaxValue);
        }
    }

    public bool IsEmpty
    {
        get
        {
            lock (_sync)
            {
                return _window.IsEmpty;
            }
        }
    }

    public bool UpdateNecessary => !IsEmpty;

    public uint FirstUnacknowledged
    {
        get
        {
            lock (_sync)
            {
                return _firstUnacknowledged;
            }
        }
    }

    private void ProcessReceivingNextCore(uint nextNumber)
    {
        _window.Clear(nextNumber);
        FindFirstUnacknowledged();
    }

    private void FindFirstUnacknowledged()
    {
        var previous = _firstUnacknowledged;
        _firstUnacknowledged = _window.IsEmpty
            ? _nextNumber
            : _window.FirstNumber;
        if (previous != _firstUnacknowledged)
        {
            _firstUnacknowledgedUpdated = true;
        }
    }

    private bool ProcessAck(uint number)
    {
        if (unchecked(number - _firstUnacknowledged) > 0x7FFFFFFFu ||
            unchecked(number - _nextNumber) < 0x7FFFFFFFu)
        {
            return false;
        }

        var removed = _window.Remove(number);
        if (removed)
        {
            FindFirstUnacknowledged();
        }

        return removed;
    }

    private bool WriteSegment(RuntimeKcpDataSegment segment)
    {
        segment.Conversation = _connection.Conversation;
        segment.SendingNext = _firstUnacknowledged;
        segment.Option = _connection.State == RuntimeKcpState.ReadyToClose
            ? RuntimeKcpSegmentOption.Close
            : RuntimeKcpSegmentOption.None;
        return _connection.WriteSegment(segment);
    }

    private void OnPacketLoss(uint lossRate)
    {
        if (_connection.RoundTrip.Timeout == 0)
        {
            return;
        }

        if (lossRate >= 15u)
        {
            _controlWindow = (3u * _controlWindow) / 4u;
        }
        else if (lossRate <= 5u)
        {
            _controlWindow += _controlWindow / 4u;
        }

        if (_controlWindow < 16u)
        {
            _controlWindow = 16u;
        }

        var maximum = RuntimeKcpDefaults.GetSendingInFlightSize() * 2u;
        if (_controlWindow > maximum)
        {
            _controlWindow = maximum;
        }
    }
}

internal sealed class RuntimeKcpReceivingWindow
{
    private readonly Dictionary<uint, RuntimeKcpDataSegment> _cache = new();

    public bool Set(uint number, RuntimeKcpDataSegment segment)
    {
        if (_cache.ContainsKey(number))
        {
            return false;
        }

        _cache[number] = segment;
        return true;
    }

    public bool Has(uint number)
        => _cache.ContainsKey(number);

    public RuntimeKcpDataSegment? Remove(uint number)
    {
        if (!_cache.Remove(number, out var segment))
        {
            return null;
        }

        return segment;
    }

    public void Release()
    {
        foreach (var segment in _cache.Values)
        {
            segment.Release();
        }

        _cache.Clear();
    }
}

internal sealed class RuntimeKcpAckList
{
    private readonly Func<RuntimeKcpAckSegment, bool> _writeSegment;
    private readonly List<uint> _timestamps = new(128);
    private readonly List<uint> _numbers = new(128);
    private readonly List<uint> _nextFlush = new(128);
    private readonly List<uint> _flushCandidates = new(128);
    private readonly uint _mss;
    private bool _dirty;

    public RuntimeKcpAckList(Func<RuntimeKcpAckSegment, bool> writeSegment, uint mss)
    {
        _writeSegment = writeSegment ?? throw new ArgumentNullException(nameof(writeSegment));
        _mss = mss;
    }

    public int Count => _numbers.Count;

    public void Add(uint number, uint timestamp)
    {
        _timestamps.Add(timestamp);
        _numbers.Add(number);
        _nextFlush.Add(0);
        _dirty = true;
    }

    public void Clear(uint unacknowledged)
    {
        var count = 0;
        for (var index = 0; index < _numbers.Count; index++)
        {
            if (_numbers[index] < unacknowledged)
            {
                continue;
            }

            if (index != count)
            {
                _numbers[count] = _numbers[index];
                _timestamps[count] = _timestamps[index];
                _nextFlush[count] = _nextFlush[index];
            }

            count++;
        }

        if (count >= _numbers.Count)
        {
            return;
        }

        _numbers.RemoveRange(count, _numbers.Count - count);
        _timestamps.RemoveRange(count, _timestamps.Count - count);
        _nextFlush.RemoveRange(count, _nextFlush.Count - count);
        _dirty = true;
    }

    public void Flush(uint current, uint rto)
    {
        _flushCandidates.Clear();
        var segment = CreateSegment();

        for (var index = 0; index < _numbers.Count; index++)
        {
            if (_nextFlush[index] > current)
            {
                if (_flushCandidates.Count < _flushCandidates.Capacity)
                {
                    _flushCandidates.Add(_numbers[index]);
                }

                continue;
            }

            segment.PutNumber(_numbers[index]);
            segment.PutTimestamp(_timestamps[index]);
            var timeout = Math.Max(20u, rto / 2u);
            _nextFlush[index] = current + timeout;

            if (!segment.IsFull)
            {
                continue;
            }

            if (!_writeSegment(segment))
            {
                return;
            }

            segment = CreateSegment();
            _dirty = false;
        }

        if (_dirty || !segment.IsEmpty)
        {
            foreach (var number in _flushCandidates)
            {
                if (segment.IsFull)
                {
                    break;
                }

                segment.PutNumber(number);
            }

            _writeSegment(segment);
            _dirty = false;
        }
    }

    private RuntimeKcpAckSegment CreateSegment()
        => new(Math.Max(1, ((int)_mss - RuntimeKcpAckSegment.HeaderSize) / sizeof(uint)));
}

internal sealed class RuntimeKcpReceivingWorker
{
    private readonly object _sync = new();
    private readonly RuntimeKcpConnection _connection;
    private readonly RuntimeKcpReceivingWindow _window = new();
    private readonly RuntimeKcpAckList _ackList;
    private readonly uint _windowSize = RuntimeKcpDefaults.GetReceivingInFlightSize();
    private uint _nextNumber;
    private byte[]? _leftOver;
    private int _leftOverOffset;

    public RuntimeKcpReceivingWorker(RuntimeKcpConnection connection)
    {
        _connection = connection ?? throw new ArgumentNullException(nameof(connection));
        _ackList = new RuntimeKcpAckList(WriteAckSegment, RuntimeKcpDefaults.DataMss + RuntimeKcpDataSegment.HeaderSize);
    }

    public void Release()
    {
        lock (_sync)
        {
            _leftOver = null;
            _leftOverOffset = 0;
            _window.Release();
        }
    }

    public void ProcessSendingNext(uint number)
    {
        lock (_sync)
        {
            _ackList.Clear(number);
        }
    }

    public void ProcessSegment(RuntimeKcpDataSegment segment)
    {
        ArgumentNullException.ThrowIfNull(segment);

        lock (_sync)
        {
            var index = segment.Number - _nextNumber;
            if (index >= _windowSize)
            {
                segment.Release();
                return;
            }

            _ackList.Clear(segment.SendingNext);
            _ackList.Add(segment.Number, segment.Timestamp);

            if (!_window.Set(segment.Number, segment))
            {
                segment.Release();
            }
        }
    }

    public int Read(Span<byte> destination)
    {
        if (destination.Length == 0)
        {
            return 0;
        }

        lock (_sync)
        {
            var written = 0;

            while (written < destination.Length)
            {
                if (_leftOver is not null)
                {
                    var remaining = _leftOver.Length - _leftOverOffset;
                    var leftOverCopyLength = Math.Min(remaining, destination.Length - written);
                    _leftOver.AsSpan(_leftOverOffset, leftOverCopyLength).CopyTo(destination[written..]);
                    written += leftOverCopyLength;
                    _leftOverOffset += leftOverCopyLength;

                    if (_leftOverOffset >= _leftOver.Length)
                    {
                        _leftOver = null;
                        _leftOverOffset = 0;
                    }

                    if (written >= destination.Length)
                    {
                        break;
                    }

                    continue;
                }

                var segment = _window.Remove(_nextNumber);
                if (segment is null)
                {
                    break;
                }

                _nextNumber++;
                var payload = segment.DetachPayload();
                var copyLength = Math.Min(payload.Length, destination.Length - written);
                payload.AsSpan(0, copyLength).CopyTo(destination[written..]);
                written += copyLength;

                if (copyLength < payload.Length)
                {
                    _leftOver = payload;
                    _leftOverOffset = copyLength;
                }

                segment.Release();
            }

            return written;
        }
    }

    public bool IsDataAvailable
    {
        get
        {
            lock (_sync)
            {
                return _leftOver is not null || _window.Has(_nextNumber);
            }
        }
    }

    public uint NextNumber
    {
        get
        {
            lock (_sync)
            {
                return _nextNumber;
            }
        }
    }

    public void Flush(uint current)
    {
        lock (_sync)
        {
            _ackList.Flush(current, _connection.RoundTrip.Timeout);
        }
    }

    public void CloseRead()
    {
    }

    public bool UpdateNecessary
    {
        get
        {
            lock (_sync)
            {
                return _ackList.Count > 0;
            }
        }
    }

    private bool WriteAckSegment(RuntimeKcpAckSegment segment)
    {
        segment.Conversation = _connection.Conversation;
        segment.ReceivingNext = _nextNumber;
        segment.ReceivingWindow = _nextNumber + _windowSize;
        segment.Option = _connection.State == RuntimeKcpState.ReadyToClose
            ? RuntimeKcpSegmentOption.Close
            : RuntimeKcpSegmentOption.None;
        return _connection.WriteSegment(segment);
    }
}

internal sealed class RuntimeKcpConnection : Stream
{
    private static int s_nextConversation = RandomNumberGenerator.GetInt32(0, ushort.MaxValue + 1);

    private readonly Socket? _socket;
    private readonly Func<Memory<byte>, CancellationToken, ValueTask<int>>? _receivePacketAsync;
    private readonly Action<byte[]> _sendPacket;
    private readonly Action _disposeTransport;
    private readonly Stopwatch _stopwatch = Stopwatch.StartNew();
    private readonly CancellationTokenSource _lifetimeCts = new();
    private readonly RuntimeKcpSignal _dataInput = new();
    private readonly RuntimeKcpSignal _dataOutput = new();
    private readonly RuntimeKcpSignal _dataUpdaterSignal = new();
    private readonly object _outputSync = new();
    private readonly RuntimeKcpRoundTripInfo _roundTrip = new(
        RuntimeKcpDefaults.InitialRto,
        RuntimeKcpDefaults.DefaultTtiMilliseconds);
    private readonly RuntimeKcpSendingWorker _sendingWorker;
    private readonly RuntimeKcpReceivingWorker _receivingWorker;
    private readonly Task _receiveLoopTask;
    private readonly Task _dataUpdaterTask;
    private readonly Task _pingLoopTask;
    private readonly ushort _conversation;

    private int _disposed;
    private int _state = (int)RuntimeKcpState.Active;
    private int _stateBeginTimeMs;
    private int _lastIncomingTimeMs;
    private int _lastPingTimeMs;
    private int _readTimeout = Timeout.Infinite;
    private int _writeTimeout = Timeout.Infinite;
    private int _terminationStarted;
    private int _wireFormat;
    private Exception? _transportError;

    public RuntimeKcpConnection(Socket socket)
        : this(
            unchecked((ushort)Interlocked.Increment(ref s_nextConversation)),
            socket,
            static (socketHandle, buffer, cancellationToken) => socketHandle.ReceiveAsync(buffer, SocketFlags.None, cancellationToken),
            static (socketHandle, payload) => socketHandle.Send(payload),
            static socketHandle => socketHandle.Dispose(),
            RuntimeKcpWireFormat.Unknown)
    {
    }

    internal RuntimeKcpConnection(
        ushort conversation,
        Action<byte[]> sendPacket,
        Action? disposeTransport = null)
        : this(
            conversation,
            sendPacket,
            RuntimeKcpWireFormat.Unknown,
            disposeTransport)
    {
    }

    internal RuntimeKcpConnection(
        ushort conversation,
        Action<byte[]> sendPacket,
        RuntimeKcpWireFormat initialWireFormat,
        Action? disposeTransport = null)
        : this(
            conversation,
            socket: null,
            receivePacketAsync: null,
            sendPacket: sendPacket,
            disposeTransport: disposeTransport ?? (() => { }),
            initialWireFormat)
    {
    }

    private RuntimeKcpConnection(
        ushort conversation,
        Socket? socket,
        Func<Socket, Memory<byte>, CancellationToken, ValueTask<int>>? receivePacketAsync,
        Action<Socket, byte[]>? sendPacket,
        Action<Socket>? disposeTransport,
        RuntimeKcpWireFormat initialWireFormat)
    {
        ArgumentNullException.ThrowIfNull(socket);
        ArgumentNullException.ThrowIfNull(receivePacketAsync);
        ArgumentNullException.ThrowIfNull(sendPacket);
        ArgumentNullException.ThrowIfNull(disposeTransport);

        _socket = socket;
        _receivePacketAsync = (buffer, cancellationToken) => receivePacketAsync(socket, buffer, cancellationToken);
        _sendPacket = payload => sendPacket(socket, payload);
        _disposeTransport = () => disposeTransport(socket);
        _conversation = conversation;
        _wireFormat = (int)initialWireFormat;
        _sendingWorker = new RuntimeKcpSendingWorker(this);
        _receivingWorker = new RuntimeKcpReceivingWorker(this);
        _receiveLoopTask = Task.Run(RunReceiveLoopAsync);
        _dataUpdaterTask = Task.Run(RunDataUpdaterLoopAsync);
        _pingLoopTask = Task.Run(RunPingLoopAsync);
    }

    private RuntimeKcpConnection(
        ushort conversation,
        Socket? socket,
        Func<Memory<byte>, CancellationToken, ValueTask<int>>? receivePacketAsync,
        Action<byte[]> sendPacket,
        Action disposeTransport,
        RuntimeKcpWireFormat initialWireFormat)
    {
        _socket = socket;
        _receivePacketAsync = receivePacketAsync;
        _sendPacket = sendPacket ?? throw new ArgumentNullException(nameof(sendPacket));
        _disposeTransport = disposeTransport ?? throw new ArgumentNullException(nameof(disposeTransport));
        _conversation = conversation;
        _wireFormat = (int)initialWireFormat;
        _sendingWorker = new RuntimeKcpSendingWorker(this);
        _receivingWorker = new RuntimeKcpReceivingWorker(this);
        _receiveLoopTask = _receivePacketAsync is null
            ? Task.CompletedTask
            : Task.Run(RunReceiveLoopAsync);
        _dataUpdaterTask = Task.Run(RunDataUpdaterLoopAsync);
        _pingLoopTask = Task.Run(RunPingLoopAsync);
    }

    public RuntimeKcpState State => (RuntimeKcpState)Volatile.Read(ref _state);

    public ushort Conversation => _conversation;

    internal RuntimeKcpWireFormat WireFormat => (RuntimeKcpWireFormat)Volatile.Read(ref _wireFormat);

    public RuntimeKcpRoundTripInfo RoundTrip => _roundTrip;

    public override bool CanRead => Volatile.Read(ref _disposed) == 0;

    public override bool CanSeek => false;

    public override bool CanWrite => Volatile.Read(ref _disposed) == 0;

    public override bool CanTimeout => true;

    public override long Length => throw new NotSupportedException();

    public override long Position
    {
        get => throw new NotSupportedException();
        set => throw new NotSupportedException();
    }

    public override int ReadTimeout
    {
        get => _readTimeout;
        set
        {
            if (value <= 0 && value != Timeout.Infinite)
            {
                throw new ArgumentOutOfRangeException(nameof(value), "Read timeout must be positive or Timeout.Infinite.");
            }

            _readTimeout = value;
        }
    }

    public override int WriteTimeout
    {
        get => _writeTimeout;
        set
        {
            if (value <= 0 && value != Timeout.Infinite)
            {
                throw new ArgumentOutOfRangeException(nameof(value), "Write timeout must be positive or Timeout.Infinite.");
            }

            _writeTimeout = value;
        }
    }

    public override void Flush()
        => SignalDataUpdater();

    public override Task FlushAsync(CancellationToken cancellationToken)
    {
        SignalDataUpdater();
        return Task.CompletedTask;
    }

    public override int Read(byte[] buffer, int offset, int count)
        => ReadAsync(buffer.AsMemory(offset, count), CancellationToken.None).AsTask().GetAwaiter().GetResult();

    public override int Read(Span<byte> buffer)
    {
        var temp = new byte[buffer.Length];
        var read = ReadAsync(temp.AsMemory(0, temp.Length), CancellationToken.None).AsTask().GetAwaiter().GetResult();
        temp.AsSpan(0, read).CopyTo(buffer);
        return read;
    }

    public override async ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken cancellationToken = default)
    {
        ThrowIfDisposed();
        if (buffer.Length == 0)
        {
            return 0;
        }

        using var timeoutCts = CreateTimeoutCancellationTokenSource(cancellationToken, _readTimeout);
        var effectiveToken = timeoutCts?.Token ?? cancellationToken;

        try
        {
            while (true)
            {
                ThrowIfDisposed();

                if (State is RuntimeKcpState.ReadyToClose or RuntimeKcpState.Terminating or RuntimeKcpState.Terminated)
                {
                    ThrowIfTransportFailed();
                    return 0;
                }

                var bytesRead = _receivingWorker.Read(buffer.Span);
                if (bytesRead > 0)
                {
                    SignalDataUpdater();
                    return bytesRead;
                }

                if (State == RuntimeKcpState.PeerTerminating)
                {
                    return 0;
                }

                await _dataInput.WaitAsync(effectiveToken).ConfigureAwait(false);
            }
        }
        catch (OperationCanceledException) when (!cancellationToken.IsCancellationRequested &&
                                                timeoutCts is not null &&
                                                timeoutCts.IsCancellationRequested)
        {
            throw new IOException("mKCP read timed out.");
        }
    }

    public override Task<int> ReadAsync(byte[] buffer, int offset, int count, CancellationToken cancellationToken)
        => ReadAsync(buffer.AsMemory(offset, count), cancellationToken).AsTask();

    public override void Write(byte[] buffer, int offset, int count)
        => WriteAsync(buffer.AsMemory(offset, count), CancellationToken.None).AsTask().GetAwaiter().GetResult();

    public override void Write(ReadOnlySpan<byte> buffer)
        => WriteAsync(buffer.ToArray().AsMemory(), CancellationToken.None).AsTask().GetAwaiter().GetResult();

    public override async ValueTask WriteAsync(ReadOnlyMemory<byte> buffer, CancellationToken cancellationToken = default)
    {
        ThrowIfDisposed();
        if (buffer.Length == 0)
        {
            return;
        }

        using var timeoutCts = CreateTimeoutCancellationTokenSource(cancellationToken, _writeTimeout);
        var effectiveToken = timeoutCts?.Token ?? cancellationToken;

        try
        {
            var offset = 0;
            var mss = checked((int)RuntimeKcpDefaults.DataMss);

            while (offset < buffer.Length)
            {
                ThrowIfDisposed();
                ThrowIfTransportFailed();

                if (State != RuntimeKcpState.Active)
                {
                    throw new IOException("The mKCP connection is closed.");
                }

                var count = Math.Min(mss, buffer.Length - offset);
                var payload = buffer.Slice(offset, count).ToArray();
                if (_sendingWorker.Push(payload))
                {
                    offset += count;
                    SignalDataUpdater();
                    continue;
                }

                await _dataOutput.WaitAsync(effectiveToken).ConfigureAwait(false);
            }
        }
        catch (OperationCanceledException) when (!cancellationToken.IsCancellationRequested &&
                                                timeoutCts is not null &&
                                                timeoutCts.IsCancellationRequested)
        {
            throw new IOException("mKCP write timed out.");
        }
    }

    public override Task WriteAsync(byte[] buffer, int offset, int count, CancellationToken cancellationToken)
        => WriteAsync(buffer.AsMemory(offset, count), cancellationToken).AsTask();

    public override long Seek(long offset, SeekOrigin origin)
        => throw new NotSupportedException();

    public override void SetLength(long value)
        => throw new NotSupportedException();

    protected override void Dispose(bool disposing)
    {
        if (disposing)
        {
            DisposeAsync().AsTask().GetAwaiter().GetResult();
        }

        base.Dispose(disposing);
    }

    public override async ValueTask DisposeAsync()
    {
        if (Interlocked.Exchange(ref _disposed, 1) != 0)
        {
            return;
        }

        try
        {
            TrySendTerminate();
        }
        catch
        {
        }

        EnsureTerminated();

        try
        {
            await Task.WhenAll(_receiveLoopTask, _dataUpdaterTask, _pingLoopTask).ConfigureAwait(false);
        }
        catch
        {
        }

        _dataInput.Dispose();
        _dataOutput.Dispose();
        _dataUpdaterSignal.Dispose();
        _lifetimeCts.Dispose();
        try
        {
            _disposeTransport();
        }
        catch
        {
        }
    }

    public bool WriteSegment(RuntimeKcpSegment segment)
    {
        ArgumentNullException.ThrowIfNull(segment);

        if (_lifetimeCts.IsCancellationRequested)
        {
            return false;
        }

        try
        {
            lock (_outputSync)
            {
                if (WireFormat == RuntimeKcpWireFormat.Unknown)
                {
                    SendSegment(segment, RuntimeKcpWireFormat.ModernRaw);
                    SendSegment(segment, RuntimeKcpWireFormat.LegacySimpleAuth);
                }
                else
                {
                    SendSegment(segment, WireFormat);
                }
            }

            return true;
        }
        catch (Exception ex)
        {
            EnsureTerminated(ex);
            return false;
        }
    }

    internal bool AcceptsWireFormat(RuntimeKcpWireFormat wireFormat)
    {
        var currentWireFormat = WireFormat;
        return currentWireFormat == RuntimeKcpWireFormat.Unknown ||
               currentWireFormat == wireFormat;
    }

    private void ObserveWireFormat(RuntimeKcpWireFormat wireFormat)
    {
        if (wireFormat == RuntimeKcpWireFormat.Unknown)
        {
            return;
        }

        Interlocked.CompareExchange(
            ref _wireFormat,
            (int)wireFormat,
            (int)RuntimeKcpWireFormat.Unknown);
    }

    private void SendSegment(RuntimeKcpSegment segment, RuntimeKcpWireFormat wireFormat)
    {
        var payload = new byte[segment.ByteSize];
        segment.Serialize(payload);

        if (wireFormat == RuntimeKcpWireFormat.LegacySimpleAuth)
        {
            payload = RuntimeKcpLegacySimpleAuth.Seal(payload);
        }

        _sendPacket(payload);
    }

    public void Ping(uint current, RuntimeKcpCommand command)
    {
        var segment = new RuntimeKcpCommandSegment
        {
            Conversation = _conversation,
            SegmentCommand = command,
            ReceivingNext = _receivingWorker.NextNumber,
            SendingNext = _sendingWorker.FirstUnacknowledged,
            PeerRto = _roundTrip.Timeout,
            Option = State == RuntimeKcpState.ReadyToClose
                ? RuntimeKcpSegmentOption.Close
                : RuntimeKcpSegmentOption.None
        };

        if (WriteSegment(segment))
        {
            Volatile.Write(ref _lastPingTimeMs, CurrentElapsedMilliseconds);
        }
    }

    internal void InputSegments(IReadOnlyList<RuntimeKcpSegment> segments)
        => InputSegments(segments, RuntimeKcpWireFormat.Unknown);

    internal void InputSegments(
        IReadOnlyList<RuntimeKcpSegment> segments,
        RuntimeKcpWireFormat wireFormat)
    {
        ArgumentNullException.ThrowIfNull(segments);
        if (segments.Count == 0 || _lifetimeCts.IsCancellationRequested)
        {
            return;
        }

        ObserveWireFormat(wireFormat);
        Input(segments);
    }

    private int CurrentElapsedMilliseconds
        => checked((int)Math.Min(int.MaxValue, _stopwatch.ElapsedMilliseconds));

    private uint CurrentElapsedTimestamp
        => unchecked((uint)CurrentElapsedMilliseconds);

    private async Task RunReceiveLoopAsync()
    {
        if (_receivePacketAsync is null)
        {
            return;
        }

        var buffer = new byte[64 * 1024];
        try
        {
            while (!_lifetimeCts.IsCancellationRequested)
            {
                var received = await _receivePacketAsync(
                        buffer.AsMemory(0, buffer.Length),
                        _lifetimeCts.Token)
                    .ConfigureAwait(false);
                if (received <= 0)
                {
                    continue;
                }

                if (!RuntimeKcpPacketReader.TryReadAny(
                        buffer.AsSpan(0, received),
                        out var segments,
                        out var wireFormat))
                {
                    continue;
                }

                InputSegments(segments, wireFormat);
            }
        }
        catch (OperationCanceledException) when (_lifetimeCts.IsCancellationRequested)
        {
        }
        catch (ObjectDisposedException) when (_lifetimeCts.IsCancellationRequested)
        {
        }
        catch (Exception ex)
        {
            EnsureTerminated(ex);
        }
    }

    private async Task RunDataUpdaterLoopAsync()
    {
        try
        {
            while (!_lifetimeCts.IsCancellationRequested)
            {
                await _dataUpdaterSignal.WaitAsync(_lifetimeCts.Token).ConfigureAwait(false);

                while (!_lifetimeCts.IsCancellationRequested && ShouldContinueDataUpdates())
                {
                    FlushCore();
                    if (!ShouldContinueDataUpdates())
                    {
                        break;
                    }

                    await WaitForSignalOrDelayAsync(
                        _dataUpdaterSignal,
                        TimeSpan.FromMilliseconds(RuntimeKcpDefaults.DefaultTtiMilliseconds),
                        _lifetimeCts.Token).ConfigureAwait(false);
                }
            }
        }
        catch (OperationCanceledException) when (_lifetimeCts.IsCancellationRequested)
        {
        }
        catch (ObjectDisposedException) when (_lifetimeCts.IsCancellationRequested)
        {
        }
        catch (Exception ex)
        {
            EnsureTerminated(ex);
        }
    }

    private async Task RunPingLoopAsync()
    {
        try
        {
            while (!_lifetimeCts.IsCancellationRequested)
            {
                var delay = State is RuntimeKcpState.Terminating or RuntimeKcpState.PeerTerminating
                    ? TimeSpan.FromMilliseconds(RuntimeKcpDefaults.TerminatingIntervalMilliseconds)
                    : TimeSpan.FromMilliseconds(RuntimeKcpDefaults.PingIntervalMilliseconds);
                await Task.Delay(delay, _lifetimeCts.Token).ConfigureAwait(false);
                FlushCore();
            }
        }
        catch (OperationCanceledException) when (_lifetimeCts.IsCancellationRequested)
        {
        }
        catch (ObjectDisposedException) when (_lifetimeCts.IsCancellationRequested)
        {
        }
        catch (Exception ex)
        {
            EnsureTerminated(ex);
        }
    }

    private void Input(IReadOnlyList<RuntimeKcpSegment> segments)
    {
        var current = CurrentElapsedTimestamp;
        Volatile.Write(ref _lastIncomingTimeMs, CurrentElapsedMilliseconds);

        foreach (var segment in segments)
        {
            if (segment.Conversation != _conversation)
            {
                break;
            }

            switch (segment)
            {
                case RuntimeKcpDataSegment dataSegment:
                    HandleOption(dataSegment.Option);
                    _receivingWorker.ProcessSegment(dataSegment);
                    if (_receivingWorker.IsDataAvailable)
                    {
                        _dataInput.Signal();
                    }

                    SignalDataUpdater();
                    break;

                case RuntimeKcpAckSegment ackSegment:
                    HandleOption(ackSegment.Option);
                    _sendingWorker.ProcessAckSegment(current, ackSegment, _roundTrip.Timeout);
                    _dataOutput.Signal();
                    SignalDataUpdater();
                    break;

                case RuntimeKcpCommandSegment commandSegment:
                    HandleOption(commandSegment.Option);

                    if (commandSegment.Command == RuntimeKcpCommand.Terminate)
                    {
                        switch (State)
                        {
                            case RuntimeKcpState.Active:
                            case RuntimeKcpState.PeerClosed:
                                TransitionState(RuntimeKcpState.PeerTerminating);
                                break;
                            case RuntimeKcpState.ReadyToClose:
                                TransitionState(RuntimeKcpState.Terminating);
                                break;
                            case RuntimeKcpState.Terminating:
                                TransitionState(RuntimeKcpState.Terminated);
                                EnsureTerminated();
                                break;
                        }
                    }

                    if (commandSegment.Option == RuntimeKcpSegmentOption.Close ||
                        commandSegment.Command == RuntimeKcpCommand.Terminate)
                    {
                        _dataInput.Signal();
                        _dataOutput.Signal();
                    }

                    _sendingWorker.ProcessReceivingNext(commandSegment.ReceivingNext);
                    _receivingWorker.ProcessSendingNext(commandSegment.SendingNext);
                    _roundTrip.UpdatePeerRto(commandSegment.PeerRto, current);
                    break;
            }
        }
    }

    private void FlushCore()
    {
        if (_lifetimeCts.IsCancellationRequested || State == RuntimeKcpState.Terminated)
        {
            return;
        }

        var current = CurrentElapsedTimestamp;
        var currentMs = CurrentElapsedMilliseconds;
        if (State == RuntimeKcpState.Active &&
            currentMs - Volatile.Read(ref _lastIncomingTimeMs) >= RuntimeKcpDefaults.IdleCloseMilliseconds)
        {
            TransitionState(RuntimeKcpState.ReadyToClose);
        }

        if (State == RuntimeKcpState.ReadyToClose && _sendingWorker.IsEmpty)
        {
            TransitionState(RuntimeKcpState.Terminating);
        }

        if (State == RuntimeKcpState.Terminating)
        {
            Ping(current, RuntimeKcpCommand.Terminate);
            if (currentMs - Volatile.Read(ref _stateBeginTimeMs) > RuntimeKcpDefaults.TerminatingDrainMilliseconds)
            {
                TransitionState(RuntimeKcpState.Terminated);
                EnsureTerminated();
            }

            return;
        }

        if (State == RuntimeKcpState.PeerTerminating &&
            currentMs - Volatile.Read(ref _stateBeginTimeMs) > RuntimeKcpDefaults.PeerTerminatingDrainMilliseconds)
        {
            TransitionState(RuntimeKcpState.Terminating);
        }

        if (State == RuntimeKcpState.ReadyToClose &&
            currentMs - Volatile.Read(ref _stateBeginTimeMs) > RuntimeKcpDefaults.CloseDrainMilliseconds)
        {
            TransitionState(RuntimeKcpState.Terminating);
        }

        _receivingWorker.Flush(current);
        _sendingWorker.Flush(current);

        if (currentMs - Volatile.Read(ref _lastPingTimeMs) >= 3_000)
        {
            Ping(current, RuntimeKcpCommand.Ping);
        }
    }

    private void HandleOption(RuntimeKcpSegmentOption option)
    {
        if ((option & RuntimeKcpSegmentOption.Close) == RuntimeKcpSegmentOption.Close)
        {
            OnPeerClosed();
        }
    }

    private void OnPeerClosed()
    {
        switch (State)
        {
            case RuntimeKcpState.ReadyToClose:
                TransitionState(RuntimeKcpState.Terminating);
                break;
            case RuntimeKcpState.Active:
                TransitionState(RuntimeKcpState.PeerClosed);
                break;
        }
    }

    private void TransitionState(RuntimeKcpState nextState)
    {
        var currentTime = CurrentElapsedMilliseconds;
        Volatile.Write(ref _state, (int)nextState);
        Volatile.Write(ref _stateBeginTimeMs, currentTime);

        switch (nextState)
        {
            case RuntimeKcpState.ReadyToClose:
                _receivingWorker.CloseRead();
                break;

            case RuntimeKcpState.PeerClosed:
                _sendingWorker.CloseWrite();
                break;

            case RuntimeKcpState.Terminating:
                _receivingWorker.CloseRead();
                _sendingWorker.CloseWrite();
                SignalDataUpdater();
                break;

            case RuntimeKcpState.PeerTerminating:
                _sendingWorker.CloseWrite();
                SignalDataUpdater();
                break;

            case RuntimeKcpState.Terminated:
                _receivingWorker.CloseRead();
                _sendingWorker.CloseWrite();
                _dataInput.Signal();
                _dataOutput.Signal();
                SignalDataUpdater();
                break;
        }
    }

    private bool ShouldContinueDataUpdates()
        => !_lifetimeCts.IsCancellationRequested &&
           State != RuntimeKcpState.Terminated &&
           (_sendingWorker.UpdateNecessary || _receivingWorker.UpdateNecessary);

    private void SignalDataUpdater()
        => _dataUpdaterSignal.Signal();

    private void TrySendTerminate()
    {
        if (_lifetimeCts.IsCancellationRequested)
        {
            return;
        }

        Ping(CurrentElapsedTimestamp, RuntimeKcpCommand.Terminate);
    }

    private void EnsureTerminated(Exception? error = null)
    {
        if (error is not null)
        {
            Interlocked.CompareExchange(ref _transportError, error, null);
        }

        if (Interlocked.Exchange(ref _terminationStarted, 1) != 0)
        {
            return;
        }

        if (State != RuntimeKcpState.Terminated)
        {
            TransitionState(RuntimeKcpState.Terminated);
        }

        _lifetimeCts.Cancel();
        try
        {
            _disposeTransport();
        }
        catch
        {
        }

        _sendingWorker.Release();
        _receivingWorker.Release();
        _dataInput.Signal();
        _dataOutput.Signal();
        SignalDataUpdater();
    }

    private void ThrowIfDisposed()
        => ObjectDisposedException.ThrowIf(Volatile.Read(ref _disposed) != 0, this);

    private void ThrowIfTransportFailed()
    {
        if (_transportError is null)
        {
            return;
        }

        throw new IOException("mKCP transport failed.", _transportError);
    }

    private static async Task WaitForSignalOrDelayAsync(
        RuntimeKcpSignal signal,
        TimeSpan delay,
        CancellationToken cancellationToken)
    {
        var signalTask = signal.WaitAsync(cancellationToken);
        var delayTask = Task.Delay(delay, cancellationToken);
        await Task.WhenAny(signalTask, delayTask).ConfigureAwait(false);
    }

    private static CancellationTokenSource? CreateTimeoutCancellationTokenSource(
        CancellationToken cancellationToken,
        int timeoutMilliseconds)
    {
        if (timeoutMilliseconds == Timeout.Infinite)
        {
            return null;
        }

        var cts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        cts.CancelAfter(timeoutMilliseconds);
        return cts;
    }
}

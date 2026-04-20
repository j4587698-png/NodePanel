using System.Runtime.ExceptionServices;
using NodePanel.Core.Protocol;

namespace NodePanel.Core.Runtime;

internal sealed class VlessLazyResponseHeaderStream : Stream, IInnerStreamAccessor
{
    private readonly Stream _innerStream;
    private readonly byte _expectedVersion;
    private readonly TimeSpan _handshakeTimeout;
    private readonly SemaphoreSlim _handshakeLock = new(1, 1);

    private int _disposed;
    private ExceptionDispatchInfo? _handshakeFailure;
    private int _headerResolved;

    public VlessLazyResponseHeaderStream(
        Stream innerStream,
        byte expectedVersion,
        TimeSpan handshakeTimeout)
    {
        _innerStream = innerStream ?? throw new ArgumentNullException(nameof(innerStream));
        _expectedVersion = expectedVersion;
        _handshakeTimeout = handshakeTimeout > TimeSpan.Zero
            ? handshakeTimeout
            : Timeout.InfiniteTimeSpan;
    }

    public Stream InnerStream => _innerStream;

    public override bool CanRead => _innerStream.CanRead;

    public override bool CanSeek => _innerStream.CanSeek;

    public override bool CanWrite => _innerStream.CanWrite;

    public override bool CanTimeout => _innerStream.CanTimeout;

    public override long Length => _innerStream.Length;

    public override long Position
    {
        get => _innerStream.Position;
        set => _innerStream.Position = value;
    }

    public override int ReadTimeout
    {
        get => _innerStream.ReadTimeout;
        set => _innerStream.ReadTimeout = value;
    }

    public override int WriteTimeout
    {
        get => _innerStream.WriteTimeout;
        set => _innerStream.WriteTimeout = value;
    }

    public override void Flush()
        => _innerStream.Flush();

    public override Task FlushAsync(CancellationToken cancellationToken)
        => _innerStream.FlushAsync(cancellationToken);

    public override int Read(byte[] buffer, int offset, int count)
        => Read(buffer.AsSpan(offset, count));

    public override int Read(Span<byte> buffer)
    {
        if (buffer.Length == 0)
        {
            return 0;
        }

        EnsureResponseHeader();
        return _innerStream.Read(buffer);
    }

    public override Task<int> ReadAsync(byte[] buffer, int offset, int count, CancellationToken cancellationToken)
        => ReadAsync(buffer.AsMemory(offset, count), cancellationToken).AsTask();

    public override async ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken cancellationToken = default)
    {
        if (buffer.Length == 0)
        {
            return 0;
        }

        await EnsureResponseHeaderAsync(cancellationToken).ConfigureAwait(false);
        return await _innerStream.ReadAsync(buffer, cancellationToken).ConfigureAwait(false);
    }

    public override long Seek(long offset, SeekOrigin origin)
        => _innerStream.Seek(offset, origin);

    public override void SetLength(long value)
        => _innerStream.SetLength(value);

    public override void Write(byte[] buffer, int offset, int count)
        => _innerStream.Write(buffer, offset, count);

    public override void Write(ReadOnlySpan<byte> buffer)
        => _innerStream.Write(buffer);

    public override Task WriteAsync(byte[] buffer, int offset, int count, CancellationToken cancellationToken)
        => _innerStream.WriteAsync(buffer, offset, count, cancellationToken);

    public override ValueTask WriteAsync(ReadOnlyMemory<byte> buffer, CancellationToken cancellationToken = default)
        => _innerStream.WriteAsync(buffer, cancellationToken);

    protected override void Dispose(bool disposing)
    {
        if (disposing)
        {
            DisposeLock();
        }

        base.Dispose(disposing);
    }

    public override ValueTask DisposeAsync()
    {
        DisposeLock();
        return ValueTask.CompletedTask;
    }

    private void EnsureResponseHeader()
    {
        if (Volatile.Read(ref _headerResolved) != 0)
        {
            _handshakeFailure?.Throw();
            return;
        }

        _handshakeLock.Wait();
        try
        {
            if (Volatile.Read(ref _headerResolved) != 0)
            {
                _handshakeFailure?.Throw();
                return;
            }

            try
            {
                using var handshakeCts = CreateHandshakeCancellation(CancellationToken.None, out var token);
                _ = VlessHandshakeReader.ReadResponseAsync(_innerStream, _expectedVersion, token)
                    .AsTask()
                    .GetAwaiter()
                    .GetResult();
            }
            catch (Exception ex)
            {
                _handshakeFailure = ExceptionDispatchInfo.Capture(ex);
                throw;
            }
            finally
            {
                Volatile.Write(ref _headerResolved, 1);
            }
        }
        finally
        {
            _handshakeLock.Release();
        }
    }

    private async ValueTask EnsureResponseHeaderAsync(CancellationToken cancellationToken)
    {
        if (Volatile.Read(ref _headerResolved) != 0)
        {
            _handshakeFailure?.Throw();
            return;
        }

        await _handshakeLock.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            if (Volatile.Read(ref _headerResolved) != 0)
            {
                _handshakeFailure?.Throw();
                return;
            }

            try
            {
                using var handshakeCts = CreateHandshakeCancellation(cancellationToken, out var token);
                _ = await VlessHandshakeReader.ReadResponseAsync(_innerStream, _expectedVersion, token).ConfigureAwait(false);
            }
            catch (Exception ex)
            {
                _handshakeFailure = ExceptionDispatchInfo.Capture(ex);
                throw;
            }
            finally
            {
                Volatile.Write(ref _headerResolved, 1);
            }
        }
        finally
        {
            _handshakeLock.Release();
        }
    }

    private CancellationTokenSource? CreateHandshakeCancellation(
        CancellationToken cancellationToken,
        out CancellationToken token)
    {
        if (_handshakeTimeout == Timeout.InfiniteTimeSpan)
        {
            token = cancellationToken;
            return null;
        }

        var handshakeCts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        handshakeCts.CancelAfter(_handshakeTimeout);
        token = handshakeCts.Token;
        return handshakeCts;
    }

    private void DisposeLock()
    {
        if (Interlocked.Exchange(ref _disposed, 1) != 0)
        {
            return;
        }

        _handshakeLock.Dispose();
    }
}

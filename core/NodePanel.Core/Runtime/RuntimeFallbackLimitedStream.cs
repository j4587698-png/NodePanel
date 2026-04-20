namespace NodePanel.Core.Runtime;

public sealed class RuntimeFallbackLimitedStream : Stream
{
    private readonly Stream _innerStream;
    private readonly RuntimeFallbackRateLimiter _limiter;

    public RuntimeFallbackLimitedStream(Stream innerStream, RuntimeFallbackLimitOptions limitOptions)
    {
        ArgumentNullException.ThrowIfNull(innerStream);
        ArgumentNullException.ThrowIfNull(limitOptions);

        _innerStream = innerStream;
        _limiter = new RuntimeFallbackRateLimiter(limitOptions);
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

    public override void Flush() => _innerStream.Flush();

    public override Task FlushAsync(CancellationToken cancellationToken) => _innerStream.FlushAsync(cancellationToken);

    public override int Read(byte[] buffer, int offset, int count)
        => ReadAsync(buffer.AsMemory(offset, count), CancellationToken.None).AsTask().GetAwaiter().GetResult();

    public override int Read(Span<byte> buffer)
    {
        var read = _innerStream.Read(buffer);
        _limiter.WaitAsync(read, CancellationToken.None).GetAwaiter().GetResult();
        return read;
    }

    public override async ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken cancellationToken = default)
    {
        var read = await _innerStream.ReadAsync(buffer, cancellationToken).ConfigureAwait(false);
        await _limiter.WaitAsync(read, cancellationToken).ConfigureAwait(false);
        return read;
    }

    public override Task<int> ReadAsync(byte[] buffer, int offset, int count, CancellationToken cancellationToken)
        => ReadAsync(buffer.AsMemory(offset, count), cancellationToken).AsTask();

    public override long Seek(long offset, SeekOrigin origin) => _innerStream.Seek(offset, origin);

    public override void SetLength(long value) => _innerStream.SetLength(value);

    public override void Write(byte[] buffer, int offset, int count) => _innerStream.Write(buffer, offset, count);

    public override void Write(ReadOnlySpan<byte> buffer) => _innerStream.Write(buffer);

    public override ValueTask WriteAsync(ReadOnlyMemory<byte> buffer, CancellationToken cancellationToken = default)
        => _innerStream.WriteAsync(buffer, cancellationToken);

    public override Task WriteAsync(byte[] buffer, int offset, int count, CancellationToken cancellationToken)
        => _innerStream.WriteAsync(buffer, offset, count, cancellationToken);

    protected override void Dispose(bool disposing)
    {
        if (disposing)
        {
            _innerStream.Dispose();
        }

        base.Dispose(disposing);
    }

    public override ValueTask DisposeAsync() => _innerStream.DisposeAsync();
}


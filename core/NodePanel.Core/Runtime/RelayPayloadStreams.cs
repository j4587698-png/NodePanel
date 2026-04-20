namespace NodePanel.Core.Runtime;

internal interface IInnerStreamAccessor
{
    Stream InnerStream { get; }
}

internal interface IReplayablePrefixStream
{
    int RemainingReplayablePrefixBytes { get; }

    int SkipReplayablePrefix(int count);
}

internal interface IInitialPayloadSentMetadata
{
    int SentInitialPayloadBytes { get; }
}

internal sealed class InitialPayloadSentStream : Stream, IInnerStreamAccessor, IInitialPayloadSentMetadata
{
    private readonly Stream _innerStream;

    public InitialPayloadSentStream(Stream innerStream, int sentInitialPayloadBytes)
    {
        ArgumentNullException.ThrowIfNull(innerStream);
        ArgumentOutOfRangeException.ThrowIfNegative(sentInitialPayloadBytes);

        _innerStream = innerStream;
        SentInitialPayloadBytes = sentInitialPayloadBytes;
    }

    public int SentInitialPayloadBytes { get; }

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
        => _innerStream.Read(buffer, offset, count);

    public override int Read(Span<byte> buffer)
        => _innerStream.Read(buffer);

    public override Task<int> ReadAsync(byte[] buffer, int offset, int count, CancellationToken cancellationToken)
        => _innerStream.ReadAsync(buffer, offset, count, cancellationToken);

    public override ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken cancellationToken = default)
        => _innerStream.ReadAsync(buffer, cancellationToken);

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
            DisposeAsync().AsTask().GetAwaiter().GetResult();
        }

        base.Dispose(disposing);
    }

    public override ValueTask DisposeAsync()
        => _innerStream.DisposeAsync();
}

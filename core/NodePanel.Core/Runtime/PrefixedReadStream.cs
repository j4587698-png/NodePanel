namespace NodePanel.Core.Runtime;

internal sealed class PrefixedReadStream : Stream
{
    private readonly Stream _innerStream;
    private readonly byte[] _prefixBuffer;
    private int _prefixOffset;

    public PrefixedReadStream(Stream innerStream, byte[] prefixBuffer)
    {
        ArgumentNullException.ThrowIfNull(innerStream);
        ArgumentNullException.ThrowIfNull(prefixBuffer);

        _innerStream = innerStream;
        _prefixBuffer = prefixBuffer;
    }

    public override bool CanRead => _innerStream.CanRead;

    public override bool CanSeek => false;

    public override bool CanWrite => _innerStream.CanWrite;

    internal Stream InnerStream => _innerStream;

    public override long Length => throw new NotSupportedException();

    public override long Position
    {
        get => throw new NotSupportedException();
        set => throw new NotSupportedException();
    }

    public override void Flush()
        => _innerStream.Flush();

    public override Task FlushAsync(CancellationToken cancellationToken)
        => _innerStream.FlushAsync(cancellationToken);

    public override int Read(byte[] buffer, int offset, int count)
    {
        if (TryReadPrefix(buffer.AsSpan(offset, count), out var read))
        {
            return read;
        }

        return _innerStream.Read(buffer, offset, count);
    }

    public override Task<int> ReadAsync(byte[] buffer, int offset, int count, CancellationToken cancellationToken)
        => ReadAsync(buffer.AsMemory(offset, count), cancellationToken).AsTask();

    public override async ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken cancellationToken = default)
    {
        if (TryReadPrefix(buffer.Span, out var read))
        {
            return read;
        }

        return await _innerStream.ReadAsync(buffer, cancellationToken).ConfigureAwait(false);
    }

    public override long Seek(long offset, SeekOrigin origin)
        => throw new NotSupportedException();

    public override void SetLength(long value)
        => throw new NotSupportedException();

    public override void Write(byte[] buffer, int offset, int count)
        => _innerStream.Write(buffer, offset, count);

    public override Task WriteAsync(byte[] buffer, int offset, int count, CancellationToken cancellationToken)
        => _innerStream.WriteAsync(buffer, offset, count, cancellationToken);

    public override ValueTask WriteAsync(ReadOnlyMemory<byte> buffer, CancellationToken cancellationToken = default)
        => _innerStream.WriteAsync(buffer, cancellationToken);

    private bool TryReadPrefix(Span<byte> destination, out int read)
    {
        if (_prefixOffset >= _prefixBuffer.Length)
        {
            read = 0;
            return false;
        }

        read = Math.Min(destination.Length, _prefixBuffer.Length - _prefixOffset);
        _prefixBuffer.AsSpan(_prefixOffset, read).CopyTo(destination);
        _prefixOffset += read;
        return true;
    }
}

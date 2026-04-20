using NodePanel.Core.Runtime;

namespace NodePanel.Core.Tests;

internal sealed class BlockingDispatcher : IDispatcher
{
    private readonly Stream _remoteStream;

    public BlockingDispatcher(Stream remoteStream)
    {
        _remoteStream = remoteStream;
    }

    public TaskCompletionSource<bool> DispatchCalled { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);

    public TaskCompletionSource<DispatchContext> DispatchContext { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);

    public TaskCompletionSource<DispatchDestination> DispatchDestination { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);

    public ValueTask<Stream> DispatchTcpAsync(
        DispatchContext context,
        DispatchDestination destination,
        CancellationToken cancellationToken)
    {
        DispatchCalled.TrySetResult(true);
        DispatchContext.TrySetResult(context);
        DispatchDestination.TrySetResult(destination);
        return ValueTask.FromResult(_remoteStream);
    }

    public ValueTask<IOutboundUdpTransport> DispatchUdpAsync(DispatchContext context, CancellationToken cancellationToken)
        => throw new NotSupportedException();
}

internal sealed class PayloadThenPendingStream : Stream
{
    private readonly byte[] _payload;
    private int _position;

    public PayloadThenPendingStream(byte[] payload)
    {
        _payload = payload;
    }

    public override bool CanRead => true;

    public override bool CanSeek => false;

    public override bool CanWrite => true;

    public override long Length => _payload.Length;

    public override long Position
    {
        get => _position;
        set => throw new NotSupportedException();
    }

    public override void Flush()
    {
    }

    public override int Read(byte[] buffer, int offset, int count)
        => throw new NotSupportedException();

    public override async ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken cancellationToken = default)
    {
        if (_position < _payload.Length)
        {
            var count = Math.Min(buffer.Length, _payload.Length - _position);
            _payload.AsMemory(_position, count).CopyTo(buffer);
            _position += count;
            return count;
        }

        await Task.Delay(Timeout.Infinite, cancellationToken);
        return 0;
    }

    public override long Seek(long offset, SeekOrigin origin)
        => throw new NotSupportedException();

    public override void SetLength(long value)
        => throw new NotSupportedException();

    public override void Write(byte[] buffer, int offset, int count)
    {
    }

    public override ValueTask WriteAsync(ReadOnlyMemory<byte> buffer, CancellationToken cancellationToken = default)
        => ValueTask.CompletedTask;
}

internal sealed class SegmentedPayloadThenPendingStream : Stream
{
    private readonly byte[][] _segments;
    private readonly long _length;
    private int _segmentIndex;
    private int _segmentOffset;
    private long _position;

    public SegmentedPayloadThenPendingStream(params byte[][] segments)
    {
        _segments = segments;
        _length = segments.Sum(static segment => (long)segment.Length);
    }

    public override bool CanRead => true;

    public override bool CanSeek => false;

    public override bool CanWrite => true;

    public override long Length => _length;

    public override long Position
    {
        get => _position;
        set => throw new NotSupportedException();
    }

    public override void Flush()
    {
    }

    public override int Read(byte[] buffer, int offset, int count)
        => throw new NotSupportedException();

    public override async ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken cancellationToken = default)
    {
        if (_segmentIndex < _segments.Length)
        {
            var segment = _segments[_segmentIndex];
            var count = Math.Min(buffer.Length, segment.Length - _segmentOffset);
            segment.AsMemory(_segmentOffset, count).CopyTo(buffer);
            _segmentOffset += count;
            _position += count;
            if (_segmentOffset >= segment.Length)
            {
                _segmentIndex++;
                _segmentOffset = 0;
            }

            return count;
        }

        await Task.Delay(Timeout.Infinite, cancellationToken);
        return 0;
    }

    public override long Seek(long offset, SeekOrigin origin)
        => throw new NotSupportedException();

    public override void SetLength(long value)
        => throw new NotSupportedException();

    public override void Write(byte[] buffer, int offset, int count)
    {
    }

    public override ValueTask WriteAsync(ReadOnlyMemory<byte> buffer, CancellationToken cancellationToken = default)
        => ValueTask.CompletedTask;
}

internal sealed class PendingDuplexStream : Stream
{
    public override bool CanRead => true;

    public override bool CanSeek => false;

    public override bool CanWrite => true;

    public override long Length => throw new NotSupportedException();

    public override long Position
    {
        get => throw new NotSupportedException();
        set => throw new NotSupportedException();
    }

    public override void Flush()
    {
    }

    public override int Read(byte[] buffer, int offset, int count)
        => throw new NotSupportedException();

    public override async ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken cancellationToken = default)
    {
        await Task.Delay(Timeout.Infinite, cancellationToken);
        return 0;
    }

    public override ValueTask WriteAsync(ReadOnlyMemory<byte> buffer, CancellationToken cancellationToken = default)
        => ValueTask.CompletedTask;

    public override long Seek(long offset, SeekOrigin origin)
        => throw new NotSupportedException();

    public override void SetLength(long value)
        => throw new NotSupportedException();

    public override void Write(byte[] buffer, int offset, int count)
    {
    }
}

namespace NodePanel.Core.Runtime;

internal readonly struct StreamFlowControl
{
    private readonly ByteRateGate? _primaryGate;
    private readonly ByteRateGate? _secondaryGate;
    private readonly Action<int>? _onTransferred;

    public StreamFlowControl(
        ByteRateGate? primaryGate = null,
        ByteRateGate? secondaryGate = null,
        Action<int>? onTransferred = null)
    {
        _primaryGate = primaryGate;
        _secondaryGate = secondaryGate;
        _onTransferred = onTransferred;
    }

    public async ValueTask ApplyAsync(int bytes, CancellationToken cancellationToken)
    {
        if (bytes <= 0)
        {
            return;
        }

        if (_primaryGate is not null)
        {
            await _primaryGate.WaitAsync(bytes, cancellationToken).ConfigureAwait(false);
        }

        if (_secondaryGate is not null)
        {
            await _secondaryGate.WaitAsync(bytes, cancellationToken).ConfigureAwait(false);
        }
    }

    public void Record(int bytes)
    {
        if (bytes <= 0)
        {
            return;
        }

        _onTransferred?.Invoke(bytes);
    }
}

internal sealed class FlowControlledStream : Stream, IInnerStreamAccessor
{
    private readonly Stream _innerStream;
    private readonly StreamFlowControl _readControl;
    private readonly StreamFlowControl _writeControl;
    private readonly ActivityTimer? _activityTimer;
    private readonly bool _leaveOpen;

    public FlowControlledStream(
        Stream innerStream,
        StreamFlowControl readControl = default,
        StreamFlowControl writeControl = default,
        ActivityTimer? activityTimer = null,
        bool leaveOpen = false)
    {
        _innerStream = innerStream ?? throw new ArgumentNullException(nameof(innerStream));
        _readControl = readControl;
        _writeControl = writeControl;
        _activityTimer = activityTimer;
        _leaveOpen = leaveOpen;
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
        => ReadAsync(buffer.AsMemory(offset, count), CancellationToken.None).AsTask().GetAwaiter().GetResult();

    public override int Read(Span<byte> buffer)
    {
        var scratch = new byte[buffer.Length];
        var read = ReadAsync(scratch, CancellationToken.None).AsTask().GetAwaiter().GetResult();
        scratch.AsSpan(0, read).CopyTo(buffer);
        return read;
    }

    public override Task<int> ReadAsync(byte[] buffer, int offset, int count, CancellationToken cancellationToken)
        => ReadAsync(buffer.AsMemory(offset, count), cancellationToken).AsTask();

    public override async ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken cancellationToken = default)
    {
        var read = await _innerStream.ReadAsync(buffer, cancellationToken).ConfigureAwait(false);
        if (read == 0)
        {
            return 0;
        }

        _activityTimer?.Update();
        await _readControl.ApplyAsync(read, cancellationToken).ConfigureAwait(false);
        _readControl.Record(read);
        return read;
    }

    public override long Seek(long offset, SeekOrigin origin)
        => _innerStream.Seek(offset, origin);

    public override void SetLength(long value)
        => _innerStream.SetLength(value);

    public override void Write(byte[] buffer, int offset, int count)
        => WriteAsync(buffer.AsMemory(offset, count), CancellationToken.None).AsTask().GetAwaiter().GetResult();

    public override void Write(ReadOnlySpan<byte> buffer)
        => WriteAsync(buffer.ToArray(), CancellationToken.None).AsTask().GetAwaiter().GetResult();

    public override Task WriteAsync(byte[] buffer, int offset, int count, CancellationToken cancellationToken)
        => WriteAsync(buffer.AsMemory(offset, count), cancellationToken).AsTask();

    public override async ValueTask WriteAsync(ReadOnlyMemory<byte> buffer, CancellationToken cancellationToken = default)
    {
        if (buffer.IsEmpty)
        {
            return;
        }

        _activityTimer?.Update();
        await _writeControl.ApplyAsync(buffer.Length, cancellationToken).ConfigureAwait(false);
        await _innerStream.WriteAsync(buffer, cancellationToken).ConfigureAwait(false);
        _activityTimer?.Update();
        _writeControl.Record(buffer.Length);
    }

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
        if (_leaveOpen)
        {
            return;
        }

        await _innerStream.DisposeAsync().ConfigureAwait(false);
    }
}

using System.Net.WebSockets;

namespace NodePanel.Core.Transport;

public sealed class WebSocketDuplexStream : Stream
{
    private readonly WebSocket _webSocket;

    public WebSocketDuplexStream(WebSocket webSocket)
    {
        _webSocket = webSocket;
    }

    public override bool CanRead => _webSocket.State is WebSocketState.Open or WebSocketState.CloseSent;

    public override bool CanSeek => false;

    public override bool CanWrite => _webSocket.State is WebSocketState.Open or WebSocketState.CloseReceived;

    public override long Length => throw new NotSupportedException();

    public override long Position
    {
        get => throw new NotSupportedException();
        set => throw new NotSupportedException();
    }

    public override void Flush()
    {
    }

    public override Task FlushAsync(CancellationToken cancellationToken) => Task.CompletedTask;

    public override int Read(byte[] buffer, int offset, int count)
        => ReadAsync(buffer.AsMemory(offset, count)).GetAwaiter().GetResult();

    public override async ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken cancellationToken = default)
    {
        var result = await _webSocket.ReceiveAsync(buffer, cancellationToken).ConfigureAwait(false);
        if (result.MessageType == WebSocketMessageType.Close)
        {
            return 0;
        }

        if (result.MessageType != WebSocketMessageType.Binary)
        {
            throw new InvalidDataException("Only binary WebSocket payload is supported.");
        }

        return result.Count;
    }

    public override void Write(byte[] buffer, int offset, int count)
        => WriteAsync(buffer.AsMemory(offset, count)).GetAwaiter().GetResult();

    public override Task WriteAsync(byte[] buffer, int offset, int count, CancellationToken cancellationToken)
        => WriteAsync(buffer.AsMemory(offset, count), cancellationToken).AsTask();

    public override ValueTask WriteAsync(ReadOnlyMemory<byte> buffer, CancellationToken cancellationToken = default)
        => _webSocket.SendAsync(buffer, WebSocketMessageType.Binary, endOfMessage: true, cancellationToken);

    public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();

    public override void SetLength(long value) => throw new NotSupportedException();

    protected override void Dispose(bool disposing)
    {
        if (disposing)
        {
            _webSocket.Dispose();
        }

        base.Dispose(disposing);
    }

    public override async ValueTask DisposeAsync()
    {
        _webSocket.Dispose();
        await base.DisposeAsync().ConfigureAwait(false);
    }
}

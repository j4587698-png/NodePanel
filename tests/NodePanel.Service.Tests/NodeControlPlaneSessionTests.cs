using System.Net.WebSockets;
using System.Text.Json;
using Microsoft.Extensions.Logging.Abstractions;
using NodePanel.ControlPlane.Protocol;
using NodePanel.Panel.Services;

namespace NodePanel.Service.Tests;

public sealed class NodeControlPlaneSessionTests
{
    [Fact]
    public async Task ReceiveAsync_returns_null_when_socket_is_disposed_during_receive()
    {
        await using var session = new NodeControlPlaneSession(
            new ThrowingWebSocket(
                receiveAsync: static (_, _) => Task.FromException<WebSocketReceiveResult>(
                    new OperationCanceledException("Aborted", new ObjectDisposedException("System.Net.WebSockets.WebSocket")))),
            NullLogger<NodeControlPlaneSession>.Instance);

        var envelope = await session.ReceiveAsync(CancellationToken.None);

        Assert.Null(envelope);
    }

    [Fact]
    public async Task SendAsync_returns_false_when_socket_has_been_disposed()
    {
        await using var session = new NodeControlPlaneSession(
            new ThrowingWebSocket(
                sendAsync: static (_, _, _, _) => Task.FromException(
                    new ObjectDisposedException("System.Net.WebSockets.WebSocket"))),
            NullLogger<NodeControlPlaneSession>.Instance);

        var sent = await session.SendAsync(
            new ControlPlaneEnvelope
            {
                Type = ControlMessageTypes.Heartbeat,
                Payload = JsonSerializer.SerializeToElement(
                    new HeartbeatPayload
                    {
                        Timestamp = DateTimeOffset.UtcNow
                    },
                    ControlPlaneJsonSerializerContext.Default.HeartbeatPayload)
            },
            CancellationToken.None);

        Assert.False(sent);
    }

    [Fact]
    public async Task SendAsync_returns_false_when_socket_is_aborted_during_send()
    {
        await using var session = new NodeControlPlaneSession(
            new ThrowingWebSocket(
                sendAsync: static (_, _, _, _) => Task.FromException(
                    new OperationCanceledException("Aborted", new ObjectDisposedException("System.Net.WebSockets.WebSocket")))),
            NullLogger<NodeControlPlaneSession>.Instance);

        var sent = await session.SendAsync(
            new ControlPlaneEnvelope
            {
                Type = ControlMessageTypes.Heartbeat,
                Payload = JsonSerializer.SerializeToElement(
                    new HeartbeatPayload
                    {
                        Timestamp = DateTimeOffset.UtcNow
                    },
                    ControlPlaneJsonSerializerContext.Default.HeartbeatPayload)
            },
            CancellationToken.None);

        Assert.False(sent);
    }

    [Fact]
    public async Task CloseAsync_ignores_abort_when_socket_is_disposed_mid_close()
    {
        await using var session = new NodeControlPlaneSession(
            new ThrowingWebSocket(
                closeAsync: static (_, _, _) => Task.FromException(
                    new OperationCanceledException("Aborted", new ObjectDisposedException("System.Net.WebSockets.WebSocket")))),
            NullLogger<NodeControlPlaneSession>.Instance);

        await session.CloseAsync(WebSocketCloseStatus.NormalClosure, "closing", CancellationToken.None);
    }

    private sealed class ThrowingWebSocket : WebSocket
    {
        private readonly Func<ArraySegment<byte>, CancellationToken, Task<WebSocketReceiveResult>> _receiveAsync;
        private readonly Func<ArraySegment<byte>, WebSocketMessageType, bool, CancellationToken, Task> _sendAsync;
        private readonly Func<WebSocketCloseStatus, string?, CancellationToken, Task> _closeAsync;
        private WebSocketState _state = WebSocketState.Open;

        public ThrowingWebSocket(
            Func<ArraySegment<byte>, CancellationToken, Task<WebSocketReceiveResult>>? receiveAsync = null,
            Func<ArraySegment<byte>, WebSocketMessageType, bool, CancellationToken, Task>? sendAsync = null,
            Func<WebSocketCloseStatus, string?, CancellationToken, Task>? closeAsync = null)
        {
            _receiveAsync = receiveAsync ?? ((_, _) => Task.FromResult(new WebSocketReceiveResult(0, WebSocketMessageType.Close, true)));
            _sendAsync = sendAsync ?? ((_, _, _, _) => Task.CompletedTask);
            _closeAsync = closeAsync ?? ((_, _, _) => Task.CompletedTask);
        }

        public override WebSocketCloseStatus? CloseStatus => null;

        public override string? CloseStatusDescription => null;

        public override WebSocketState State => _state;

        public override string? SubProtocol => null;

        public override void Abort()
        {
            _state = WebSocketState.Aborted;
        }

        public override Task CloseAsync(WebSocketCloseStatus closeStatus, string? statusDescription, CancellationToken cancellationToken)
        {
            _state = WebSocketState.Closed;
            return _closeAsync(closeStatus, statusDescription, cancellationToken);
        }

        public override Task CloseOutputAsync(WebSocketCloseStatus closeStatus, string? statusDescription, CancellationToken cancellationToken)
        {
            _state = WebSocketState.CloseSent;
            return Task.CompletedTask;
        }

        public override void Dispose()
        {
            _state = WebSocketState.Closed;
        }

        public override Task<WebSocketReceiveResult> ReceiveAsync(ArraySegment<byte> buffer, CancellationToken cancellationToken)
            => _receiveAsync(buffer, cancellationToken);

        public override Task SendAsync(ArraySegment<byte> buffer, WebSocketMessageType messageType, bool endOfMessage, CancellationToken cancellationToken)
            => _sendAsync(buffer, messageType, endOfMessage, cancellationToken);
    }
}

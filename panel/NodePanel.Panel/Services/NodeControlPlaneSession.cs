using System.Net.WebSockets;
using System.Text.Json;
using Microsoft.Extensions.Logging;
using NodePanel.ControlPlane.Protocol;

namespace NodePanel.Panel.Services;

public sealed class NodeControlPlaneSession : IAsyncDisposable
{
    private readonly ILogger<NodeControlPlaneSession> _logger;
    private readonly SemaphoreSlim _sendLock = new(1, 1);
    private readonly WebSocket _socket;

    public NodeControlPlaneSession(WebSocket socket, ILogger<NodeControlPlaneSession> logger)
    {
        _socket = socket;
        _logger = logger;
    }

    public async Task<ControlPlaneEnvelope?> ReceiveAsync(CancellationToken cancellationToken)
    {
        using var buffer = new MemoryStream();
        var chunk = new byte[8 * 1024];

        while (_socket.State == WebSocketState.Open && !cancellationToken.IsCancellationRequested)
        {
            var result = await _socket.ReceiveAsync(chunk.AsMemory(0, chunk.Length), cancellationToken).ConfigureAwait(false);
            if (result.MessageType == WebSocketMessageType.Close)
            {
                return null;
            }

            buffer.Write(chunk, 0, result.Count);
            if (result.EndOfMessage)
            {
                break;
            }
        }

        if (buffer.Length == 0)
        {
            return null;
        }

        return JsonSerializer.Deserialize(buffer.ToArray(), ControlPlaneJsonSerializerContext.Default.ControlPlaneEnvelope);
    }

    public async Task<bool> SendAsync(ControlPlaneEnvelope envelope, CancellationToken cancellationToken)
    {
        var buffer = JsonSerializer.SerializeToUtf8Bytes(envelope, ControlPlaneJsonSerializerContext.Default.ControlPlaneEnvelope);

        await _sendLock.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            if (_socket.State != WebSocketState.Open)
            {
                return false;
            }

            await _socket.SendAsync(buffer.AsMemory(0, buffer.Length), WebSocketMessageType.Text, endOfMessage: true, cancellationToken).ConfigureAwait(false);
            return true;
        }
        catch (WebSocketException ex)
        {
            _logger.LogWarning(ex, "Failed to push control plane message {Type}.", envelope.Type);
            return false;
        }
        finally
        {
            _sendLock.Release();
        }
    }

    public async Task CloseAsync(WebSocketCloseStatus closeStatus, string description, CancellationToken cancellationToken)
    {
        if (_socket.State is not (WebSocketState.Open or WebSocketState.CloseReceived))
        {
            return;
        }

        try
        {
            await _socket.CloseAsync(closeStatus, description, cancellationToken).ConfigureAwait(false);
        }
        catch (WebSocketException ex)
        {
            _logger.LogDebug(ex, "Closing control plane socket failed.");
        }
    }

    public ValueTask DisposeAsync()
    {
        _socket.Dispose();
        _sendLock.Dispose();
        return ValueTask.CompletedTask;
    }
}

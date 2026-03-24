using System.Net.WebSockets;
using System.Text.Json;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using NodePanel.ControlPlane.Protocol;
using NodePanel.Core.Runtime;
using NodePanel.Service.Configuration;
using NodePanel.Service.Runtime;

namespace NodePanel.Service.Services;

public sealed class ControlPlaneClientService : BackgroundService, IControlPlaneConnection
{
    private readonly CertificateRenewalSignal _certificateRenewalSignal;
    private readonly ConfigOrchestrator _configOrchestrator;
    private readonly ILogger<ControlPlaneClientService> _logger;
    private readonly string _nodeId;
    private readonly NodePanelOptions _options;
    private readonly RuntimeConfigStore _runtimeConfigStore;
    private readonly SemaphoreSlim _sendLock = new(1, 1);

    private ClientWebSocket? _socket;

    public ControlPlaneClientService(
        NodePanelOptions options,
        CertificateRenewalSignal certificateRenewalSignal,
        ConfigOrchestrator configOrchestrator,
        RuntimeConfigStore runtimeConfigStore,
        ILogger<ControlPlaneClientService> logger)
    {
        _options = options;
        _certificateRenewalSignal = certificateRenewalSignal;
        _configOrchestrator = configOrchestrator;
        _runtimeConfigStore = runtimeConfigStore;
        _logger = logger;
        _nodeId = string.IsNullOrWhiteSpace(options.Identity.NodeId) ? Environment.MachineName : options.Identity.NodeId;
    }

    public bool IsConnected => Volatile.Read(ref _socket) is { State: WebSocketState.Open };

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        if (!_options.ControlPlane.Enabled || string.IsNullOrWhiteSpace(_options.ControlPlane.Url))
        {
            _logger.LogInformation("Control plane client is disabled.");
            return;
        }

        var uri = new Uri(_options.ControlPlane.Url, UriKind.Absolute);

        while (!stoppingToken.IsCancellationRequested)
        {
            using var socket = new ClientWebSocket();
            socket.Options.KeepAliveInterval = TimeSpan.FromSeconds(_options.ControlPlane.HeartbeatIntervalSeconds);
            if (!string.IsNullOrWhiteSpace(_options.ControlPlane.AccessToken))
            {
                socket.Options.SetRequestHeader("Authorization", $"Bearer {_options.ControlPlane.AccessToken}");
            }

            try
            {
                using var connectCts = CancellationTokenSource.CreateLinkedTokenSource(stoppingToken);
                connectCts.CancelAfter(TimeSpan.FromSeconds(_options.ControlPlane.ConnectTimeoutSeconds));
                await socket.ConnectAsync(uri, connectCts.Token).ConfigureAwait(false);

                Volatile.Write(ref _socket, socket);
                await SendAsync(CreateHelloEnvelope(), stoppingToken).ConfigureAwait(false);

                var receiveLoop = ReceiveLoopAsync(socket, stoppingToken);
                var heartbeatLoop = HeartbeatLoopAsync(stoppingToken);
                await Task.WhenAny(receiveLoop, heartbeatLoop).ConfigureAwait(false);

                try
                {
                    await Task.WhenAll(receiveLoop, heartbeatLoop).ConfigureAwait(false);
                }
                catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested)
                {
                }
            }
            catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested)
            {
                break;
            }
            catch (Exception ex)
            {
                _logger.LogWarning(ex, "Control plane connection failed.");
            }
            finally
            {
                if (ReferenceEquals(Volatile.Read(ref _socket), socket))
                {
                    Volatile.Write(ref _socket, null);
                }
            }

            await Task.Delay(TimeSpan.FromSeconds(_options.ControlPlane.ReconnectDelaySeconds), stoppingToken).ConfigureAwait(false);
        }
    }

    public async Task<bool> SendAsync(ControlPlaneEnvelope envelope, CancellationToken cancellationToken)
    {
        var socket = Volatile.Read(ref _socket);
        if (socket is null || socket.State != WebSocketState.Open)
        {
            return false;
        }

        var buffer = JsonSerializer.SerializeToUtf8Bytes(envelope, ControlPlaneJsonSerializerContext.Default.ControlPlaneEnvelope);

        await _sendLock.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            if (socket.State != WebSocketState.Open)
            {
                return false;
            }

            await socket.SendAsync(buffer.AsMemory(0, buffer.Length), WebSocketMessageType.Text, endOfMessage: true, cancellationToken).ConfigureAwait(false);
            return true;
        }
        catch (WebSocketException ex)
        {
            _logger.LogWarning(ex, "Failed to send control plane message {Type}.", envelope.Type);
            return false;
        }
        finally
        {
            _sendLock.Release();
        }
    }

    private async Task ReceiveLoopAsync(ClientWebSocket socket, CancellationToken cancellationToken)
    {
        while (!cancellationToken.IsCancellationRequested && socket.State == WebSocketState.Open)
        {
            var envelope = await ReceiveEnvelopeAsync(socket, cancellationToken).ConfigureAwait(false);
            if (envelope is null)
            {
                break;
            }

            switch (envelope.Type)
            {
                case ControlMessageTypes.ApplySnapshot:
                    await HandleApplySnapshotAsync(envelope, cancellationToken).ConfigureAwait(false);
                    break;
                case ControlMessageTypes.ApplyPatch:
                    await SendAsync(
                        CreateApplyResultEnvelope(
                            envelope.Revision,
                            success: false,
                            error: "Patch application is not implemented yet."),
                        cancellationToken).ConfigureAwait(false);
                    break;
                case ControlMessageTypes.CertificateRenew:
                    _certificateRenewalSignal.Request("panel");
                    break;
            }
        }
    }

    private async Task HandleApplySnapshotAsync(ControlPlaneEnvelope envelope, CancellationToken cancellationToken)
    {
        var payload = JsonSerializer.Deserialize(
            envelope.Payload.GetRawText(),
            ControlPlaneJsonSerializerContext.Default.ApplySnapshotPayload);

        if (payload is null)
        {
            await SendAsync(
                CreateApplyResultEnvelope(envelope.Revision, success: false, error: "Snapshot payload is empty."),
                cancellationToken).ConfigureAwait(false);
            return;
        }

        var result = await _configOrchestrator.ApplySnapshotAsync(envelope.Revision, payload.Config, cancellationToken).ConfigureAwait(false);
        await SendAsync(CreateApplyResultEnvelope(envelope.Revision, result.Success, result.Error), cancellationToken).ConfigureAwait(false);
    }

    private async Task HeartbeatLoopAsync(CancellationToken cancellationToken)
    {
        while (!cancellationToken.IsCancellationRequested)
        {
            await Task.Delay(TimeSpan.FromSeconds(_options.ControlPlane.HeartbeatIntervalSeconds), cancellationToken).ConfigureAwait(false);
            await SendAsync(CreateHeartbeatEnvelope(), cancellationToken).ConfigureAwait(false);
        }
    }

    private async Task<ControlPlaneEnvelope?> ReceiveEnvelopeAsync(ClientWebSocket socket, CancellationToken cancellationToken)
    {
        using var buffer = new MemoryStream();
        var chunk = new byte[8 * 1024];

        while (socket.State == WebSocketState.Open && !cancellationToken.IsCancellationRequested)
        {
            var result = await socket.ReceiveAsync(chunk.AsMemory(0, chunk.Length), cancellationToken).ConfigureAwait(false);
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

    private ControlPlaneEnvelope CreateHelloEnvelope()
    {
        var payload = new NodeHelloPayload
        {
            NodeId = _nodeId,
            Version = NodePanel.Service.ApplicationVersion.Current,
            Capabilities = new[] { "trojan", "vless", "vmess", "udp", "tls", "ws", "stats", "rate-limit", "certificate-renew" },
            AppliedRevision = _runtimeConfigStore.GetSnapshot().Revision
        };

        return CreateEnvelope(
            ControlMessageTypes.NodeHello,
            _runtimeConfigStore.GetSnapshot().Revision,
            payload,
            ControlPlaneJsonSerializerContext.Default.NodeHelloPayload);
    }

    private ControlPlaneEnvelope CreateHeartbeatEnvelope()
    {
        var payload = new HeartbeatPayload
        {
            Timestamp = DateTimeOffset.UtcNow
        };

        return CreateEnvelope(
            ControlMessageTypes.Heartbeat,
            _runtimeConfigStore.GetSnapshot().Revision,
            payload,
            ControlPlaneJsonSerializerContext.Default.HeartbeatPayload);
    }

    private ControlPlaneEnvelope CreateApplyResultEnvelope(int requestedRevision, bool success, string? error)
    {
        var payload = new ApplyResultPayload
        {
            RequestedRevision = requestedRevision,
            Success = success,
            Error = error
        };

        return CreateEnvelope(
            ControlMessageTypes.ApplyResult,
            _runtimeConfigStore.GetSnapshot().Revision,
            payload,
            ControlPlaneJsonSerializerContext.Default.ApplyResultPayload);
    }

    private ControlPlaneEnvelope CreateEnvelope<TPayload>(
        string type,
        int revision,
        TPayload payload,
        System.Text.Json.Serialization.Metadata.JsonTypeInfo<TPayload> typeInfo)
    {
        return new ControlPlaneEnvelope
        {
            Type = type,
            NodeId = _nodeId,
            Revision = revision,
            Payload = JsonSerializer.SerializeToElement(payload, typeInfo)
        };
    }
}

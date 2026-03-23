using System.Net;
using NodePanel.Core.Protocol;

namespace NodePanel.Core.Runtime;

internal sealed record VmessInboundSessionOptions : ITrojanInboundConnectionOptions
{
    public string InboundTag { get; init; } = string.Empty;

    public int HandshakeTimeoutSeconds { get; init; } = 60;

    public int ConnectTimeoutSeconds { get; init; } = 10;

    public int ConnectionIdleSeconds { get; init; } = 300;

    public int UplinkOnlySeconds { get; init; } = 1;

    public int DownlinkOnlySeconds { get; init; } = 1;

    public bool UseCone { get; init; } = true;

    public bool ReceiveOriginalDestination { get; init; }

    public string ServerName { get; init; } = string.Empty;

    public string Alpn { get; init; } = string.Empty;

    public EndPoint? RemoteEndPoint { get; init; }

    public EndPoint? LocalEndPoint { get; init; }

    public EndPoint? OriginalDestinationEndPoint { get; init; }

    public ITrojanSniffingDefinition Sniffing { get; init; } = TrojanSniffingRuntime.Disabled;

    public bool DrainOnHandshakeFailure { get; init; }

    public IReadOnlyList<VmessUser> Users { get; init; } = Array.Empty<VmessUser>();

    internal VmessInboundRuntimeState? RuntimeState { get; init; }

    public bool TryAuthenticate(string passwordHash, out TrojanUser? user)
    {
        user = null;
        return false;
    }

    public IReadOnlyList<ITrojanFallbackDefinition> Fallbacks => Array.Empty<ITrojanFallbackDefinition>();
}

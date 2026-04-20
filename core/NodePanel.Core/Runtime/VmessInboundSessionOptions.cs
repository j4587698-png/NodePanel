using System.Net;
using NodePanel.Core.Protocol;

namespace NodePanel.Core.Runtime;

internal sealed record VmessInboundSessionOptions : IRuntimeInboundConnectionOptions
{
    internal RuntimeSessionPolicyCatalog SessionPolicies { get; init; } = RuntimeSessionPolicyCatalog.Default;

    public string InboundTag { get; init; } = string.Empty;

    public int UserLevel { get; init; }

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

    public IRuntimeSniffingDefinition Sniffing { get; init; } = RuntimeSniffingOptions.Disabled;

    public bool DrainOnHandshakeFailure { get; init; }

    public IReadOnlyList<VmessUser> Users { get; init; } = Array.Empty<VmessUser>();

    internal VmessInboundRuntimeState? RuntimeState { get; init; }

    internal IReadOnlyList<VmessUser> ResolveUsers()
        => Users;

    internal VmessInboundSessionOptions WithUserLevel(int userLevel)
    {
        var limits = RuntimeInboundSessionLimitResolver.Resolve(this, SessionPolicies, userLevel);
        return this with
        {
            UserLevel = Math.Max(0, userLevel),
            HandshakeTimeoutSeconds = limits.HandshakeTimeoutSeconds,
            ConnectTimeoutSeconds = limits.ConnectTimeoutSeconds,
            ConnectionIdleSeconds = limits.ConnectionIdleSeconds,
            UplinkOnlySeconds = limits.UplinkOnlySeconds,
            DownlinkOnlySeconds = limits.DownlinkOnlySeconds
        };
    }
}

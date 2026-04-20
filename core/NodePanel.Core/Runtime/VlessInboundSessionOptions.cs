using System.Net;
using System.Security.Authentication;
using NodePanel.Core.Protocol;

namespace NodePanel.Core.Runtime;

internal sealed record VlessInboundSessionOptions : IRuntimeFallbackConnectionOptions
{
    internal VlessInboundRuntimeState? RuntimeState { get; init; }

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

    internal string Transport { get; init; } = string.Empty;

    internal string TransportProtocol { get; init; } = string.Empty;

    internal string SecurityType { get; init; } = string.Empty;

    internal SslProtocols OuterTlsProtocol { get; init; } = SslProtocols.None;

    public EndPoint? RemoteEndPoint { get; init; }

    public EndPoint? LocalEndPoint { get; init; }

    public EndPoint? OriginalDestinationEndPoint { get; init; }

    public IRuntimeSniffingDefinition Sniffing { get; init; } = RuntimeSniffingOptions.Disabled;

    internal string Decryption { get; init; } = string.Empty;

    internal uint XorMode { get; init; }

    internal int SecondsFrom { get; init; }

    internal int SecondsTo { get; init; }

    internal string Padding { get; init; } = string.Empty;

    public IReadOnlyList<IRuntimeFallbackDefinition> Fallbacks { get; init; } = Array.Empty<IRuntimeFallbackDefinition>();

    public bool TryResolveUser(string uuid, out VlessUser? user)
    {
        if (RuntimeState is not null)
        {
            return RuntimeState.TryResolveUser(uuid, out user);
        }

        user = null;
        return false;
    }

    internal VlessInboundSessionOptions WithUserLevel(int userLevel)
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

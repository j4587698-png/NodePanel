using System.Net;
using System.Security.Authentication;

namespace NodePanel.Core.Runtime;

internal static class RuntimeTlsInboundSessionOptionsFactory
{
    public static TrojanInboundSessionOptions Create(
        TrojanInboundServerOptions options,
        TrojanTlsInboundRuntime inbound,
        string serverName,
        string alpn,
        EndPoint? remoteEndPoint,
        EndPoint? localEndPoint,
        IPEndPoint? originalDestinationEndPoint)
    {
        var common = CreateCommon(
            inbound.Tag,
            inbound.HandshakeTimeoutSeconds,
            inbound.ReceiveOriginalDestination,
            inbound.Sniffing,
            options.Limits,
            options.UseCone,
            serverName,
            alpn,
            remoteEndPoint,
            localEndPoint,
            originalDestinationEndPoint);

        return new TrojanInboundSessionOptions
        {
            RuntimeState = inbound.RuntimeState,
            SessionPolicies = options.SessionPolicies,
            InboundTag = common.InboundTag,
            HandshakeTimeoutSeconds = common.HandshakeTimeoutSeconds,
            ConnectTimeoutSeconds = common.ConnectTimeoutSeconds,
            ConnectionIdleSeconds = common.ConnectionIdleSeconds,
            UplinkOnlySeconds = common.UplinkOnlySeconds,
            DownlinkOnlySeconds = common.DownlinkOnlySeconds,
            UseCone = common.UseCone,
            ReceiveOriginalDestination = common.ReceiveOriginalDestination,
            ServerName = common.ServerName,
            Alpn = common.Alpn,
            RemoteEndPoint = common.RemoteEndPoint,
            LocalEndPoint = common.LocalEndPoint,
            OriginalDestinationEndPoint = common.OriginalDestinationEndPoint,
            Sniffing = common.Sniffing,
            Fallbacks = inbound.Fallbacks
        };
    }

    public static VlessInboundSessionOptions Create(
        VlessInboundServerOptions options,
        VlessTlsInboundRuntime inbound,
        string serverName,
        string alpn,
        SslProtocols outerTlsProtocol,
        EndPoint? remoteEndPoint,
        EndPoint? localEndPoint,
        IPEndPoint? originalDestinationEndPoint)
    {
        var common = CreateCommon(
            inbound.Tag,
            inbound.HandshakeTimeoutSeconds,
            inbound.ReceiveOriginalDestination,
            inbound.Sniffing,
            options.Limits,
            options.UseCone,
            serverName,
            alpn,
            remoteEndPoint,
            localEndPoint,
            originalDestinationEndPoint);

        return new VlessInboundSessionOptions
        {
            RuntimeState = inbound.RuntimeState,
            SessionPolicies = options.SessionPolicies,
            InboundTag = common.InboundTag,
            HandshakeTimeoutSeconds = common.HandshakeTimeoutSeconds,
            ConnectTimeoutSeconds = common.ConnectTimeoutSeconds,
            ConnectionIdleSeconds = common.ConnectionIdleSeconds,
            UplinkOnlySeconds = common.UplinkOnlySeconds,
            DownlinkOnlySeconds = common.DownlinkOnlySeconds,
            UseCone = common.UseCone,
            ReceiveOriginalDestination = common.ReceiveOriginalDestination,
            ServerName = common.ServerName,
            Alpn = common.Alpn,
            Transport = inbound.Transport,
            TransportProtocol = inbound.TransportProtocol,
            SecurityType = inbound.SecurityType,
            OuterTlsProtocol = outerTlsProtocol,
            RemoteEndPoint = common.RemoteEndPoint,
            LocalEndPoint = common.LocalEndPoint,
            OriginalDestinationEndPoint = common.OriginalDestinationEndPoint,
            Sniffing = common.Sniffing,
            Decryption = inbound.Decryption,
            XorMode = inbound.XorMode,
            SecondsFrom = inbound.SecondsFrom,
            SecondsTo = inbound.SecondsTo,
            Padding = inbound.Padding,
            Fallbacks = inbound.Fallbacks
        };
    }

    public static VmessInboundSessionOptions Create(
        VmessInboundServerOptions options,
        VmessTlsInboundRuntime inbound,
        string serverName,
        string alpn,
        EndPoint? remoteEndPoint,
        EndPoint? localEndPoint,
        IPEndPoint? originalDestinationEndPoint)
    {
        var common = CreateCommon(
            inbound.Tag,
            inbound.HandshakeTimeoutSeconds,
            inbound.ReceiveOriginalDestination,
            inbound.Sniffing,
            options.Limits,
            options.UseCone,
            serverName,
            alpn,
            remoteEndPoint,
            localEndPoint,
            originalDestinationEndPoint);

        return new VmessInboundSessionOptions
        {
            RuntimeState = inbound.RuntimeState,
            SessionPolicies = options.SessionPolicies,
            InboundTag = common.InboundTag,
            HandshakeTimeoutSeconds = common.HandshakeTimeoutSeconds,
            ConnectTimeoutSeconds = common.ConnectTimeoutSeconds,
            ConnectionIdleSeconds = common.ConnectionIdleSeconds,
            UplinkOnlySeconds = common.UplinkOnlySeconds,
            DownlinkOnlySeconds = common.DownlinkOnlySeconds,
            UseCone = common.UseCone,
            ReceiveOriginalDestination = common.ReceiveOriginalDestination,
            ServerName = common.ServerName,
            Alpn = common.Alpn,
            RemoteEndPoint = common.RemoteEndPoint,
            LocalEndPoint = common.LocalEndPoint,
            OriginalDestinationEndPoint = common.OriginalDestinationEndPoint,
            DrainOnHandshakeFailure = true,
            Sniffing = common.Sniffing,
            Users = inbound.Users
        };
    }

    private static RuntimeTlsInboundSessionCommonOptions CreateCommon(
        string inboundTag,
        int handshakeTimeoutSeconds,
        bool receiveOriginalDestination,
        IRuntimeSniffingDefinition sniffing,
        IRuntimeInboundLimits limits,
        bool useCone,
        string serverName,
        string alpn,
        EndPoint? remoteEndPoint,
        EndPoint? localEndPoint,
        IPEndPoint? originalDestinationEndPoint)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(inboundTag);
        ArgumentNullException.ThrowIfNull(sniffing);
        ArgumentNullException.ThrowIfNull(limits);

        return new RuntimeTlsInboundSessionCommonOptions(
            inboundTag,
            handshakeTimeoutSeconds,
            limits.ConnectTimeoutSeconds,
            limits.ConnectionIdleSeconds,
            limits.UplinkOnlySeconds,
            limits.DownlinkOnlySeconds,
            useCone,
            receiveOriginalDestination,
            serverName ?? string.Empty,
            alpn ?? string.Empty,
            remoteEndPoint,
            localEndPoint,
            receiveOriginalDestination ? originalDestinationEndPoint : null,
            sniffing);
    }
}

internal readonly record struct RuntimeTlsInboundSessionCommonOptions(
    string InboundTag,
    int HandshakeTimeoutSeconds,
    int ConnectTimeoutSeconds,
    int ConnectionIdleSeconds,
    int UplinkOnlySeconds,
    int DownlinkOnlySeconds,
    bool UseCone,
    bool ReceiveOriginalDestination,
    string ServerName,
    string Alpn,
    EndPoint? RemoteEndPoint,
    EndPoint? LocalEndPoint,
    EndPoint? OriginalDestinationEndPoint,
    IRuntimeSniffingDefinition Sniffing);

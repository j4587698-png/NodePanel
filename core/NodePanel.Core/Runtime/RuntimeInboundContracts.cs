using System.Net;

namespace NodePanel.Core.Runtime;

public interface IRuntimeInboundLimits
{
    long GlobalBytesPerSecond { get; }

    int ConnectTimeoutSeconds { get; }

    int ConnectionIdleSeconds { get; }

    int UplinkOnlySeconds { get; }

    int DownlinkOnlySeconds { get; }
}

public interface IRuntimeInboundConnectionOptions
{
    string InboundTag { get; }

    int UserLevel => 0;

    int HandshakeTimeoutSeconds { get; }

    int ConnectTimeoutSeconds { get; }

    int ConnectionIdleSeconds { get; }

    int UplinkOnlySeconds { get; }

    int DownlinkOnlySeconds { get; }

    bool UseCone { get; }

    bool ReceiveOriginalDestination { get; }

    string ServerName { get; }

    string Alpn { get; }

    EndPoint? RemoteEndPoint { get; }

    EndPoint? LocalEndPoint { get; }

    EndPoint? OriginalDestinationEndPoint { get; }

    IRuntimeSniffingDefinition Sniffing { get; }
}

internal sealed class DefaultRuntimeInboundConnectionOptions : IRuntimeInboundConnectionOptions
{
    public static IRuntimeInboundConnectionOptions Instance { get; } = new DefaultRuntimeInboundConnectionOptions();

    private DefaultRuntimeInboundConnectionOptions()
    {
    }

    public string InboundTag => string.Empty;

    public int UserLevel => 0;

    public int HandshakeTimeoutSeconds => 60;

    public int ConnectTimeoutSeconds => 10;

    public int ConnectionIdleSeconds => 300;

    public int UplinkOnlySeconds => 1;

    public int DownlinkOnlySeconds => 1;

    public bool UseCone => true;

    public bool ReceiveOriginalDestination => false;

    public string ServerName => string.Empty;

    public string Alpn => string.Empty;

    public EndPoint? RemoteEndPoint => null;

    public EndPoint? LocalEndPoint => null;

    public EndPoint? OriginalDestinationEndPoint => null;

    public IRuntimeSniffingDefinition Sniffing => RuntimeSniffingOptions.Disabled;
}

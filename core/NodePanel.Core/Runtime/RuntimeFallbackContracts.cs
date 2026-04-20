using System.Net;

namespace NodePanel.Core.Runtime;

public interface IRuntimeFallbackDefinition
{
    string Name { get; }

    string Alpn { get; }

    string Path { get; }

    string Type { get; }

    string Dest { get; }

    int ProxyProtocolVersion { get; }
}

public interface IRuntimeFallbackConnectionOptions : IRuntimeInboundConnectionOptions
{
    new int ConnectTimeoutSeconds { get; }

    new string ServerName { get; }

    new string Alpn { get; }

    new EndPoint? RemoteEndPoint { get; }

    new EndPoint? LocalEndPoint { get; }

    IReadOnlyList<IRuntimeFallbackDefinition> Fallbacks { get; }
}

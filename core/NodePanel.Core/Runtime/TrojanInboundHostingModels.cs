using System.Net;
using System.Security.Cryptography.X509Certificates;

namespace NodePanel.Core.Runtime;

public sealed record TrojanInboundServerOptions
{
    public TrojanInboundRuntimePlan Plan { get; init; } = TrojanInboundRuntimePlan.Empty;

    public TrojanInboundServerLimits Limits { get; init; } = new();

    public TrojanInboundTlsOptions? Tls { get; init; }

    public bool UseCone { get; init; } = true;

    public TrojanInboundServerCallbacks Callbacks { get; init; } = new();
}

public sealed record TrojanInboundServerLimits : ITrojanInboundLimits
{
    public long GlobalBytesPerSecond { get; init; }

    public int ConnectTimeoutSeconds { get; init; } = 10;

    public int ConnectionIdleSeconds { get; init; } = 300;

    public int UplinkOnlySeconds { get; init; } = 1;

    public int DownlinkOnlySeconds { get; init; } = 1;
}

public sealed record TrojanInboundTlsOptions
{
    public required X509Certificate2 Certificate { get; init; }

    public TrojanTlsServerNamePolicyOptions ServerNamePolicy { get; init; } = new();

    public TrojanClientHelloPolicyRuntime ClientHelloPolicy { get; init; } = TrojanClientHelloPolicyRuntime.Disabled;
}

public sealed record TrojanTlsServerNamePolicyOptions
{
    public bool RejectUnknownServerName { get; init; }

    public IReadOnlyList<string> ConfiguredServerNames { get; init; } = Array.Empty<string>();
}

public sealed record TrojanInboundServerCallbacks
{
    public Action<TrojanTlsListenerRuntime>? ListenerStarted { get; init; }

    public Action<TrojanInboundClientHelloRejectionContext>? ClientHelloRejected { get; init; }

    public Action<TrojanInboundSniRejectionContext>? UnknownServerNameRejected { get; init; }

    public Action<TrojanInboundConnectionErrorContext>? ConnectionError { get; init; }
}

public sealed record TrojanInboundClientHelloRejectionContext
{
    public EndPoint? RemoteEndPoint { get; init; }

    public TrojanTlsClientHelloMetadata? Metadata { get; init; }

    public string Reason { get; init; } = string.Empty;
}

public sealed record TrojanInboundSniRejectionContext
{
    public EndPoint? RemoteEndPoint { get; init; }

    public string RequestedServerName { get; init; } = string.Empty;
}

public sealed record TrojanInboundConnectionErrorContext
{
    public Exception Exception { get; init; } = new InvalidOperationException("Unknown trojan inbound connection error.");

    public EndPoint? RemoteEndPoint { get; init; }
}

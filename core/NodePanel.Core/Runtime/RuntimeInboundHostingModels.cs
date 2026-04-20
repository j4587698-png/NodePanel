using System.Net;

namespace NodePanel.Core.Runtime;

public sealed record RuntimeTlsServerNamePolicyOptions
{
    public bool RejectUnknownServerName { get; init; }

    public IReadOnlyList<string> ConfiguredServerNames { get; init; } = Array.Empty<string>();
}

public sealed record RuntimeTlsClientHelloRejectionContext
{
    public EndPoint? RemoteEndPoint { get; init; }

    public RuntimeTlsClientHelloMetadata? Metadata { get; init; }

    public string Reason { get; init; } = string.Empty;
}

public sealed record RuntimeTlsServerNameRejectionContext
{
    public EndPoint? RemoteEndPoint { get; init; }

    public string RequestedServerName { get; init; } = string.Empty;
}

public sealed record RuntimeInboundConnectionErrorContext
{
    public Exception Exception { get; init; } = new InvalidOperationException("Unknown inbound connection error.");

    public EndPoint? RemoteEndPoint { get; init; }
}

namespace NodePanel.Core.Runtime;

public sealed record VlessInboundServerOptions
{
    public VlessInboundRuntimePlan Plan { get; init; } = VlessInboundRuntimePlan.Empty;

    public TrojanInboundServerLimits Limits { get; init; } = new();

    public TrojanInboundTlsOptions? Tls { get; init; }

    public bool UseCone { get; init; } = true;

    public VlessInboundServerCallbacks Callbacks { get; init; } = new();
}

public sealed record VlessInboundServerCallbacks
{
    public Action<VlessTlsListenerRuntime>? ListenerStarted { get; init; }

    public Action<TrojanInboundClientHelloRejectionContext>? ClientHelloRejected { get; init; }

    public Action<TrojanInboundSniRejectionContext>? UnknownServerNameRejected { get; init; }

    public Action<TrojanInboundConnectionErrorContext>? ConnectionError { get; init; }
}

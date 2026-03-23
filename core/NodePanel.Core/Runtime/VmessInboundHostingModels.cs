namespace NodePanel.Core.Runtime;

public sealed record VmessInboundServerOptions
{
    public VmessInboundRuntimePlan Plan { get; init; } = VmessInboundRuntimePlan.Empty;

    public TrojanInboundServerLimits Limits { get; init; } = new();

    public TrojanInboundTlsOptions? Tls { get; init; }

    public bool UseCone { get; init; } = true;

    public VmessInboundServerCallbacks Callbacks { get; init; } = new();
}

public sealed record VmessInboundServerCallbacks
{
    public Action<VmessTlsListenerRuntime>? ListenerStarted { get; init; }

    public Action<TrojanInboundClientHelloRejectionContext>? ClientHelloRejected { get; init; }

    public Action<TrojanInboundSniRejectionContext>? UnknownServerNameRejected { get; init; }

    public Action<TrojanInboundConnectionErrorContext>? ConnectionError { get; init; }
}

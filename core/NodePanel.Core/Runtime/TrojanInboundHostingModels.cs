namespace NodePanel.Core.Runtime;

public sealed record TrojanInboundServerOptions
{
    public TrojanInboundRuntimePlan Plan { get; init; } = TrojanInboundRuntimePlan.Empty;

    public RuntimeTransportLimits Limits { get; init; } = new();

    public RuntimeSessionPolicyCatalog SessionPolicies { get; init; } = RuntimeSessionPolicyCatalog.Default;

    public RuntimeTlsOptions? Tls { get; init; }

    public RuntimeRealityServerOptions? Reality { get; init; }

    public bool UseCone { get; init; } = true;

    public TrojanInboundServerCallbacks Callbacks { get; init; } = new();
}

public sealed record TrojanInboundServerCallbacks
{
    public Action<TrojanTlsListenerRuntime>? ListenerStarted { get; init; }

    public Action<RuntimeTlsClientHelloRejectionContext>? ClientHelloRejected { get; init; }

    public Action<RuntimeTlsServerNameRejectionContext>? UnknownServerNameRejected { get; init; }

    public Action<RuntimeInboundConnectionErrorContext>? ConnectionError { get; init; }
}

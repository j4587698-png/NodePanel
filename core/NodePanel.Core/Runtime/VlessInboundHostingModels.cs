namespace NodePanel.Core.Runtime;

public sealed record VlessInboundServerOptions
{
    public VlessInboundRuntimePlan Plan { get; init; } = VlessInboundRuntimePlan.Empty;

    public RuntimeTransportLimits Limits { get; init; } = new();

    public RuntimeSessionPolicyCatalog SessionPolicies { get; init; } = RuntimeSessionPolicyCatalog.Default;

    public RuntimeTlsOptions? Tls { get; init; }

    public RuntimeRealityServerOptions? Reality { get; init; }

    public bool UseCone { get; init; } = true;

    public VlessInboundServerCallbacks Callbacks { get; init; } = new();
}

public sealed record VlessInboundServerCallbacks
{
    public Action<VlessTlsListenerRuntime>? ListenerStarted { get; init; }

    public Action<RuntimeTlsClientHelloRejectionContext>? ClientHelloRejected { get; init; }

    public Action<RuntimeTlsServerNameRejectionContext>? UnknownServerNameRejected { get; init; }

    public Action<RuntimeInboundConnectionErrorContext>? ConnectionError { get; init; }
}

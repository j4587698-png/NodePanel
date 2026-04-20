namespace NodePanel.Core.Runtime;

public sealed record VmessInboundServerOptions
{
    public VmessInboundRuntimePlan Plan { get; init; } = VmessInboundRuntimePlan.Empty;

    public RuntimeTransportLimits Limits { get; init; } = new();

    public RuntimeSessionPolicyCatalog SessionPolicies { get; init; } = RuntimeSessionPolicyCatalog.Default;

    public RuntimeTlsOptions? Tls { get; init; }

    public RuntimeRealityServerOptions? Reality { get; init; }

    public bool UseCone { get; init; } = true;

    public VmessInboundServerCallbacks Callbacks { get; init; } = new();
}

public sealed record VmessInboundServerCallbacks
{
    public Action<VmessTlsListenerRuntime>? ListenerStarted { get; init; }

    public Action<RuntimeTlsClientHelloRejectionContext>? ClientHelloRejected { get; init; }

    public Action<RuntimeTlsServerNameRejectionContext>? UnknownServerNameRejected { get; init; }

    public Action<RuntimeInboundConnectionErrorContext>? ConnectionError { get; init; }
}

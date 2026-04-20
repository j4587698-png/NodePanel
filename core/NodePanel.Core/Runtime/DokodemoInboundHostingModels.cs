namespace NodePanel.Core.Runtime;

public sealed record DokodemoInboundServerOptions
{
    public DokodemoInboundRuntimePlan Plan { get; init; } = DokodemoInboundRuntimePlan.Empty;

    public RuntimeTransportLimits Limits { get; init; } = new();

    public RuntimeSessionPolicyCatalog SessionPolicies { get; init; } = RuntimeSessionPolicyCatalog.Default;

    public bool UseCone { get; init; } = true;

    public DokodemoInboundServerCallbacks Callbacks { get; init; } = new();
}

public sealed record DokodemoInboundServerCallbacks
{
    public Action<DokodemoInboundListenerContext>? ListenerStarted { get; init; }

    public Action<RuntimeInboundConnectionErrorContext>? ConnectionError { get; init; }
}

public sealed record DokodemoInboundListenerContext
{
    public required string Tag { get; init; }

    public required ListenerBinding Binding { get; init; }

    public required string Network { get; init; }
}

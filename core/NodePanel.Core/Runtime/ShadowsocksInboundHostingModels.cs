namespace NodePanel.Core.Runtime;

public sealed record ShadowsocksInboundServerOptions
{
    public ShadowsocksInboundRuntimePlan Plan { get; init; } = ShadowsocksInboundRuntimePlan.Empty;

    public RuntimeTransportLimits Limits { get; init; } = new();

    public RuntimeSessionPolicyCatalog SessionPolicies { get; init; } = RuntimeSessionPolicyCatalog.Default;

    public bool UseCone { get; init; } = true;

    public ShadowsocksInboundServerCallbacks Callbacks { get; init; } = new();
}

public sealed record ShadowsocksInboundServerCallbacks
{
    public Action<ShadowsocksInboundListenerContext>? ListenerStarted { get; init; }

    public Action<RuntimeInboundConnectionErrorContext>? ConnectionError { get; init; }
}

public sealed record ShadowsocksInboundListenerContext
{
    public required string Tag { get; init; }

    public required ListenerBinding Binding { get; init; }

    public required string Network { get; init; }
}

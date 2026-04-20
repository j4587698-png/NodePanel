using NodePanel.Core.Protocol;

namespace NodePanel.Core.Runtime;

public interface IRuntimeInboundEventSink
{
    void ReportListenerStarted(IReadOnlyList<string> listenerKeys, string message);

    void ReportConnectionError(RuntimeInboundConnectionErrorReport report);

    void ReportClientHelloRejected(RuntimeInboundClientHelloRejectedReport report);

    void ReportUnknownServerNameRejected(RuntimeInboundUnknownServerNameRejectedReport report);

    DokodemoInboundServerCallbacks CreateDokodemoCallbacks();

    TrojanInboundServerCallbacks CreateTrojanCallbacks();

    ShadowsocksInboundServerCallbacks CreateShadowsocksCallbacks();

    VlessInboundServerCallbacks CreateVlessCallbacks();

    VmessInboundServerCallbacks CreateVmessCallbacks();

    ProxyInboundServerCallbacks CreateProxyInboundCallbacks(string protocol, string message);
}

public sealed record RuntimeInboundConnectionErrorReport
{
    public required string Protocol { get; init; }

    public string Tag { get; init; } = string.Empty;

    public bool IsProxyInbound { get; init; }

    public string? RemoteEndPoint { get; init; }

    public string Message { get; init; } = "Inbound connection failed.";

    public Exception Exception { get; init; } = new InvalidOperationException("Inbound connection failed.");
}

public sealed record RuntimeInboundClientHelloRejectedReport
{
    public required string Protocol { get; init; }

    public string? RemoteEndPoint { get; init; }

    public string ServerName { get; init; } = string.Empty;

    public string Ja3Hash { get; init; } = string.Empty;

    public string Reason { get; init; } = string.Empty;
}

public sealed record RuntimeInboundUnknownServerNameRejectedReport
{
    public required string Protocol { get; init; }

    public string? RemoteEndPoint { get; init; }

    public string RequestedServerName { get; init; } = string.Empty;
}

public interface IRuntimeInboundHandlerFactory
{
    string Protocol { get; }

    int CountStartupSignals(RuntimePlan plan);

    IReadOnlyList<RuntimeListenerStatus> CreateListenerStatuses(RuntimePlan plan);

    IInboundHandler? Create(RuntimeInboundHandlerContext context);
}

public interface IRuntimeInboundComposition
{
    int CountStartupSignals(RuntimePlan plan);

    IReadOnlyList<RuntimeListenerStatus> CreateListenerStatuses(RuntimePlan plan);

    IInboundManager CreateManager(RuntimeInboundHandlerContext context);
}

public sealed class RuntimeInboundHandlerContext
{
    public required RuntimePlan Plan { get; init; }

    public required RuntimeComponentResolver Resolver { get; init; }

    public required IRuntimeInboundEventSink Callbacks { get; init; }

    public required RuntimeTransportLimits InboundLimits { get; init; }

    public required RuntimeTlsOptions? InboundTls { get; init; }

    public required RuntimeRealityServerOptions? InboundReality { get; init; }

    public required ProxyInboundServerLimits ProxyInboundLimits { get; init; }
}

internal sealed class DefaultRuntimeInboundComposition : IRuntimeInboundComposition
{
    private readonly IReadOnlyList<IRuntimeInboundHandlerFactory> _factories;

    public DefaultRuntimeInboundComposition(IReadOnlyList<IRuntimeInboundHandlerFactory> factories)
    {
        ArgumentNullException.ThrowIfNull(factories);
        _factories = factories.ToArray();
    }

    public int CountStartupSignals(RuntimePlan plan)
    {
        ArgumentNullException.ThrowIfNull(plan);

        var count = 0;
        foreach (var factory in _factories)
        {
            count += factory.CountStartupSignals(plan);
        }

        return count;
    }

    public IReadOnlyList<RuntimeListenerStatus> CreateListenerStatuses(RuntimePlan plan)
    {
        ArgumentNullException.ThrowIfNull(plan);

        return _factories
            .SelectMany(factory => factory.CreateListenerStatuses(plan))
            .OrderBy(static listener => listener.Protocol, StringComparer.Ordinal)
            .ThenBy(static listener => listener.Tag, StringComparer.Ordinal)
            .ToArray();
    }

    public IInboundManager CreateManager(RuntimeInboundHandlerContext context)
    {
        ArgumentNullException.ThrowIfNull(context);

        var manager = new DefaultInboundManager();
        foreach (var factory in _factories)
        {
            var handler = factory.Create(context);
            if (handler is not null)
            {
                manager.AddHandler(handler);
            }
        }

        return manager;
    }
}

public sealed class RuntimeInboundHandler : IInboundHandler
{
    private readonly Func<CancellationToken, Task> _runAsync;

    public RuntimeInboundHandler(
        string name,
        string protocol,
        IReadOnlyList<string> listenerKeys,
        int startupSignalCount,
        Func<CancellationToken, Task> runAsync)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(name);
        ArgumentException.ThrowIfNullOrWhiteSpace(protocol);
        ArgumentNullException.ThrowIfNull(listenerKeys);
        ArgumentNullException.ThrowIfNull(runAsync);

        Name = name.Trim();
        Protocol = protocol.Trim();
        ListenerKeys = listenerKeys;
        StartupSignalCount = Math.Max(0, startupSignalCount);
        _runAsync = runAsync;
    }

    public string Name { get; }

    public string Protocol { get; }

    public IReadOnlyList<string> ListenerKeys { get; }

    public int StartupSignalCount { get; }

    public Task RunAsync(CancellationToken cancellationToken) => _runAsync(cancellationToken);

    public ValueTask DisposeAsync() => ValueTask.CompletedTask;
}

internal sealed class DokodemoInboundHandlerFactory : IRuntimeInboundHandlerFactory
{
    public string Protocol => InboundProtocols.DokodemoDoor;

    public int CountStartupSignals(RuntimePlan plan)
    {
        return plan.Plan.TryGetInboundPlan(InboundProtocols.DokodemoDoor, out DokodemoInboundRuntimePlan inboundPlan)
            ? inboundPlan.Inbounds.Sum(static inbound => (inbound.HasTcp ? 1 : 0) + (inbound.HasUdp ? 1 : 0))
            : 0;
    }

    public IReadOnlyList<RuntimeListenerStatus> CreateListenerStatuses(RuntimePlan plan)
        => plan.Plan.TryGetInboundPlan(InboundProtocols.DokodemoDoor, out DokodemoInboundRuntimePlan inboundPlan)
            ? RuntimeInboundListenerStatusFactory.CreateDokodemoStatuses(inboundPlan)
            : Array.Empty<RuntimeListenerStatus>();

    public IInboundHandler? Create(RuntimeInboundHandlerContext context)
    {
        if (!context.Plan.Plan.TryGetInboundPlan(InboundProtocols.DokodemoDoor, out DokodemoInboundRuntimePlan plan) ||
            plan.Inbounds.Count == 0)
        {
            return null;
        }

        var listenerKeys = plan.Inbounds
            .SelectMany(static inbound => CreateDokodemoListenerKeys(inbound))
            .ToArray();
        if (listenerKeys.Length == 0)
        {
            return null;
        }

        return new RuntimeInboundHandler(
            "dokodemo-door-inbound",
            InboundProtocols.DokodemoDoor,
            listenerKeys,
            listenerKeys.Length,
            cancellationToken => context.Resolver.GetRequired<DokodemoInboundServer>().RunAsync(
                new DokodemoInboundServerOptions
                {
                    Plan = plan,
                    Limits = context.InboundLimits,
                    SessionPolicies = context.Plan.SessionPolicies,
                    UseCone = context.Plan.UseCone,
                    Callbacks = context.Callbacks.CreateDokodemoCallbacks()
                },
                cancellationToken));
    }

    private static IReadOnlyList<string> CreateDokodemoListenerKeys(DokodemoInboundRuntime inbound)
    {
        var keys = new List<string>(2);
        if (inbound.HasTcp)
        {
            keys.Add(RuntimeListenerKeys.CreateListenerKey(
                InboundProtocols.DokodemoDoor,
                inbound.Tag,
                RoutingNetworks.Tcp,
                inbound.Binding));
        }

        if (inbound.HasUdp)
        {
            keys.Add(RuntimeListenerKeys.CreateListenerKey(
                InboundProtocols.DokodemoDoor,
                inbound.Tag,
                RoutingNetworks.Udp,
                inbound.Binding));
        }

        return keys;
    }
}

internal sealed class TrojanInboundHandlerFactory : IRuntimeInboundHandlerFactory
{
    public string Protocol => InboundProtocols.Trojan;

    public int CountStartupSignals(RuntimePlan plan)
    {
        return plan.Plan.TryGetInboundPlan(InboundProtocols.Trojan, out TrojanInboundRuntimePlan inboundPlan)
            ? inboundPlan.Listeners.Count
            : 0;
    }

    public IReadOnlyList<RuntimeListenerStatus> CreateListenerStatuses(RuntimePlan plan)
        => plan.Plan.TryGetInboundPlan(InboundProtocols.Trojan, out TrojanInboundRuntimePlan inboundPlan)
            ? RuntimeInboundListenerStatusFactory.CreateTrojanStatuses(inboundPlan)
            : Array.Empty<RuntimeListenerStatus>();

    public IInboundHandler? Create(RuntimeInboundHandlerContext context)
    {
        if (!context.Plan.Plan.TryGetInboundPlan(InboundProtocols.Trojan, out TrojanInboundRuntimePlan plan) ||
            plan.Listeners.Count == 0)
        {
            return null;
        }

        return new RuntimeInboundHandler(
            "trojan-inbound",
            InboundProtocols.Trojan,
            RuntimeListenerKeys.GetListenerKeys(plan),
            plan.Listeners.Count,
            cancellationToken => context.Resolver.GetRequired<TrojanInboundServer>().RunAsync(
                new TrojanInboundServerOptions
                {
                    Plan = plan,
                    Limits = context.InboundLimits,
                    SessionPolicies = context.Plan.SessionPolicies,
                    Tls = context.InboundTls,
                    Reality = context.InboundReality,
                    UseCone = context.Plan.UseCone,
                    Callbacks = context.Callbacks.CreateTrojanCallbacks()
                },
                cancellationToken));
    }
}

internal sealed class ShadowsocksInboundHandlerFactory : IRuntimeInboundHandlerFactory
{
    public string Protocol => InboundProtocols.Shadowsocks;

    public int CountStartupSignals(RuntimePlan plan)
    {
        if (!plan.Plan.TryGetInboundPlan(InboundProtocols.Shadowsocks, out ShadowsocksInboundRuntimePlan inboundPlan))
        {
            return 0;
        }

        var count = 0;
        foreach (var inbound in inboundPlan.Inbounds)
        {
            if (inbound.HasTcp)
            {
                count++;
            }

            if (inbound.HasUdp)
            {
                count++;
            }
        }

        foreach (var inbound in inboundPlan.Inbounds2022)
        {
            if (inbound.HasTcp)
            {
                count++;
            }

            if (inbound.HasUdp)
            {
                count++;
            }
        }

        return count;
    }

    public IReadOnlyList<RuntimeListenerStatus> CreateListenerStatuses(RuntimePlan plan)
        => plan.Plan.TryGetInboundPlan(InboundProtocols.Shadowsocks, out ShadowsocksInboundRuntimePlan inboundPlan)
            ? RuntimeInboundListenerStatusFactory.CreateShadowsocksStatuses(inboundPlan)
            : Array.Empty<RuntimeListenerStatus>();

    public IInboundHandler? Create(RuntimeInboundHandlerContext context)
    {
        if (!context.Plan.Plan.TryGetInboundPlan(InboundProtocols.Shadowsocks, out ShadowsocksInboundRuntimePlan plan))
        {
            return null;
        }

        if (plan.Inbounds.Count == 0 &&
            plan.Inbounds2022.Count == 0)
        {
            return null;
        }

        return new RuntimeInboundHandler(
            "shadowsocks-inbound",
            InboundProtocols.Shadowsocks,
            RuntimeListenerKeys.GetListenerKeys(plan),
            CountStartupSignals(context.Plan),
            cancellationToken => context.Resolver.GetRequired<ShadowsocksInboundServer>().RunAsync(
                new ShadowsocksInboundServerOptions
                {
                    Plan = plan,
                    Limits = context.InboundLimits,
                    SessionPolicies = context.Plan.SessionPolicies,
                    UseCone = context.Plan.UseCone,
                    Callbacks = context.Callbacks.CreateShadowsocksCallbacks()
                },
                cancellationToken));
    }
}

internal sealed class VlessInboundHandlerFactory : IRuntimeInboundHandlerFactory
{
    public string Protocol => InboundProtocols.Vless;

    public int CountStartupSignals(RuntimePlan plan)
    {
        return plan.Plan.TryGetInboundPlan(InboundProtocols.Vless, out VlessInboundRuntimePlan inboundPlan)
            ? inboundPlan.Listeners.Count
            : 0;
    }

    public IReadOnlyList<RuntimeListenerStatus> CreateListenerStatuses(RuntimePlan plan)
        => plan.Plan.TryGetInboundPlan(InboundProtocols.Vless, out VlessInboundRuntimePlan inboundPlan)
            ? RuntimeInboundListenerStatusFactory.CreateVlessStatuses(inboundPlan)
            : Array.Empty<RuntimeListenerStatus>();

    public IInboundHandler? Create(RuntimeInboundHandlerContext context)
    {
        if (!context.Plan.Plan.TryGetInboundPlan(InboundProtocols.Vless, out VlessInboundRuntimePlan plan) ||
            plan.Listeners.Count == 0)
        {
            return null;
        }

        return new RuntimeInboundHandler(
            "vless-inbound",
            InboundProtocols.Vless,
            RuntimeListenerKeys.GetListenerKeys(plan),
            plan.Listeners.Count,
            cancellationToken => context.Resolver.GetRequired<VlessInboundServer>().RunAsync(
                new VlessInboundServerOptions
                {
                    Plan = plan,
                    Limits = context.InboundLimits,
                    SessionPolicies = context.Plan.SessionPolicies,
                    Tls = context.InboundTls,
                    Reality = context.InboundReality,
                    UseCone = context.Plan.UseCone,
                    Callbacks = context.Callbacks.CreateVlessCallbacks()
                },
                cancellationToken));
    }
}

internal sealed class VmessInboundHandlerFactory : IRuntimeInboundHandlerFactory
{
    public string Protocol => InboundProtocols.Vmess;

    public int CountStartupSignals(RuntimePlan plan)
    {
        return plan.Plan.TryGetInboundPlan(InboundProtocols.Vmess, out VmessInboundRuntimePlan inboundPlan)
            ? inboundPlan.Listeners.Count
            : 0;
    }

    public IReadOnlyList<RuntimeListenerStatus> CreateListenerStatuses(RuntimePlan plan)
        => plan.Plan.TryGetInboundPlan(InboundProtocols.Vmess, out VmessInboundRuntimePlan inboundPlan)
            ? RuntimeInboundListenerStatusFactory.CreateVmessStatuses(inboundPlan)
            : Array.Empty<RuntimeListenerStatus>();

    public IInboundHandler? Create(RuntimeInboundHandlerContext context)
    {
        if (!context.Plan.Plan.TryGetInboundPlan(InboundProtocols.Vmess, out VmessInboundRuntimePlan plan) ||
            plan.Listeners.Count == 0)
        {
            return null;
        }

        return new RuntimeInboundHandler(
            "vmess-inbound",
            InboundProtocols.Vmess,
            RuntimeListenerKeys.GetListenerKeys(plan),
            plan.Listeners.Count,
            cancellationToken => context.Resolver.GetRequired<VmessInboundServer>().RunAsync(
                new VmessInboundServerOptions
                {
                    Plan = plan,
                    Limits = context.InboundLimits,
                    SessionPolicies = context.Plan.SessionPolicies,
                    Tls = context.InboundTls,
                    Reality = context.InboundReality,
                    UseCone = context.Plan.UseCone,
                    Callbacks = context.Callbacks.CreateVmessCallbacks()
                },
                cancellationToken));
    }
}

internal sealed class SocksInboundHandlerFactory : IRuntimeInboundHandlerFactory
{
    public string Protocol => ProxyInboundProtocols.Socks;

    public int CountStartupSignals(RuntimePlan plan)
    {
        return plan.ProxyInbounds.SocksListeners.Count;
    }

    public IReadOnlyList<RuntimeListenerStatus> CreateListenerStatuses(RuntimePlan plan)
        => RuntimeInboundListenerStatusFactory.CreateProxyInboundStatuses(
            ProxyInboundProtocols.Socks,
            plan.ProxyInbounds.SocksListeners);

    public IInboundHandler? Create(RuntimeInboundHandlerContext context)
    {
        if (context.Plan.ProxyInbounds.SocksListeners.Count == 0)
        {
            return null;
        }

        return new RuntimeInboundHandler(
            "socks-inbound",
            ProxyInboundProtocols.Socks,
            RuntimeListenerKeys.GetListenerKeys(ProxyInboundProtocols.Socks, context.Plan.ProxyInbounds.SocksListeners),
            context.Plan.ProxyInbounds.SocksListeners.Count,
            cancellationToken => context.Resolver.GetRequired<SocksInboundServer>().RunAsync(
                new SocksInboundServerOptions
                {
                    Listeners = context.Plan.ProxyInbounds.SocksListeners,
                    Limits = context.ProxyInboundLimits,
                    UseCone = context.Plan.UseCone,
                    AuthenticationsByTag = context.Plan.ProxyInbounds.SocksAuthenticationsByTag,
                    Callbacks = context.Callbacks.CreateProxyInboundCallbacks(
                        ProxyInboundProtocols.Socks,
                        "SOCKS inbound is running.")
                },
                cancellationToken));
    }
}

internal sealed class HttpInboundHandlerFactory : IRuntimeInboundHandlerFactory
{
    public string Protocol => ProxyInboundProtocols.Http;

    public int CountStartupSignals(RuntimePlan plan)
    {
        return plan.ProxyInbounds.HttpListeners.Count;
    }

    public IReadOnlyList<RuntimeListenerStatus> CreateListenerStatuses(RuntimePlan plan)
        => RuntimeInboundListenerStatusFactory.CreateProxyInboundStatuses(
            ProxyInboundProtocols.Http,
            plan.ProxyInbounds.HttpListeners);

    public IInboundHandler? Create(RuntimeInboundHandlerContext context)
    {
        if (context.Plan.ProxyInbounds.HttpListeners.Count == 0)
        {
            return null;
        }

        return new RuntimeInboundHandler(
            "http-inbound",
            ProxyInboundProtocols.Http,
            RuntimeListenerKeys.GetListenerKeys(ProxyInboundProtocols.Http, context.Plan.ProxyInbounds.HttpListeners),
            context.Plan.ProxyInbounds.HttpListeners.Count,
            cancellationToken => context.Resolver.GetRequired<HttpInboundServer>().RunAsync(
                new HttpInboundServerOptions
                {
                    Listeners = context.Plan.ProxyInbounds.HttpListeners,
                    Limits = context.ProxyInboundLimits,
                    AuthenticationsByTag = context.Plan.ProxyInbounds.HttpAuthenticationsByTag,
                    Callbacks = context.Callbacks.CreateProxyInboundCallbacks(
                        ProxyInboundProtocols.Http,
                        "HTTP inbound is running.")
                },
                cancellationToken));
    }
}

internal static class RuntimeInboundListenerStatusFactory
{
    public static IReadOnlyList<RuntimeListenerStatus> CreateDokodemoStatuses(DokodemoInboundRuntimePlan plan)
        => plan.Inbounds
            .SelectMany(static inbound => CreateDokodemoInboundStatuses(inbound))
            .ToArray();

    public static IReadOnlyList<RuntimeListenerStatus> CreateTrojanStatuses(TrojanInboundRuntimePlan plan)
        => plan.Listeners
            .SelectMany(static listener => CreateInboundStatuses(
                InboundProtocols.Trojan,
                listener.Inbounds,
                static inbound => (inbound.Tag, inbound.Transport, inbound.Binding)))
            .ToArray();

    public static IReadOnlyList<RuntimeListenerStatus> CreateShadowsocksStatuses(ShadowsocksInboundRuntimePlan plan)
        => plan.Inbounds
            .SelectMany(CreateInboundStatuses)
            .Concat(plan.Inbounds2022.SelectMany(CreateInboundStatuses))
            .ToArray();

    public static IReadOnlyList<RuntimeListenerStatus> CreateVlessStatuses(VlessInboundRuntimePlan plan)
        => plan.Listeners
            .SelectMany(static listener => CreateInboundStatuses(
                InboundProtocols.Vless,
                listener.Inbounds,
                static inbound => (inbound.Tag, inbound.Transport, inbound.Binding)))
            .ToArray();

    public static IReadOnlyList<RuntimeListenerStatus> CreateVmessStatuses(VmessInboundRuntimePlan plan)
        => plan.Listeners
            .SelectMany(static listener => CreateInboundStatuses(
                InboundProtocols.Vmess,
                listener.Inbounds,
                static inbound => (inbound.Tag, inbound.Transport, inbound.Binding)))
            .ToArray();

    public static IReadOnlyList<RuntimeListenerStatus> CreateProxyInboundStatuses(
        string protocol,
        IReadOnlyList<ProxyInboundListenerDefinition> listeners)
        => listeners
            .Select(listener => CreateInboundStatus(protocol, listener.Tag, string.Empty, listener.Binding, isProxyInbound: true))
            .ToArray();

    private static IReadOnlyList<RuntimeListenerStatus> CreateInboundStatuses<TInbound>(
        string protocol,
        IReadOnlyList<TInbound> inbounds,
        Func<TInbound, (string Tag, string Transport, ListenerBinding Binding)> projector)
    {
        return inbounds
            .Select(inbound =>
            {
                var (tag, transport, binding) = projector(inbound);
                return CreateInboundStatus(protocol, tag, transport, binding, isProxyInbound: false);
            })
            .ToArray();
    }

    private static IReadOnlyList<RuntimeListenerStatus> CreateInboundStatuses(ShadowsocksInboundRuntime inbound)
    {
        var items = new List<RuntimeListenerStatus>(2);
        if (inbound.HasTcp)
        {
            items.Add(CreateInboundStatus(
                InboundProtocols.Shadowsocks,
                inbound.Tag,
                RoutingNetworks.Tcp,
                inbound.Binding,
                isProxyInbound: false));
        }

        if (inbound.HasUdp)
        {
            items.Add(CreateInboundStatus(
                InboundProtocols.Shadowsocks,
                inbound.Tag,
                RoutingNetworks.Udp,
                inbound.Binding,
                isProxyInbound: false));
        }

        return items;
    }

    private static IReadOnlyList<RuntimeListenerStatus> CreateInboundStatuses(Shadowsocks2022InboundRuntime inbound)
    {
        var items = new List<RuntimeListenerStatus>(2);
        if (inbound.HasTcp)
        {
            items.Add(CreateInboundStatus(
                InboundProtocols.Shadowsocks,
                inbound.Tag,
                RoutingNetworks.Tcp,
                inbound.Binding,
                isProxyInbound: false));
        }

        if (inbound.HasUdp)
        {
            items.Add(CreateInboundStatus(
                InboundProtocols.Shadowsocks,
                inbound.Tag,
                RoutingNetworks.Udp,
                inbound.Binding,
                isProxyInbound: false));
        }

        return items;
    }

    private static IReadOnlyList<RuntimeListenerStatus> CreateDokodemoInboundStatuses(DokodemoInboundRuntime inbound)
    {
        var items = new List<RuntimeListenerStatus>(2);
        if (inbound.HasTcp)
        {
            items.Add(CreateInboundStatus(
                InboundProtocols.DokodemoDoor,
                inbound.Tag,
                RoutingNetworks.Tcp,
                inbound.Binding,
                isProxyInbound: false));
        }

        if (inbound.HasUdp)
        {
            items.Add(CreateInboundStatus(
                InboundProtocols.DokodemoDoor,
                inbound.Tag,
                RoutingNetworks.Udp,
                inbound.Binding,
                isProxyInbound: false));
        }

        return items;
    }

    private static IReadOnlyList<RuntimeListenerStatus> CreateInboundStatuses(
        string protocol,
        VlessTlsInboundRuntime? rawTls,
        VlessTlsInboundRuntime? webSocket)
    {
        var items = new List<RuntimeListenerStatus>(2);
        if (rawTls is not null)
        {
            items.Add(CreateInboundStatus(protocol, rawTls.Tag, rawTls.Transport, rawTls.Binding, isProxyInbound: false));
        }

        if (webSocket is not null)
        {
            items.Add(CreateInboundStatus(protocol, webSocket.Tag, webSocket.Transport, webSocket.Binding, isProxyInbound: false));
        }

        return items;
    }

    private static IReadOnlyList<RuntimeListenerStatus> CreateInboundStatuses(
        string protocol,
        VmessTlsInboundRuntime? rawTls,
        VmessTlsInboundRuntime? webSocket)
    {
        var items = new List<RuntimeListenerStatus>(2);
        if (rawTls is not null)
        {
            items.Add(CreateInboundStatus(protocol, rawTls.Tag, rawTls.Transport, rawTls.Binding, isProxyInbound: false));
        }

        if (webSocket is not null)
        {
            items.Add(CreateInboundStatus(protocol, webSocket.Tag, webSocket.Transport, webSocket.Binding, isProxyInbound: false));
        }

        return items;
    }

    private static RuntimeListenerStatus CreateInboundStatus(
        string protocol,
        string tag,
        string transport,
        ListenerBinding binding,
        bool isProxyInbound)
    {
        return new RuntimeListenerStatus
        {
            Tag = tag,
            Protocol = protocol,
            Transport = transport,
            Binding = binding,
            IsProxyInbound = isProxyInbound,
            State = RuntimeState.Starting,
            Message = "Starting listener.",
            UpdatedAt = DateTimeOffset.UtcNow
        };
    }
}

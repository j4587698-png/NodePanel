using NodePanel.Core.Protocol;

namespace NodePanel.Core.Runtime;

internal sealed class RuntimeInboundEventBridge : IRuntimeInboundEventSink
{
    private readonly int _revision;
    private readonly RuntimeStartupCoordinator _startup;
    private readonly Action<int, IReadOnlyList<string>, string> _onInboundListenerStarted;
    private readonly Action<int, string, ProxyInboundListenerDefinition, string> _onProxyInboundListenerStarted;
    private readonly Action<int, RuntimeInboundConnectionErrorReport> _onInboundConnectionError;
    private readonly Action<int, RuntimeInboundClientHelloRejectedReport> _onInboundClientHelloRejected;
    private readonly Action<int, RuntimeInboundUnknownServerNameRejectedReport> _onInboundUnknownServerNameRejected;
    private readonly Action<int, ProxyInboundConnectionAccessedContext> _onConnectionAccessed;

    public RuntimeInboundEventBridge(
        int revision,
        RuntimeStartupCoordinator startup,
        Action<int, IReadOnlyList<string>, string> onInboundListenerStarted,
        Action<int, string, ProxyInboundListenerDefinition, string> onProxyInboundListenerStarted,
        Action<int, RuntimeInboundConnectionErrorReport> onInboundConnectionError,
        Action<int, RuntimeInboundClientHelloRejectedReport> onInboundClientHelloRejected,
        Action<int, RuntimeInboundUnknownServerNameRejectedReport> onInboundUnknownServerNameRejected,
        Action<int, ProxyInboundConnectionAccessedContext> onConnectionAccessed)
    {
        _revision = revision;
        _startup = startup;
        _onInboundListenerStarted = onInboundListenerStarted;
        _onProxyInboundListenerStarted = onProxyInboundListenerStarted;
        _onInboundConnectionError = onInboundConnectionError;
        _onInboundClientHelloRejected = onInboundClientHelloRejected;
        _onInboundUnknownServerNameRejected = onInboundUnknownServerNameRejected;
        _onConnectionAccessed = onConnectionAccessed;
    }

    public void ReportListenerStarted(IReadOnlyList<string> listenerKeys, string message)
    {
        ArgumentNullException.ThrowIfNull(listenerKeys);
        _startup.ReportStarted();
        _onInboundListenerStarted(_revision, listenerKeys, message ?? string.Empty);
    }

    public void ReportConnectionError(RuntimeInboundConnectionErrorReport report)
    {
        ArgumentNullException.ThrowIfNull(report);
        _onInboundConnectionError(_revision, report);
    }

    public void ReportClientHelloRejected(RuntimeInboundClientHelloRejectedReport report)
    {
        ArgumentNullException.ThrowIfNull(report);
        _onInboundClientHelloRejected(_revision, report);
    }

    public void ReportUnknownServerNameRejected(RuntimeInboundUnknownServerNameRejectedReport report)
    {
        ArgumentNullException.ThrowIfNull(report);
        _onInboundUnknownServerNameRejected(_revision, report);
    }

    public void ReportProxyInboundListenerStarted(
        string protocol,
        ProxyInboundListenerDefinition listener,
        string message)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(protocol);
        ArgumentNullException.ThrowIfNull(listener);

        _startup.ReportStarted();
        _onProxyInboundListenerStarted(_revision, protocol, listener, message ?? string.Empty);
    }

    public DokodemoInboundServerCallbacks CreateDokodemoCallbacks()
    {
        return new DokodemoInboundServerCallbacks
        {
            ListenerStarted = context => ReportListenerStarted(
            [
                RuntimeListenerKeys.CreateListenerKey(
                    InboundProtocols.DokodemoDoor,
                    context.Tag,
                    context.Network,
                    context.Binding)
            ],
                $"Dokodemo-door {context.Network.ToUpperInvariant()} listener '{RuntimeListenerKeys.DescribeBinding(context.Binding)}' is running."),
            ConnectionError = context => ReportConnectionError(
                new RuntimeInboundConnectionErrorReport
                {
                    Protocol = InboundProtocols.DokodemoDoor,
                    RemoteEndPoint = context.RemoteEndPoint?.ToString(),
                    Message = "Inbound connection failed.",
                    Exception = context.Exception
                })
        };
    }

    public TrojanInboundServerCallbacks CreateTrojanCallbacks()
    {
        return new TrojanInboundServerCallbacks
        {
            ListenerStarted = listener => ReportListenerStarted(
                RuntimeListenerKeys.GetListenerKeys(listener),
                $"Trojan listener '{RuntimeListenerKeys.DescribeBinding(listener.Binding)}' is running."),
            ConnectionError = context => ReportConnectionError(
                new RuntimeInboundConnectionErrorReport
                {
                    Protocol = InboundProtocols.Trojan,
                    RemoteEndPoint = context.RemoteEndPoint?.ToString(),
                    Message = "Inbound connection failed.",
                    Exception = context.Exception
                }),
            ClientHelloRejected = context => ReportClientHelloRejected(
                new RuntimeInboundClientHelloRejectedReport
                {
                    Protocol = InboundProtocols.Trojan,
                    RemoteEndPoint = context.RemoteEndPoint?.ToString(),
                    ServerName = context.Metadata?.ServerName ?? string.Empty,
                    Ja3Hash = context.Metadata?.Ja3Hash ?? string.Empty,
                    Reason = context.Reason
                }),
            UnknownServerNameRejected = context => ReportUnknownServerNameRejected(
                new RuntimeInboundUnknownServerNameRejectedReport
                {
                    Protocol = InboundProtocols.Trojan,
                    RemoteEndPoint = context.RemoteEndPoint?.ToString(),
                    RequestedServerName = context.RequestedServerName
                })
        };
    }

    public ShadowsocksInboundServerCallbacks CreateShadowsocksCallbacks()
    {
        return new ShadowsocksInboundServerCallbacks
        {
            ListenerStarted = context => ReportListenerStarted(
                RuntimeListenerKeys.GetListenerKeys(context.Tag, context.Network, context.Binding),
                $"Shadowsocks {context.Network.ToUpperInvariant()} listener '{RuntimeListenerKeys.DescribeBinding(context.Binding)}' is running."),
            ConnectionError = context => ReportConnectionError(
                new RuntimeInboundConnectionErrorReport
                {
                    Protocol = InboundProtocols.Shadowsocks,
                    RemoteEndPoint = context.RemoteEndPoint?.ToString(),
                    Message = "Inbound connection failed.",
                    Exception = context.Exception
                })
        };
    }

    public VlessInboundServerCallbacks CreateVlessCallbacks()
    {
        return new VlessInboundServerCallbacks
        {
            ListenerStarted = listener => ReportListenerStarted(
                RuntimeListenerKeys.GetListenerKeys(listener),
                $"VLESS listener '{RuntimeListenerKeys.DescribeBinding(listener.Binding)}' is running."),
            ConnectionError = context => ReportConnectionError(
                new RuntimeInboundConnectionErrorReport
                {
                    Protocol = InboundProtocols.Vless,
                    RemoteEndPoint = context.RemoteEndPoint?.ToString(),
                    Message = "Inbound connection failed.",
                    Exception = context.Exception
                }),
            ClientHelloRejected = context => ReportClientHelloRejected(
                new RuntimeInboundClientHelloRejectedReport
                {
                    Protocol = InboundProtocols.Vless,
                    RemoteEndPoint = context.RemoteEndPoint?.ToString(),
                    ServerName = context.Metadata?.ServerName ?? string.Empty,
                    Ja3Hash = context.Metadata?.Ja3Hash ?? string.Empty,
                    Reason = context.Reason
                }),
            UnknownServerNameRejected = context => ReportUnknownServerNameRejected(
                new RuntimeInboundUnknownServerNameRejectedReport
                {
                    Protocol = InboundProtocols.Vless,
                    RemoteEndPoint = context.RemoteEndPoint?.ToString(),
                    RequestedServerName = context.RequestedServerName
                })
        };
    }

    public VmessInboundServerCallbacks CreateVmessCallbacks()
    {
        return new VmessInboundServerCallbacks
        {
            ListenerStarted = listener => ReportListenerStarted(
                RuntimeListenerKeys.GetListenerKeys(listener),
                $"VMess listener '{RuntimeListenerKeys.DescribeBinding(listener.Binding)}' is running."),
            ConnectionError = context => ReportConnectionError(
                new RuntimeInboundConnectionErrorReport
                {
                    Protocol = InboundProtocols.Vmess,
                    RemoteEndPoint = context.RemoteEndPoint?.ToString(),
                    Message = "Inbound connection failed.",
                    Exception = context.Exception
                }),
            ClientHelloRejected = context => ReportClientHelloRejected(
                new RuntimeInboundClientHelloRejectedReport
                {
                    Protocol = InboundProtocols.Vmess,
                    RemoteEndPoint = context.RemoteEndPoint?.ToString(),
                    ServerName = context.Metadata?.ServerName ?? string.Empty,
                    Ja3Hash = context.Metadata?.Ja3Hash ?? string.Empty,
                    Reason = context.Reason
                }),
            UnknownServerNameRejected = context => ReportUnknownServerNameRejected(
                new RuntimeInboundUnknownServerNameRejectedReport
                {
                    Protocol = InboundProtocols.Vmess,
                    RemoteEndPoint = context.RemoteEndPoint?.ToString(),
                    RequestedServerName = context.RequestedServerName
                })
        };
    }

    public void ReportConnectionAccessed(ProxyInboundConnectionAccessedContext context)
    {
        ArgumentNullException.ThrowIfNull(context);
        _onConnectionAccessed(_revision, context);
    }

    public ProxyInboundServerCallbacks CreateProxyInboundCallbacks(string protocol, string message)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(protocol);

        return new ProxyInboundServerCallbacks
        {
            ListenerStarted = listener => ReportProxyInboundListenerStarted(protocol, listener, message),
            ConnectionError = context => ReportConnectionError(
                new RuntimeInboundConnectionErrorReport
                {
                    Protocol = ProxyInboundProtocols.Normalize(context.Protocol),
                    Tag = context.InboundTag,
                    IsProxyInbound = true,
                    RemoteEndPoint = context.RemoteEndPoint?.ToString(),
                    Message = "Proxy inbound connection failed.",
                    Exception = context.Exception
                }),
            ConnectionAccessed = ReportConnectionAccessed
        };
    }
}

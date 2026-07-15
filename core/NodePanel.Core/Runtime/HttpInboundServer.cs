namespace NodePanel.Core.Runtime;

public class HttpInboundServer
{
    private readonly IDispatcher _dispatcher;
    private readonly IRuntimeRelayService _relayService;
    private readonly IRuntimeSniffer _runtimeSniffer;

    public HttpInboundServer(IDispatcher dispatcher, IRuntimeRelayService relayService)
        : this(dispatcher, relayService, fakeDnsEngine: null)
    {
    }

    public HttpInboundServer(
        IDispatcher dispatcher,
        IRuntimeRelayService relayService,
        IFakeDnsEngine? fakeDnsEngine)
        : this(
            dispatcher,
            relayService,
            new DefaultRuntimeSniffer(fakeDnsEngine))
    {
    }

    internal HttpInboundServer(
        IDispatcher dispatcher,
        IRuntimeRelayService relayService,
        IRuntimeSniffer runtimeSniffer)
    {
        _dispatcher = dispatcher;
        _relayService = relayService;
        _runtimeSniffer = runtimeSniffer ?? throw new ArgumentNullException(nameof(runtimeSniffer));
    }

    public async Task RunAsync(HttpInboundServerOptions options, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(options);

        if (options.Listeners.Count == 0)
        {
            return;
        }

        var activeListeners = options.Listeners
            .Select(listener => new ListenerRuntime(
                listener,
                ResolveAuthentication(listener.Tag, options.AuthenticationsByTag)))
            .ToArray();

        await InboundServerRuntimeSupport.RunAsync(
            activeListeners,
            static listener => listener.Definition.Binding,
            listener => options.Callbacks.ListenerStarted?.Invoke(listener.Definition),
            (listener, handle, token) => InboundServerRuntimeSupport.AcceptLoopAsync(
                listener,
                handle,
                (connection, definition, innerToken) => HandleAcceptedConnectionAsync(connection, definition, options, innerToken),
                token),
            "HTTP proxy inbound accept loop ended unexpectedly.",
            cancellationToken).ConfigureAwait(false);
    }

    private async Task HandleAcceptedConnectionAsync(
        AcceptedConnection connection,
        ListenerRuntime listener,
        HttpInboundServerOptions options,
        CancellationToken cancellationToken)
    {
        await using var connectionLease = connection;
        try
        {
            var proxyOptions = CreateConnectionOptions(listener.Definition, connection, options.Limits, options.Callbacks);
            await HttpInboundProcessor.HandleAsync(
                    connection.Stream,
                    _dispatcher,
                    _relayService,
                    _runtimeSniffer,
                    proxyOptions,
                    cancellationToken,
                    listener.Authentication)
                .ConfigureAwait(false);
        }
        catch (Exception ex) when (ex is not OperationCanceledException || !cancellationToken.IsCancellationRequested)
        {
            options.Callbacks.ConnectionError?.Invoke(new ProxyInboundConnectionErrorContext
            {
                Protocol = ProxyInboundProtocols.Http,
                InboundTag = listener.Definition.Tag,
                Exception = ex,
                RemoteEndPoint = connection.LogRemoteEndPoint ?? connection.RemoteEndPoint
            });
        }
    }

    private static ProxyInboundConnectionOptions CreateConnectionOptions(
        ProxyInboundListenerDefinition listener,
        AcceptedConnection connection,
        ProxyInboundServerLimits limits,
        ProxyInboundServerCallbacks callbacks)
        => new()
        {
            InboundTag = listener.Tag,
            UserId = "proxy-user",
            ScopedUserId = "proxy-user",
            UserLevel = listener.UserLevel,
            HandshakeTimeoutSeconds = listener.HandshakeTimeoutSeconds > 0
                ? listener.HandshakeTimeoutSeconds
                : limits.ConnectTimeoutSeconds,
            ConnectTimeoutSeconds = limits.ConnectTimeoutSeconds,
            ConnectionIdleSeconds = limits.ConnectionIdleSeconds,
            UplinkOnlySeconds = limits.UplinkOnlySeconds,
            DownlinkOnlySeconds = limits.DownlinkOnlySeconds,
            AllowTransparent = listener.AllowTransparent,
            Sniffing = listener.Sniffing,
            RemoteEndPoint = connection.LogRemoteEndPoint ?? connection.RemoteEndPoint,
            LocalEndPoint = connection.LocalEndPoint,
            ConnectionAccessed = callbacks.ConnectionAccessed
        };

    private static Socks5LocalAuthenticationOptions ResolveAuthentication(
        string inboundTag,
        IReadOnlyDictionary<string, Socks5LocalAuthenticationOptions> authenticationsByTag)
    {
        if (!string.IsNullOrWhiteSpace(inboundTag) &&
            authenticationsByTag.TryGetValue(inboundTag, out var authentication) &&
            authentication is not null)
        {
            return authentication;
        }

        return Socks5LocalAuthenticationOptions.Disabled;
    }

    private sealed record ListenerRuntime(
        ProxyInboundListenerDefinition Definition,
        Socks5LocalAuthenticationOptions Authentication);
}

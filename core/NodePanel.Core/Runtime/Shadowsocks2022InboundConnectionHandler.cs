using System.Net;
using NodePanel.Core.Protocol;

namespace NodePanel.Core.Runtime;

public sealed class Shadowsocks2022InboundConnectionHandler
{
    private readonly IDispatcher _dispatcher;
    private readonly IRuntimeSniffer _runtimeSniffer;
    private readonly IRuntimeRateLimiterRegistry _rateLimiterRegistry;
    private readonly IRuntimeRelayService _relayService;
    private readonly IRuntimeSessionRegistry _sessionRegistry;
    private readonly IRuntimeTrafficRegistry _trafficRegistry;

    public Shadowsocks2022InboundConnectionHandler(
        IDispatcher dispatcher,
        IRuntimeSessionRegistry sessionRegistry,
        IRuntimeRelayService relayService,
        IRuntimeRateLimiterRegistry rateLimiterRegistry,
        IRuntimeTrafficRegistry trafficRegistry,
        IFakeDnsEngine? fakeDnsEngine = null)
        : this(
            dispatcher,
            sessionRegistry,
            relayService,
            rateLimiterRegistry,
            trafficRegistry,
            new DefaultRuntimeSniffer(fakeDnsEngine))
    {
    }

    internal Shadowsocks2022InboundConnectionHandler(
        IDispatcher dispatcher,
        IRuntimeSessionRegistry sessionRegistry,
        IRuntimeRelayService relayService,
        IRuntimeRateLimiterRegistry rateLimiterRegistry,
        IRuntimeTrafficRegistry trafficRegistry,
        IRuntimeSniffer runtimeSniffer)
    {
        _dispatcher = dispatcher;
        _sessionRegistry = sessionRegistry;
        _relayService = relayService;
        _rateLimiterRegistry = rateLimiterRegistry;
        _trafficRegistry = trafficRegistry;
        _runtimeSniffer = runtimeSniffer;
    }

    internal async Task HandleAsync(
        Stream stream,
        Shadowsocks2022InboundSessionOptions options,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(stream);
        ArgumentNullException.ThrowIfNull(options);

        using var handshakeCts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        handshakeCts.CancelAfter(TimeSpan.FromSeconds(options.HandshakeTimeoutSeconds));

        var initialPayload = await InboundServerRuntimeSupport.ReadInitialPayloadAsync(
            stream,
            handshakeCts.Token,
            options.RuntimeState?.GetMinimumTcpProbeBytes() ?? 64).ConfigureAwait(false);
        if (initialPayload.Length == 0)
        {
            throw new EndOfStreamException("Unexpected end of stream before reading the Shadowsocks 2022 request.");
        }

        if (options.RuntimeState is null ||
            !options.RuntimeState.TryMatchTcpUser(initialPayload, out var user, out var account) ||
            user is null ||
            account is null)
        {
            throw new UnauthorizedAccessException("Shadowsocks 2022 user authentication failed.");
        }
        var sessionOptions = options.WithUserLevel(user.Level);

        using var session = OpenTrackedSession(user, sessionOptions);

        var prefixedStream = new PrefixedReadStream(stream, initialPayload);
        var accepted = await Shadowsocks2022ProtocolCodec.AcceptServerTcpStreamAsync(
            prefixedStream,
            account,
            handshakeCts.Token).ConfigureAwait(false);

        await using var serverStream = accepted.Stream;
        var requestedDestination = accepted.Destination;

        var dispatchDestination = user.HasRelayDestination
            ? new DispatchDestination
            {
                Host = user.Address,
                Port = user.Port,
                Network = DispatchNetwork.Tcp
            }
            : new DispatchDestination
            {
                Host = requestedDestination.Host,
                Port = requestedDestination.Port,
                Network = DispatchNetwork.Tcp
            };

        var dispatchContext = DispatchContextTargeting.SetOriginalAndTarget(
            ShadowsocksDispatchContextFactory.Create(user, sessionOptions),
            dispatchDestination) with
        {
            OriginalDestinationHost = requestedDestination.Host,
            OriginalDestinationPort = requestedDestination.Port
        };

        var dispatchResult = await RuntimeTcpDispatchPipeline.DispatchAsync(
            _dispatcher,
            _runtimeSniffer,
            options.Sniffing,
            serverStream,
            dispatchContext,
            dispatchDestination,
            cancellationToken,
            handshakeCts.Token,
            allowDestinationOverride: !user.HasRelayDestination).ConfigureAwait(false);
        await using var remoteStream = dispatchResult.OutboundStream;
        handshakeCts.CancelAfter(Timeout.InfiniteTimeSpan);

        var userGate = _rateLimiterRegistry.GetUserGate(user);
        var globalGate = _rateLimiterRegistry.GlobalGate;

        await _relayService.RelayAsync(
            dispatchResult.InboundStream,
            remoteStream,
            user,
            userGate,
            globalGate,
            _trafficRegistry,
            sessionOptions,
            cancellationToken).ConfigureAwait(false);
    }

    private IDisposable OpenTrackedSession(
        Shadowsocks2022User user,
        Shadowsocks2022InboundSessionOptions options)
    {
        var remoteIp = ExtractRemoteIp(options.RemoteEndPoint);
        if (!_sessionRegistry.TryOpenSession(RuntimeUserKeys.Get(user), remoteIp, user.DeviceLimit, out var lease) || lease is null)
        {
            throw new UnauthorizedAccessException("Shadowsocks 2022 user device limit exceeded.");
        }

        return lease;
    }

    private static string? ExtractRemoteIp(EndPoint? remoteEndPoint)
    {
        if (remoteEndPoint is not IPEndPoint ipEndPoint)
        {
            return null;
        }

        var address = ipEndPoint.Address;
        if (address.IsIPv4MappedToIPv6)
        {
            address = address.MapToIPv4();
        }

        return address.ToString();
    }
}

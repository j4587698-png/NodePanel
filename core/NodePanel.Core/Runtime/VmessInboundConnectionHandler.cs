using System.Net;
using NodePanel.Core.Protocol;

namespace NodePanel.Core.Runtime;

public sealed class VmessInboundConnectionHandler
{
    private readonly IDispatcher _dispatcher;
    private readonly IRuntimeSniffer _runtimeSniffer;
    private readonly TrojanMuxInboundServer _trojanMuxInboundServer;
    private readonly VmessUdpRelay _vmessUdpRelay;
    private readonly IRuntimeRateLimiterRegistry _rateLimiterRegistry;
    private readonly IRuntimeRelayService _relayService;
    private readonly IRuntimeSessionRegistry _sessionRegistry;
    private readonly IRuntimeTrafficRegistry _trafficRegistry;
    private readonly VmessHandshakeReader _vmessHandshakeReader;

    public VmessInboundConnectionHandler(
        IDispatcher dispatcher,
        VmessHandshakeReader vmessHandshakeReader,
        TrojanMuxInboundServer trojanMuxInboundServer,
        VmessUdpRelay vmessUdpRelay,
        IRuntimeSessionRegistry sessionRegistry,
        IRuntimeRelayService relayService,
        IRuntimeRateLimiterRegistry rateLimiterRegistry,
        IRuntimeTrafficRegistry trafficRegistry,
        IFakeDnsEngine? fakeDnsEngine = null)
        : this(
            dispatcher,
            vmessHandshakeReader,
            trojanMuxInboundServer,
            vmessUdpRelay,
            sessionRegistry,
            relayService,
            rateLimiterRegistry,
            trafficRegistry,
            new DefaultRuntimeSniffer(fakeDnsEngine))
    {
    }

    internal VmessInboundConnectionHandler(
        IDispatcher dispatcher,
        VmessHandshakeReader vmessHandshakeReader,
        TrojanMuxInboundServer trojanMuxInboundServer,
        VmessUdpRelay vmessUdpRelay,
        IRuntimeSessionRegistry sessionRegistry,
        IRuntimeRelayService relayService,
        IRuntimeRateLimiterRegistry rateLimiterRegistry,
        IRuntimeTrafficRegistry trafficRegistry,
        IRuntimeSniffer runtimeSniffer)
    {
        _dispatcher = dispatcher;
        _vmessHandshakeReader = vmessHandshakeReader;
        _trojanMuxInboundServer = trojanMuxInboundServer;
        _vmessUdpRelay = vmessUdpRelay;
        _sessionRegistry = sessionRegistry;
        _relayService = relayService;
        _rateLimiterRegistry = rateLimiterRegistry;
        _trafficRegistry = trafficRegistry;
        _runtimeSniffer = runtimeSniffer;
    }

    internal async Task HandleAsync(Stream stream, VmessInboundSessionOptions options, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(options);

        using var handshakeCts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        handshakeCts.CancelAfter(TimeSpan.FromSeconds(options.HandshakeTimeoutSeconds));

        var request = await _vmessHandshakeReader.ReadAsync(
            stream,
            options.ResolveUsers(),
            options.DrainOnHandshakeFailure,
            options.RuntimeState,
            handshakeCts.Token).ConfigureAwait(false);
        var sessionOptions = options.WithUserLevel(request.User.Level);

        using var session = OpenTrackedSession(request.User, sessionOptions);
        var vmessStream = VmessHandshakeReader.CreateDataStream(stream, request);
        var responseStarted = false;

        try
        {
            if (request.Command == VmessCommand.Udp)
            {
                await VmessHandshakeReader.WriteResponseAsync(stream, request, handshakeCts.Token).ConfigureAwait(false);
                responseStarted = true;
                handshakeCts.CancelAfter(Timeout.InfiniteTimeSpan);
                await _vmessUdpRelay.RelayAsync(vmessStream, request, sessionOptions, cancellationToken).ConfigureAwait(false);
                return;
            }

            if (request.Command == VmessCommand.Mux)
            {
                await VmessHandshakeReader.WriteResponseAsync(stream, request, handshakeCts.Token).ConfigureAwait(false);
                responseStarted = true;
                handshakeCts.CancelAfter(Timeout.InfiniteTimeSpan);
                await _trojanMuxInboundServer.HandleAsync(
                    vmessStream,
                    request.User,
                    VmessDispatchContextFactory.Create(request.User, sessionOptions),
                    sessionOptions.ConnectionIdleSeconds,
                    cancellationToken).ConfigureAwait(false);
                return;
            }

            if (request.Command != VmessCommand.Connect)
            {
                throw new NotSupportedException($"Unsupported VMess command: {request.Command}.");
            }

            var dispatchDestination = new DispatchDestination
            {
                Host = request.TargetHost,
                Port = request.TargetPort,
                Network = DispatchNetwork.Tcp
            };
            var dispatchContext = DispatchContextTargeting.SetOriginalAndTarget(
                VmessDispatchContextFactory.Create(request.User, sessionOptions),
                dispatchDestination);

            var dispatchResult = await RuntimeTcpDispatchPipeline.DispatchAsync(
                _dispatcher,
                _runtimeSniffer,
                options.Sniffing,
                vmessStream,
                dispatchContext,
                dispatchDestination,
                cancellationToken,
                handshakeCts.Token).ConfigureAwait(false);
            await using var remoteStream = dispatchResult.OutboundStream;
            await VmessHandshakeReader.WriteResponseAsync(stream, request, handshakeCts.Token).ConfigureAwait(false);
            responseStarted = true;
            handshakeCts.CancelAfter(Timeout.InfiniteTimeSpan);

            var userGate = _rateLimiterRegistry.GetUserGate(request.User);
            var globalGate = _rateLimiterRegistry.GlobalGate;

            await _relayService.RelayAsync(
                dispatchResult.InboundStream,
                remoteStream,
                request.User,
                userGate,
                globalGate,
                _trafficRegistry,
                sessionOptions,
                cancellationToken).ConfigureAwait(false);
        }
        finally
        {
            if (responseStarted)
            {
                await vmessStream.CompleteResponseAsync(cancellationToken).ConfigureAwait(false);
            }
        }
    }

    private IDisposable OpenTrackedSession(VmessUser user, VmessInboundSessionOptions options)
    {
        var remoteIp = ExtractRemoteIp(options.RemoteEndPoint);
        if (!_sessionRegistry.TryOpenSession(RuntimeUserKeys.Get(user), remoteIp, user.DeviceLimit, out var lease) || lease is null)
        {
            throw new UnauthorizedAccessException("VMess user device limit exceeded.");
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

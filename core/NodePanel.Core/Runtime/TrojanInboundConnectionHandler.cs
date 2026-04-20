using System.Net;
using NodePanel.Core.Protocol;

namespace NodePanel.Core.Runtime;

public sealed class TrojanInboundConnectionHandler
{
    private const int InitialProbeBytes = 4096;

    private readonly IDispatcher _dispatcher;
    private readonly IRuntimeSniffer _runtimeSniffer;
    private readonly TrojanFallbackRelayService _trojanFallbackRelayService;
    private readonly IRuntimeRateLimiterRegistry _rateLimiterRegistry;
    private readonly IRuntimeRelayService _relayService;
    private readonly TrojanMuxInboundServer _trojanMuxInboundServer;
    private readonly IRuntimeSessionRegistry _sessionRegistry;
    private readonly IRuntimeTrafficRegistry _trafficRegistry;
    private readonly TrojanHandshakeReader _trojanHandshakeReader;
    private readonly TrojanUdpAssociateRelay _trojanUdpAssociateRelay;

    public TrojanInboundConnectionHandler(
        IDispatcher dispatcher,
        TrojanHandshakeReader trojanHandshakeReader,
        TrojanUdpAssociateRelay trojanUdpAssociateRelay,
        TrojanMuxInboundServer trojanMuxInboundServer,
        TrojanFallbackRelayService trojanFallbackRelayService,
        IRuntimeSessionRegistry sessionRegistry,
        IRuntimeRelayService relayService,
        IRuntimeRateLimiterRegistry rateLimiterRegistry,
        IRuntimeTrafficRegistry trafficRegistry,
        IFakeDnsEngine? fakeDnsEngine = null)
        : this(
            dispatcher,
            trojanHandshakeReader,
            trojanUdpAssociateRelay,
            trojanMuxInboundServer,
            trojanFallbackRelayService,
            sessionRegistry,
            relayService,
            rateLimiterRegistry,
            trafficRegistry,
            new DefaultRuntimeSniffer(fakeDnsEngine))
    {
    }

    internal TrojanInboundConnectionHandler(
        IDispatcher dispatcher,
        TrojanHandshakeReader trojanHandshakeReader,
        TrojanUdpAssociateRelay trojanUdpAssociateRelay,
        TrojanMuxInboundServer trojanMuxInboundServer,
        TrojanFallbackRelayService trojanFallbackRelayService,
        IRuntimeSessionRegistry sessionRegistry,
        IRuntimeRelayService relayService,
        IRuntimeRateLimiterRegistry rateLimiterRegistry,
        IRuntimeTrafficRegistry trafficRegistry,
        IRuntimeSniffer runtimeSniffer)
    {
        _dispatcher = dispatcher;
        _trojanHandshakeReader = trojanHandshakeReader;
        _trojanUdpAssociateRelay = trojanUdpAssociateRelay;
        _trojanMuxInboundServer = trojanMuxInboundServer;
        _trojanFallbackRelayService = trojanFallbackRelayService;
        _sessionRegistry = sessionRegistry;
        _relayService = relayService;
        _rateLimiterRegistry = rateLimiterRegistry;
        _trafficRegistry = trafficRegistry;
        _runtimeSniffer = runtimeSniffer;
    }

    public async Task HandleAsync(Stream stream, ITrojanInboundConnectionOptions options, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(options);

        using var handshakeCts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        handshakeCts.CancelAfter(TimeSpan.FromSeconds(options.HandshakeTimeoutSeconds));

        var initialPayload = await ReadInitialPayloadAsync(stream, handshakeCts.Token).ConfigureAwait(false);
        if (initialPayload.Length == 0)
        {
            throw new EndOfStreamException("Unexpected end of stream before reading the trojan request.");
        }

        if (!TryAuthenticate(initialPayload, options, out var user))
        {
            if (await _trojanFallbackRelayService.TryHandleAsync(stream, initialPayload, options, cancellationToken).ConfigureAwait(false))
            {
                return;
            }

            throw new UnauthorizedAccessException("Trojan user authentication failed.");
        }

        ArgumentNullException.ThrowIfNull(user);
        var sessionOptions = options is TrojanInboundSessionOptions trojanOptions
            ? trojanOptions.WithUserLevel(user.Level)
            : options;

        var requestStream = new PrefixedReadStream(stream, initialPayload);
        TrojanRequest request;
        try
        {
            request = await _trojanHandshakeReader.ReadAsync(requestStream, handshakeCts.Token).ConfigureAwait(false);
        }
        finally
        {
            handshakeCts.CancelAfter(Timeout.InfiniteTimeSpan);
        }

        using var session = OpenTrackedSession(user, sessionOptions);

        if (request.Command == TrojanCommand.Associate)
        {
            await _trojanUdpAssociateRelay.RelayAsync(requestStream, user, sessionOptions, cancellationToken).ConfigureAwait(false);
            return;
        }

        if (request.Command != TrojanCommand.Connect)
        {
            throw new NotSupportedException($"Unsupported trojan command: {request.Command}.");
        }

        var dispatchDestination = new DispatchDestination
        {
            Host = request.TargetHost,
            Port = request.TargetPort,
            Network = DispatchNetwork.Tcp
        };
        var dispatchContext = DispatchContextTargeting.SetOriginalAndTarget(
            TrojanDispatchContextFactory.Create(user, sessionOptions),
            dispatchDestination);

        if (TrojanMuxProtocol.IsMuxDestination(request.TargetHost))
        {
            await _trojanMuxInboundServer.HandleAsync(
                requestStream,
                user,
                sessionOptions,
                cancellationToken).ConfigureAwait(false);
            return;
        }

        var dispatchResult = await RuntimeTcpDispatchPipeline.DispatchAsync(
            _dispatcher,
            _runtimeSniffer,
            options.Sniffing,
            requestStream,
            dispatchContext,
            dispatchDestination,
            cancellationToken,
            cancellationToken).ConfigureAwait(false);
        await using var remoteStream = dispatchResult.OutboundStream;
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

    private static bool TryAuthenticate(byte[] initialPayload, ITrojanInboundConnectionOptions options, out TrojanUser? user)
    {
        user = null;
        if (initialPayload.Length < TrojanProtocolCodec.UserHashLength + 2 ||
            initialPayload[TrojanProtocolCodec.UserHashLength] != '\r' ||
            initialPayload[TrojanProtocolCodec.UserHashLength + 1] != '\n')
        {
            return false;
        }

        var userHash = System.Text.Encoding.ASCII.GetString(initialPayload, 0, TrojanProtocolCodec.UserHashLength);
        return options.TryAuthenticate(userHash, out user) && user is not null;
    }

    private IDisposable OpenTrackedSession(TrojanUser user, ITrojanInboundConnectionOptions options)
    {
        var remoteIp = ExtractRemoteIp(options.RemoteEndPoint);
        if (!_sessionRegistry.TryOpenSession(RuntimeUserKeys.Get(user), remoteIp, user.DeviceLimit, out var lease) || lease is null)
        {
            throw new UnauthorizedAccessException("Trojan user device limit exceeded.");
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

    private static async Task<byte[]> ReadInitialPayloadAsync(Stream stream, CancellationToken cancellationToken)
    {
        var buffer = new byte[InitialProbeBytes];
        var read = 0;
        var minimum = Math.Min(TrojanProtocolCodec.UserHashLength + 2, buffer.Length);

        while (read < minimum)
        {
            var current = await stream.ReadAsync(buffer.AsMemory(read, buffer.Length - read), cancellationToken).ConfigureAwait(false);
            if (current == 0)
            {
                break;
            }

            read += current;
        }

        return read == buffer.Length ? buffer : buffer.AsSpan(0, read).ToArray();
    }
}

using System.Net;
using NodePanel.Core.Protocol;

namespace NodePanel.Core.Runtime;

public sealed class ShadowsocksInboundConnectionHandler
{
    private const int InitialProbeBytes = 4096;
    private const int UserProbeMinimumBytes = 50;

    private readonly IDispatcher _dispatcher;
    private readonly IRuntimeSniffer _runtimeSniffer;
    private readonly IRuntimeRateLimiterRegistry _rateLimiterRegistry;
    private readonly IRuntimeRelayService _relayService;
    private readonly IRuntimeSessionRegistry _sessionRegistry;
    private readonly IRuntimeTrafficRegistry _trafficRegistry;

    public ShadowsocksInboundConnectionHandler(
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

    internal ShadowsocksInboundConnectionHandler(
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
        ShadowsocksInboundSessionOptions options,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(stream);
        ArgumentNullException.ThrowIfNull(options);

        using var handshakeCts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        handshakeCts.CancelAfter(TimeSpan.FromSeconds(options.HandshakeTimeoutSeconds));

        var initialPayload = await ReadInitialPayloadAsync(stream, handshakeCts.Token).ConfigureAwait(false);
        if (initialPayload.Length == 0)
        {
            throw new EndOfStreamException("Unexpected end of stream before reading the Shadowsocks request.");
        }

        if (options.RuntimeState is null ||
            !options.RuntimeState.TryMatchTcpUser(initialPayload, out var user, out var account) ||
            user is null ||
            account is null)
        {
            throw new UnauthorizedAccessException("Shadowsocks user authentication failed.");
        }
        var sessionOptions = options.WithUserLevel(user.Level);

        using var session = OpenTrackedSession(user, sessionOptions);

        var prefixedStream = new PrefixedReadStream(stream, initialPayload);
        var accepted = await ShadowsocksProtocolCodec.AcceptServerTcpStreamAsync(
            prefixedStream,
            account,
            handshakeCts.Token).ConfigureAwait(false);

        await using var serverStream = accepted.Stream;

        var dispatchDestination = new DispatchDestination
        {
            Host = accepted.Destination.Host,
            Port = accepted.Destination.Port,
            Network = DispatchNetwork.Tcp
        };

        var dispatchContext = DispatchContextTargeting.SetOriginalAndTarget(
            ShadowsocksDispatchContextFactory.Create(user, sessionOptions),
            dispatchDestination);

        var dispatchResult = await RuntimeTcpDispatchPipeline.DispatchAsync(
            _dispatcher,
            _runtimeSniffer,
            options.Sniffing,
            serverStream,
            dispatchContext,
            dispatchDestination,
            cancellationToken,
            handshakeCts.Token).ConfigureAwait(false);
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

    private IDisposable OpenTrackedSession(ShadowsocksUser user, ShadowsocksInboundSessionOptions options)
    {
        var remoteIp = ExtractRemoteIp(options.RemoteEndPoint);
        if (!_sessionRegistry.TryOpenSession(RuntimeUserKeys.Get(user), remoteIp, user.DeviceLimit, out var lease) || lease is null)
        {
            throw new UnauthorizedAccessException("Shadowsocks user device limit exceeded.");
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

        while (read < UserProbeMinimumBytes && read < buffer.Length)
        {
            var current = await stream.ReadAsync(
                buffer.AsMemory(read, buffer.Length - read),
                cancellationToken).ConfigureAwait(false);
            if (current == 0)
            {
                break;
            }

            read += current;
        }

        return read == buffer.Length ? buffer : buffer.AsSpan(0, read).ToArray();
    }
}

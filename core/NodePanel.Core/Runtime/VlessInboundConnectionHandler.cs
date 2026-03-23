using System.Net;
using NodePanel.Core.Protocol;

namespace NodePanel.Core.Runtime;

public sealed class VlessInboundConnectionHandler
{
    private const int InitialProbeBytes = 4096;
    private static readonly TimeSpan SniffProbeTimeout = TimeSpan.FromMilliseconds(200);

    private readonly IDispatcher _dispatcher;
    private readonly TrojanMuxInboundServer _trojanMuxInboundServer;
    private readonly VlessUdpRelay _vlessUdpRelay;
    private readonly RateLimiterRegistry _rateLimiterRegistry;
    private readonly RelayService _relayService;
    private readonly SessionRegistry _sessionRegistry;
    private readonly TrafficRegistry _trafficRegistry;
    private readonly VlessHandshakeReader _vlessHandshakeReader;

    public VlessInboundConnectionHandler(
        IDispatcher dispatcher,
        VlessHandshakeReader vlessHandshakeReader,
        TrojanMuxInboundServer trojanMuxInboundServer,
        VlessUdpRelay vlessUdpRelay,
        SessionRegistry sessionRegistry,
        RelayService relayService,
        RateLimiterRegistry rateLimiterRegistry,
        TrafficRegistry trafficRegistry)
    {
        _dispatcher = dispatcher;
        _vlessHandshakeReader = vlessHandshakeReader;
        _trojanMuxInboundServer = trojanMuxInboundServer;
        _vlessUdpRelay = vlessUdpRelay;
        _sessionRegistry = sessionRegistry;
        _relayService = relayService;
        _rateLimiterRegistry = rateLimiterRegistry;
        _trafficRegistry = trafficRegistry;
    }

    internal async Task HandleAsync(Stream stream, VlessInboundSessionOptions options, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(options);

        using var handshakeCts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        handshakeCts.CancelAfter(TimeSpan.FromSeconds(options.HandshakeTimeoutSeconds));

        var request = await _vlessHandshakeReader.ReadAsync(stream, handshakeCts.Token).ConfigureAwait(false);
        if (!options.TryResolveUser(request.UserUuid, out var user) || user is null)
        {
            throw new UnauthorizedAccessException("VLESS user authentication failed.");
        }

        using var session = OpenTrackedSession(user, options);

        if (request.Command == VlessCommand.Udp)
        {
            await _vlessUdpRelay.RelayAsync(stream, request, user, options, cancellationToken).ConfigureAwait(false);
            return;
        }

        if (request.Command == VlessCommand.Mux)
        {
            await VlessHandshakeReader.WriteResponseAsync(stream, request.Version, handshakeCts.Token).ConfigureAwait(false);
            handshakeCts.CancelAfter(Timeout.InfiniteTimeSpan);
            await _trojanMuxInboundServer.HandleAsync(
                stream,
                user,
                VlessDispatchContextFactory.Create(user, options),
                options.ConnectionIdleSeconds,
                cancellationToken).ConfigureAwait(false);
            return;
        }

        if (request.Command != VlessCommand.Connect)
        {
            throw new NotSupportedException($"Unsupported VLESS command: {request.Command}.");
        }

        var relayStream = stream;
        var dispatchContext = VlessDispatchContextFactory.Create(user, options);
        var dispatchDestination = new DispatchDestination
        {
            Host = request.TargetHost,
            Port = request.TargetPort,
            Network = DispatchNetwork.Tcp
        };
        dispatchContext = dispatchContext with
        {
            OriginalDestinationHost = request.TargetHost,
            OriginalDestinationPort = request.TargetPort
        };

        if (options.Sniffing.Enabled && !options.Sniffing.MetadataOnly)
        {
            var sniffPayload = await ReadSniffPayloadAsync(stream, cancellationToken).ConfigureAwait(false);
            if (sniffPayload.Length > 0)
            {
                relayStream = new PrefixedReadStream(stream, sniffPayload);
                var sniffing = TrojanSniffingEvaluator.Evaluate(
                    options.Sniffing,
                    sniffPayload,
                    DispatchNetwork.Tcp,
                    dispatchDestination);

                dispatchContext = dispatchContext with
                {
                    DetectedProtocol = sniffing.Protocol,
                    DetectedDomain = sniffing.Domain
                };

                if (sniffing.OverrideDestination is not null)
                {
                    dispatchDestination = sniffing.OverrideDestination;
                }
            }
        }

        await using var remoteStream = await _dispatcher.DispatchTcpAsync(
            dispatchContext,
            dispatchDestination,
            handshakeCts.Token).ConfigureAwait(false);
        await VlessHandshakeReader.WriteResponseAsync(stream, request.Version, handshakeCts.Token).ConfigureAwait(false);
        handshakeCts.CancelAfter(Timeout.InfiniteTimeSpan);

        var userGate = _rateLimiterRegistry.GetUserGate(user);
        var globalGate = _rateLimiterRegistry.GlobalGate;

        await _relayService.RelayAsync(
            relayStream,
            remoteStream,
            user,
            userGate,
            globalGate,
            _trafficRegistry,
            options,
            cancellationToken).ConfigureAwait(false);
    }

    private IDisposable OpenTrackedSession(VlessUser user, VlessInboundSessionOptions options)
    {
        var remoteIp = ExtractRemoteIp(options.RemoteEndPoint);
        if (!_sessionRegistry.TryOpenSession(user.UserId, remoteIp, user.DeviceLimit, out var lease) || lease is null)
        {
            throw new UnauthorizedAccessException("VLESS user device limit exceeded.");
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

    private static async Task<byte[]> ReadSniffPayloadAsync(Stream stream, CancellationToken cancellationToken)
    {
        var buffer = new byte[InitialProbeBytes];
        using var sniffCts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        sniffCts.CancelAfter(SniffProbeTimeout);

        try
        {
            var read = await stream.ReadAsync(buffer.AsMemory(0, buffer.Length), sniffCts.Token).ConfigureAwait(false);
            return read == 0 ? Array.Empty<byte>() : buffer.AsSpan(0, read).ToArray();
        }
        catch (OperationCanceledException) when (!cancellationToken.IsCancellationRequested)
        {
            return Array.Empty<byte>();
        }
    }
}

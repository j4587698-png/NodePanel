using System.Net;
using NodePanel.Core.Protocol;

namespace NodePanel.Core.Runtime;

public sealed class TrojanInboundConnectionHandler
{
    private const int InitialProbeBytes = 4096;
    private static readonly TimeSpan SniffProbeTimeout = TimeSpan.FromMilliseconds(200);

    private readonly IDispatcher _dispatcher;
    private readonly TrojanFallbackRelayService _trojanFallbackRelayService;
    private readonly RateLimiterRegistry _rateLimiterRegistry;
    private readonly RelayService _relayService;
    private readonly TrojanMuxInboundServer _trojanMuxInboundServer;
    private readonly SessionRegistry _sessionRegistry;
    private readonly TrafficRegistry _trafficRegistry;
    private readonly TrojanHandshakeReader _trojanHandshakeReader;
    private readonly TrojanUdpAssociateRelay _trojanUdpAssociateRelay;

    public TrojanInboundConnectionHandler(
        IDispatcher dispatcher,
        TrojanHandshakeReader trojanHandshakeReader,
        TrojanUdpAssociateRelay trojanUdpAssociateRelay,
        TrojanMuxInboundServer trojanMuxInboundServer,
        TrojanFallbackRelayService trojanFallbackRelayService,
        SessionRegistry sessionRegistry,
        RelayService relayService,
        RateLimiterRegistry rateLimiterRegistry,
        TrafficRegistry trafficRegistry)
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

        using var session = OpenTrackedSession(user, options);

        if (request.Command == TrojanCommand.Associate)
        {
            await _trojanUdpAssociateRelay.RelayAsync(requestStream, user, options, cancellationToken).ConfigureAwait(false);
            return;
        }

        if (request.Command != TrojanCommand.Connect)
        {
            throw new NotSupportedException($"Unsupported trojan command: {request.Command}.");
        }

        var relayStream = (Stream)requestStream;
        var dispatchContext = TrojanDispatchContextFactory.Create(user, options);
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

        if (TrojanMuxProtocol.IsMuxDestination(request.TargetHost))
        {
            await _trojanMuxInboundServer.HandleAsync(
                requestStream,
                user,
                options,
                cancellationToken).ConfigureAwait(false);
            return;
        }

        if (options.Sniffing.Enabled && !options.Sniffing.MetadataOnly)
        {
            var sniffPayload = await ReadSniffPayloadAsync(requestStream, cancellationToken).ConfigureAwait(false);
            if (sniffPayload.Length > 0)
            {
                relayStream = new PrefixedReadStream(requestStream, sniffPayload);
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
            cancellationToken).ConfigureAwait(false);
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
        if (!_sessionRegistry.TryOpenSession(user.UserId, remoteIp, user.DeviceLimit, out var lease) || lease is null)
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

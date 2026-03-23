using System.Net;
using NodePanel.Core.Protocol;

namespace NodePanel.Core.Runtime;

public sealed class VmessInboundConnectionHandler
{
    private const int InitialProbeBytes = 4096;
    private static readonly TimeSpan SniffProbeTimeout = TimeSpan.FromMilliseconds(200);

    private readonly IDispatcher _dispatcher;
    private readonly TrojanMuxInboundServer _trojanMuxInboundServer;
    private readonly VmessUdpRelay _vmessUdpRelay;
    private readonly RateLimiterRegistry _rateLimiterRegistry;
    private readonly RelayService _relayService;
    private readonly SessionRegistry _sessionRegistry;
    private readonly TrafficRegistry _trafficRegistry;
    private readonly VmessHandshakeReader _vmessHandshakeReader;

    public VmessInboundConnectionHandler(
        IDispatcher dispatcher,
        VmessHandshakeReader vmessHandshakeReader,
        TrojanMuxInboundServer trojanMuxInboundServer,
        VmessUdpRelay vmessUdpRelay,
        SessionRegistry sessionRegistry,
        RelayService relayService,
        RateLimiterRegistry rateLimiterRegistry,
        TrafficRegistry trafficRegistry)
    {
        _dispatcher = dispatcher;
        _vmessHandshakeReader = vmessHandshakeReader;
        _trojanMuxInboundServer = trojanMuxInboundServer;
        _vmessUdpRelay = vmessUdpRelay;
        _sessionRegistry = sessionRegistry;
        _relayService = relayService;
        _rateLimiterRegistry = rateLimiterRegistry;
        _trafficRegistry = trafficRegistry;
    }

    internal async Task HandleAsync(Stream stream, VmessInboundSessionOptions options, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(options);

        using var handshakeCts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        handshakeCts.CancelAfter(TimeSpan.FromSeconds(options.HandshakeTimeoutSeconds));

        var request = await _vmessHandshakeReader.ReadAsync(
            stream,
            options.Users,
            options.DrainOnHandshakeFailure,
            options.RuntimeState,
            handshakeCts.Token).ConfigureAwait(false);

        using var session = OpenTrackedSession(request.User, options);
        var vmessStream = VmessHandshakeReader.CreateDataStream(stream, request);
        var responseStarted = false;

        try
        {
            if (request.Command == VmessCommand.Udp)
            {
                await VmessHandshakeReader.WriteResponseAsync(stream, request, handshakeCts.Token).ConfigureAwait(false);
                responseStarted = true;
                handshakeCts.CancelAfter(Timeout.InfiniteTimeSpan);
                await _vmessUdpRelay.RelayAsync(vmessStream, request, options, cancellationToken).ConfigureAwait(false);
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
                    VmessDispatchContextFactory.Create(request.User, options),
                    options.ConnectionIdleSeconds,
                    cancellationToken).ConfigureAwait(false);
                return;
            }

            if (request.Command != VmessCommand.Connect)
            {
                throw new NotSupportedException($"Unsupported VMess command: {request.Command}.");
            }

            Stream relayStream = vmessStream;

            var dispatchContext = VmessDispatchContextFactory.Create(request.User, options);
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
                var sniffPayload = await ReadSniffPayloadAsync(vmessStream, cancellationToken).ConfigureAwait(false);
                if (sniffPayload.Length > 0)
                {
                    relayStream = new PrefixedReadStream(vmessStream, sniffPayload);
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
            await VmessHandshakeReader.WriteResponseAsync(stream, request, handshakeCts.Token).ConfigureAwait(false);
            responseStarted = true;
            handshakeCts.CancelAfter(Timeout.InfiniteTimeSpan);

            var userGate = _rateLimiterRegistry.GetUserGate(request.User);
            var globalGate = _rateLimiterRegistry.GlobalGate;

            await _relayService.RelayAsync(
                relayStream,
                remoteStream,
                request.User,
                userGate,
                globalGate,
                _trafficRegistry,
                options,
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
        if (!_sessionRegistry.TryOpenSession(user.UserId, remoteIp, user.DeviceLimit, out var lease) || lease is null)
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

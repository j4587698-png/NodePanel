using System.Net;
using System.Security.Authentication;
using NodePanel.Core.Protocol;

namespace NodePanel.Core.Runtime;

public sealed class VlessInboundConnectionHandler
{
    private const int InitialProbeBytes = 4096;
    private const int MuxProbeBytes = 7;
    private static readonly TimeSpan MuxProbeTimeout = TimeSpan.FromMilliseconds(200);

    private readonly IDispatcher _dispatcher;
    private readonly RuntimeFallbackRelayService _fallbackRelayService;
    private readonly DefaultOutboundManager? _outboundManager;
    private readonly IRuntimeSniffer _runtimeSniffer;
    private readonly TrojanMuxInboundServer _trojanMuxInboundServer;
    private readonly VlessUdpRelay _vlessUdpRelay;
    private readonly IRuntimeRateLimiterRegistry _rateLimiterRegistry;
    private readonly IRuntimeRelayService _relayService;
    private readonly IRuntimeSessionRegistry _sessionRegistry;
    private readonly IRuntimeTrafficRegistry _trafficRegistry;
    private readonly VlessHandshakeReader _vlessHandshakeReader;
    private readonly VlessTransportEncryption _transportEncryption = new();

    public VlessInboundConnectionHandler(
        IDispatcher dispatcher,
        VlessHandshakeReader vlessHandshakeReader,
        TrojanMuxInboundServer trojanMuxInboundServer,
        VlessUdpRelay vlessUdpRelay,
        IRuntimeSessionRegistry sessionRegistry,
        IRuntimeRelayService relayService,
        IRuntimeRateLimiterRegistry rateLimiterRegistry,
        IRuntimeTrafficRegistry trafficRegistry,
        DefaultOutboundManager? outboundManager = null,
        IFakeDnsEngine? fakeDnsEngine = null)
        : this(
            dispatcher,
            vlessHandshakeReader,
            trojanMuxInboundServer,
            vlessUdpRelay,
            sessionRegistry,
            relayService,
            rateLimiterRegistry,
            trafficRegistry,
            outboundManager,
            new DefaultRuntimeSniffer(fakeDnsEngine))
    {
    }

    internal VlessInboundConnectionHandler(
        IDispatcher dispatcher,
        VlessHandshakeReader vlessHandshakeReader,
        TrojanMuxInboundServer trojanMuxInboundServer,
        VlessUdpRelay vlessUdpRelay,
        IRuntimeSessionRegistry sessionRegistry,
        IRuntimeRelayService relayService,
        IRuntimeRateLimiterRegistry rateLimiterRegistry,
        IRuntimeTrafficRegistry trafficRegistry,
        DefaultOutboundManager? outboundManager,
        IRuntimeSniffer runtimeSniffer)
    {
        _dispatcher = dispatcher;
        _vlessHandshakeReader = vlessHandshakeReader;
        _trojanMuxInboundServer = trojanMuxInboundServer;
        _vlessUdpRelay = vlessUdpRelay;
        _sessionRegistry = sessionRegistry;
        _relayService = relayService;
        _fallbackRelayService = new RuntimeFallbackRelayService(relayService);
        _outboundManager = outboundManager;
        _rateLimiterRegistry = rateLimiterRegistry;
        _trafficRegistry = trafficRegistry;
        _runtimeSniffer = runtimeSniffer;
    }

    internal async Task HandleAsync(Stream stream, VlessInboundSessionOptions options, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(options);

        using var handshakeCts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        handshakeCts.CancelAfter(TimeSpan.FromSeconds(options.HandshakeTimeoutSeconds));

        if (VlessTransportEncryption.IsEnabled(options.Decryption))
        {
            stream = await _transportEncryption.AcceptAsync(stream, options, handshakeCts.Token).ConfigureAwait(false);
        }

        var initialPayload = await ReadInitialPayloadAsync(stream, handshakeCts.Token).ConfigureAwait(false);
        if (initialPayload.Length == 0)
        {
            throw new EndOfStreamException("Unexpected end of stream before reading the VLESS request.");
        }

        if (!TryAuthenticate(initialPayload, options, out var user))
        {
            if (await _fallbackRelayService.TryHandleAsync(stream, initialPayload, options, cancellationToken).ConfigureAwait(false))
            {
                return;
            }

            throw new UnauthorizedAccessException("VLESS user authentication failed.");
        }

        ArgumentNullException.ThrowIfNull(user);
        var requestStream = new HandshakeCaptureStream(new PrefixedReadStream(stream, initialPayload));
        VlessRequest request;
        try
        {
            request = await _vlessHandshakeReader.ReadAsync(requestStream, handshakeCts.Token).ConfigureAwait(false);
        }
        catch (OperationCanceledException)
        {
            throw;
        }
        catch
        {
            if (await _fallbackRelayService.TryHandleAsync(
                    requestStream,
                    requestStream.GetCapturedBytes(),
                    options,
                    cancellationToken).ConfigureAwait(false))
            {
                return;
            }

            throw;
        }

        requestStream.StopCapture();
        var requestFlow = ResolveRequestFlow(request.Addons);
        var userFlow = ResolveUserFlow(user);
        var muxProbe = await ProbeMuxFlowAsync(
            requestStream,
            request,
            userFlow,
            handshakeCts.Token).ConfigureAwait(false);

        EnsureRequestFlowAllowed(request, user, options, requestFlow, userFlow, muxProbe.AllowEmptyVisionMuxFlow);
        EnsureReverseCommandAllowed(user, request);
        var sessionOptions = options.WithUserLevel(user.Level);

        var applicationStream = WrapApplicationStream(muxProbe.Stream, user, requestFlow);

        using var session = OpenTrackedSession(user, sessionOptions);

        if (request.Command == VlessCommand.Udp)
        {
            await _vlessUdpRelay.RelayAsync(applicationStream, request, user, sessionOptions, cancellationToken).ConfigureAwait(false);
            return;
        }

        if (request.Command == VlessCommand.Mux)
        {
            await VlessHandshakeReader.WriteResponseAsync(stream, request.Version, handshakeCts.Token).ConfigureAwait(false);
            handshakeCts.CancelAfter(Timeout.InfiniteTimeSpan);
            await _trojanMuxInboundServer.HandleAsync(
                applicationStream,
                user,
                VlessDispatchContextFactory.Create(user, sessionOptions, request.VlessRoutePort),
                sessionOptions.ConnectionIdleSeconds,
                cancellationToken,
                ResolveMuxAllowedTargetNetwork(userFlow)).ConfigureAwait(false);
            return;
        }

        if (request.Command == VlessCommand.Rvs)
        {
            var reverseHandler = GetOrCreateReverseHandler(user.ReverseTag);
            await using var reverseAttachment = reverseHandler.Attach(applicationStream);
            await VlessHandshakeReader.WriteResponseAsync(stream, request.Version, handshakeCts.Token).ConfigureAwait(false);
            handshakeCts.CancelAfter(Timeout.InfiniteTimeSpan);
            await reverseAttachment.WaitClosedAsync(cancellationToken).ConfigureAwait(false);
            return;
        }

        if (request.Command != VlessCommand.Connect)
        {
            throw new NotSupportedException($"Unsupported VLESS command: {request.Command}.");
        }

        var dispatchDestination = new DispatchDestination
        {
            Host = request.TargetHost,
            Port = request.TargetPort,
            Network = DispatchNetwork.Tcp
        };
        var dispatchContext = DispatchContextTargeting.SetOriginalAndTarget(
            VlessDispatchContextFactory.Create(user, sessionOptions, request.VlessRoutePort),
            dispatchDestination);

        var dispatchResult = await RuntimeTcpDispatchPipeline.DispatchAsync(
            _dispatcher,
            _runtimeSniffer,
            options.Sniffing,
            applicationStream,
            dispatchContext,
            dispatchDestination,
            cancellationToken,
            handshakeCts.Token).ConfigureAwait(false);
        await using var remoteStream = dispatchResult.OutboundStream;
        await VlessHandshakeReader.WriteResponseAsync(stream, request.Version, handshakeCts.Token).ConfigureAwait(false);
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

    private IDisposable OpenTrackedSession(VlessUser user, VlessInboundSessionOptions options)
    {
        var remoteIp = ExtractRemoteIp(options.RemoteEndPoint);
        if (!_sessionRegistry.TryOpenSession(RuntimeUserKeys.Get(user), remoteIp, user.DeviceLimit, out var lease) || lease is null)
        {
            throw new UnauthorizedAccessException("VLESS user device limit exceeded.");
        }

        return lease;
    }

    private static bool TryAuthenticate(byte[] initialPayload, VlessInboundSessionOptions options, out VlessUser? user)
    {
        user = null;
        if (initialPayload.Length < 17)
        {
            return false;
        }

        var userUuid = ProtocolUuid.Format(initialPayload.AsSpan(1, 16));
        return options.TryResolveUser(userUuid, out user) && user is not null;
    }

    private static string ResolveRequestFlow(VlessHeaderAddons addons)
    {
        ArgumentNullException.ThrowIfNull(addons);

        if (string.IsNullOrWhiteSpace(addons.Flow))
        {
            return string.Empty;
        }

        var normalizedFlow = addons.Flow.Trim();
        if (string.Equals(normalizedFlow, VlessFlowTypes.Vision, StringComparison.OrdinalIgnoreCase))
        {
            return VlessFlowTypes.Vision;
        }

        throw new NotSupportedException($"Unsupported VLESS request flow: {normalizedFlow}.");
    }

    private static string ResolveUserFlow(VlessUser user)
        => VlessFlowTypes.IsVision(user.Flow)
            ? VlessFlowTypes.Vision
            : string.Empty;

    private static void EnsureRequestFlowAllowed(
        VlessRequest request,
        VlessUser user,
        VlessInboundSessionOptions options,
        string requestFlow,
        string userFlow,
        bool allowEmptyVisionMuxFlow)
    {
        if (!string.Equals(requestFlow, VlessFlowTypes.Vision, StringComparison.Ordinal))
        {
            if (string.Equals(userFlow, VlessFlowTypes.Vision, StringComparison.Ordinal) &&
                (request.Command == VlessCommand.Connect ||
                 (request.Command == VlessCommand.Mux && !allowEmptyVisionMuxFlow)))
            {
                throw new InvalidOperationException(
                    $"VLESS user '{user.UserId}' requires request flow '{VlessFlowTypes.Vision}' for TCP or mux traffic.");
            }

            return;
        }

        if (!string.Equals(userFlow, VlessFlowTypes.Vision, StringComparison.Ordinal))
        {
            throw new InvalidOperationException(
                $"VLESS user '{user.UserId}' is not allowed to use request flow '{requestFlow}'.");
        }

        if (request.Command == VlessCommand.Udp)
        {
            throw new NotSupportedException($"VLESS flow '{requestFlow}' does not support UDP.");
        }

        if (!string.Equals(
                RuntimeInternetTransportProtocols.Normalize(options.TransportProtocol),
                RuntimeInternetTransportProtocols.Tcp,
                StringComparison.Ordinal) ||
            !RuntimeInternetSecurityTypes.UsesTlsLikeSemantics(options.SecurityType))
        {
            throw new NotSupportedException($"VLESS flow '{requestFlow}' currently requires direct TLS-like transport.");
        }

        if (options.OuterTlsProtocol != SslProtocols.Tls13)
        {
            throw new InvalidOperationException($"VLESS flow '{requestFlow}' requires an outer TLS 1.3 transport.");
        }
    }

    private static void EnsureReverseCommandAllowed(VlessUser user, VlessRequest request)
    {
        if (string.IsNullOrWhiteSpace(user.ReverseTag))
        {
            if (request.Command == VlessCommand.Rvs)
            {
                throw new InvalidOperationException($"VLESS user '{user.UserId}' is not allowed to create reverse proxy sessions.");
            }

            return;
        }

        if (request.Command != VlessCommand.Rvs)
        {
            throw new InvalidOperationException($"VLESS user '{user.UserId}' is only allowed to use reverse proxy sessions.");
        }
    }

    private static async ValueTask<MuxFlowProbeResult> ProbeMuxFlowAsync(
        Stream stream,
        VlessRequest request,
        string userFlow,
        CancellationToken cancellationToken)
    {
        if (request.Command != VlessCommand.Mux ||
            !string.Equals(userFlow, VlessFlowTypes.Vision, StringComparison.Ordinal))
        {
            return new MuxFlowProbeResult(stream, AllowEmptyVisionMuxFlow: false);
        }

        if (!string.IsNullOrWhiteSpace(request.Addons.Flow))
        {
            return new MuxFlowProbeResult(stream, AllowEmptyVisionMuxFlow: false);
        }

        var probeBytes = await ReadMuxProbeAsync(stream, cancellationToken).ConfigureAwait(false);
        var probeStream = probeBytes.Length == 0
            ? stream
            : new PrefixedReadStream(stream, probeBytes);

        return new MuxFlowProbeResult(
            probeStream,
            AllowEmptyVisionMuxFlow: !IsMuxAndNotXudp(probeBytes));
    }

    private static Stream WrapApplicationStream(
        Stream stream,
        VlessUser user,
        string requestFlow)
    {
        if (!string.Equals(requestFlow, VlessFlowTypes.Vision, StringComparison.Ordinal))
        {
            return stream;
        }

        Span<byte> userUuidBytes = stackalloc byte[VlessVisionPaddingCodec.UserUuidLength];
        if (!ProtocolUuid.TryWriteBytes(user.Uuid, userUuidBytes))
        {
            throw new InvalidDataException("VLESS user UUID could not be converted into vision runtime state.");
        }

        return new VlessVisionDuplexStream(
            stream,
            new VlessVisionTrafficState(userUuidBytes),
            readIsUplink: true,
            writeIsUplink: false,
            paddingSeed: VlessVisionPaddingSeed.FromTestSeed(user.TestSeed));
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

    private static DispatchNetwork? ResolveMuxAllowedTargetNetwork(string userFlow)
        => string.Equals(userFlow, VlessFlowTypes.Vision, StringComparison.Ordinal)
            ? DispatchNetwork.Udp
            : null;

    private static bool IsMuxAndNotXudp(ReadOnlySpan<byte> firstBytes)
    {
        if (firstBytes.Length < MuxProbeBytes)
        {
            return true;
        }

        return !(firstBytes[2] == 0 &&
                 firstBytes[3] == 0 &&
                 firstBytes[6] == (byte)TrojanMuxTargetNetwork.Udp);
    }

    private static async ValueTask<byte[]> ReadMuxProbeAsync(Stream stream, CancellationToken cancellationToken)
    {
        var buffer = new byte[MuxProbeBytes];
        using var probeCts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        probeCts.CancelAfter(MuxProbeTimeout);

        try
        {
            var read = await stream.ReadAsync(buffer.AsMemory(0, buffer.Length), probeCts.Token).ConfigureAwait(false);
            return read == 0 ? Array.Empty<byte>() : buffer.AsSpan(0, read).ToArray();
        }
        catch (OperationCanceledException) when (!cancellationToken.IsCancellationRequested)
        {
            return Array.Empty<byte>();
        }
    }

    private static async Task<byte[]> ReadInitialPayloadAsync(Stream stream, CancellationToken cancellationToken)
    {
        var buffer = new byte[InitialProbeBytes];
        var read = 0;
        const int minimum = 17;

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

    private VlessReverseOutboundHandler GetOrCreateReverseHandler(string reverseTag)
    {
        if (string.IsNullOrWhiteSpace(reverseTag))
        {
            throw new InvalidOperationException("VLESS reverse tag is required to create reverse proxy sessions.");
        }

        if (_outboundManager is null)
        {
            throw new InvalidOperationException("VLESS reverse proxy requires an outbound manager.");
        }

        var normalizedTag = reverseTag.Trim();
        if (_outboundManager.GetHandler(normalizedTag) is { } existingHandler)
        {
            if (existingHandler is VlessReverseOutboundHandler reverseHandler)
            {
                return reverseHandler;
            }

            throw new InvalidOperationException($"VLESS reverse tag '{normalizedTag}' conflicts with an existing outbound handler.");
        }

        var created = new VlessReverseOutboundHandler(normalizedTag);
        try
        {
            _outboundManager.AddHandler(normalizedTag, created);
            return created;
        }
        catch (InvalidOperationException)
        {
            if (_outboundManager.GetHandler(normalizedTag) is VlessReverseOutboundHandler reverseHandler)
            {
                return reverseHandler;
            }

            throw;
        }
    }

    private sealed class HandshakeCaptureStream : Stream, IInnerStreamAccessor, IReplayablePrefixStream
    {
        private readonly Stream _innerStream;
        private readonly MemoryStream _captured = new();
        private bool _captureEnabled = true;

        public HandshakeCaptureStream(Stream innerStream)
        {
            ArgumentNullException.ThrowIfNull(innerStream);
            _innerStream = innerStream;
        }

        public Stream InnerStream => _innerStream;

        public int RemainingReplayablePrefixBytes
            => _innerStream is IReplayablePrefixStream replayable
                ? replayable.RemainingReplayablePrefixBytes
                : 0;

        public override bool CanRead => _innerStream.CanRead;

        public override bool CanSeek => false;

        public override bool CanWrite => _innerStream.CanWrite;

        public override bool CanTimeout => _innerStream.CanTimeout;

        public override long Length => throw new NotSupportedException();

        public override long Position
        {
            get => throw new NotSupportedException();
            set => throw new NotSupportedException();
        }

        public void StopCapture() => _captureEnabled = false;

        public byte[] GetCapturedBytes() => _captured.ToArray();

        public override void Flush() => _innerStream.Flush();

        public override Task FlushAsync(CancellationToken cancellationToken)
            => _innerStream.FlushAsync(cancellationToken);

        public override int Read(byte[] buffer, int offset, int count)
        {
            var read = _innerStream.Read(buffer, offset, count);
            Capture(buffer.AsSpan(offset, read));
            return read;
        }

        public override int Read(Span<byte> buffer)
        {
            var read = _innerStream.Read(buffer);
            Capture(buffer[..read]);
            return read;
        }

        public override Task<int> ReadAsync(byte[] buffer, int offset, int count, CancellationToken cancellationToken)
            => ReadAsync(buffer.AsMemory(offset, count), cancellationToken).AsTask();

        public override async ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken cancellationToken = default)
        {
            var read = await _innerStream.ReadAsync(buffer, cancellationToken).ConfigureAwait(false);
            Capture(buffer.Span[..read]);
            return read;
        }

        public override long Seek(long offset, SeekOrigin origin)
            => throw new NotSupportedException();

        public override void SetLength(long value)
            => throw new NotSupportedException();

        public override void Write(byte[] buffer, int offset, int count)
            => _innerStream.Write(buffer, offset, count);

        public override void Write(ReadOnlySpan<byte> buffer)
            => _innerStream.Write(buffer);

        public override Task WriteAsync(byte[] buffer, int offset, int count, CancellationToken cancellationToken)
            => _innerStream.WriteAsync(buffer, offset, count, cancellationToken);

        public override ValueTask WriteAsync(ReadOnlyMemory<byte> buffer, CancellationToken cancellationToken = default)
            => _innerStream.WriteAsync(buffer, cancellationToken);

        public int SkipReplayablePrefix(int count)
            => _innerStream is IReplayablePrefixStream replayable
                ? replayable.SkipReplayablePrefix(count)
                : 0;

        private void Capture(ReadOnlySpan<byte> buffer)
        {
            if (!_captureEnabled || buffer.Length == 0)
            {
                return;
            }

            _captured.Write(buffer);
        }
    }

    private sealed record MuxFlowProbeResult(Stream Stream, bool AllowEmptyVisionMuxFlow);
}

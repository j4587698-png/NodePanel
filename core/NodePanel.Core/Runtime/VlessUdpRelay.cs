using NodePanel.Core.Protocol;

namespace NodePanel.Core.Runtime;

public sealed class VlessUdpRelay
{
    private readonly IDispatcher _dispatcher;
    private readonly IRuntimeSniffer _runtimeSniffer;
    private readonly IRuntimeRateLimiterRegistry _rateLimiterRegistry;
    private readonly IRuntimeTrafficRegistry _trafficRegistry;
    private readonly VlessUdpPacketReader _udpPacketReader;
    private readonly VlessUdpPacketWriter _udpPacketWriter;

    public VlessUdpRelay(
        IDispatcher dispatcher,
        IRuntimeRateLimiterRegistry rateLimiterRegistry,
        IRuntimeTrafficRegistry trafficRegistry,
        VlessUdpPacketReader udpPacketReader,
        VlessUdpPacketWriter udpPacketWriter,
        IFakeDnsEngine? fakeDnsEngine = null)
        : this(
            dispatcher,
            rateLimiterRegistry,
            trafficRegistry,
            udpPacketReader,
            udpPacketWriter,
            new DefaultRuntimeSniffer(fakeDnsEngine))
    {
    }

    internal VlessUdpRelay(
        IDispatcher dispatcher,
        IRuntimeRateLimiterRegistry rateLimiterRegistry,
        IRuntimeTrafficRegistry trafficRegistry,
        VlessUdpPacketReader udpPacketReader,
        VlessUdpPacketWriter udpPacketWriter,
        IRuntimeSniffer runtimeSniffer)
    {
        _dispatcher = dispatcher;
        _rateLimiterRegistry = rateLimiterRegistry;
        _trafficRegistry = trafficRegistry;
        _udpPacketReader = udpPacketReader;
        _udpPacketWriter = udpPacketWriter;
        _runtimeSniffer = runtimeSniffer;
    }

    internal async Task RelayAsync(
        Stream stream,
        VlessRequest request,
        VlessUser user,
        VlessInboundSessionOptions options,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(options);

        using var linkedCts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        await using var activityTimer = ActivityTimer.CancelAfterInactivity(
            linkedCts.Cancel,
            TimeSpan.FromSeconds(options.ConnectionIdleSeconds));
        using var writeLock = new SemaphoreSlim(1, 1);

        var userGate = _rateLimiterRegistry.GetUserGate(user);
        var globalGate = _rateLimiterRegistry.GlobalGate;
        var destination = new DispatchDestination
        {
            Host = request.TargetHost,
            Port = request.TargetPort,
            Network = DispatchNetwork.Udp
        };
        var dispatchContext = DispatchContextTargeting.SetOriginalAndTarget(
            VlessDispatchContextFactory.Create(user, options, request.VlessRoutePort),
            destination);

        byte[]? firstPacket = null;
        if (options.Sniffing.Enabled)
        {
            firstPacket = await _udpPacketReader.ReadAsync(stream, linkedCts.Token).ConfigureAwait(false);
            if (firstPacket is null)
            {
                return;
            }

            activityTimer.Update();
        }

        var dispatchResult = await RuntimeUdpDispatchPipeline.DispatchAsync(
            _dispatcher,
            _runtimeSniffer,
            options.Sniffing,
            firstPacket ?? Array.Empty<byte>(),
            dispatchContext,
            destination,
            linkedCts.Token).ConfigureAwait(false);
        destination = dispatchResult.Destination;

        await using var udpTransport = dispatchResult.Transport;
        var handleFlowLocally = !RuntimeUdpTransportClassifier.IsFlowControlled(udpTransport);
        await VlessHandshakeReader.WriteResponseAsync(stream, request.Version, linkedCts.Token).ConfigureAwait(false);
        activityTimer.Update();

        if (firstPacket is not null)
        {
            if (handleFlowLocally)
            {
                await userGate.WaitAsync(firstPacket.Length, linkedCts.Token).ConfigureAwait(false);
                await globalGate.WaitAsync(firstPacket.Length, linkedCts.Token).ConfigureAwait(false);
            }

            await udpTransport.SendAsync(destination, firstPacket, linkedCts.Token).ConfigureAwait(false);
            activityTimer.Update();
            if (handleFlowLocally)
            {
                _trafficRegistry.RecordUpload(user, firstPacket.Length);
            }
        }

        var requestTask = RunRequestLoopAsync(
            stream,
            udpTransport,
            destination,
            user,
            userGate,
            globalGate,
            handleFlowLocally,
            activityTimer,
            linkedCts.Token);

        var responseTask = RunResponseLoopAsync(
            stream,
            udpTransport,
            user,
            userGate,
            globalGate,
            handleFlowLocally,
            writeLock,
            activityTimer,
            linkedCts.Token);

        try
        {
            await Task.WhenAny(requestTask, responseTask).ConfigureAwait(false);
            linkedCts.Cancel();
            await Task.WhenAll(
                ObserveCancellationAsync(requestTask, linkedCts.Token),
                ObserveCancellationAsync(responseTask, linkedCts.Token)).ConfigureAwait(false);
        }
        catch
        {
            linkedCts.Cancel();
            throw;
        }
    }

    private async Task RunRequestLoopAsync(
        Stream stream,
        IOutboundUdpTransport udpTransport,
        DispatchDestination destination,
        VlessUser user,
        ByteRateGate userGate,
        ByteRateGate globalGate,
        bool handleFlowLocally,
        ActivityTimer activityTimer,
        CancellationToken cancellationToken)
    {
        while (!cancellationToken.IsCancellationRequested)
        {
            var payload = await _udpPacketReader.ReadAsync(stream, cancellationToken).ConfigureAwait(false);
            if (payload is null)
            {
                return;
            }

            activityTimer.Update();
            if (handleFlowLocally)
            {
                await userGate.WaitAsync(payload.Length, cancellationToken).ConfigureAwait(false);
                await globalGate.WaitAsync(payload.Length, cancellationToken).ConfigureAwait(false);
            }
            await udpTransport.SendAsync(destination, payload, cancellationToken).ConfigureAwait(false);

            activityTimer.Update();
            if (handleFlowLocally)
            {
                _trafficRegistry.RecordUpload(user, payload.Length);
            }
        }
    }

    private async Task RunResponseLoopAsync(
        Stream stream,
        IOutboundUdpTransport udpTransport,
        VlessUser user,
        ByteRateGate userGate,
        ByteRateGate globalGate,
        bool handleFlowLocally,
        SemaphoreSlim writeLock,
        ActivityTimer activityTimer,
        CancellationToken cancellationToken)
    {
        while (!cancellationToken.IsCancellationRequested)
        {
            var datagram = await udpTransport.ReceiveAsync(cancellationToken).ConfigureAwait(false);
            if (datagram is null)
            {
                return;
            }

            activityTimer.Update();
            if (handleFlowLocally)
            {
                await userGate.WaitAsync(datagram.Payload.Length, cancellationToken).ConfigureAwait(false);
                await globalGate.WaitAsync(datagram.Payload.Length, cancellationToken).ConfigureAwait(false);
            }

            await WritePacketAsync(
                stream,
                user,
                datagram.Payload,
                handleFlowLocally,
                writeLock,
                activityTimer,
                cancellationToken).ConfigureAwait(false);
        }
    }

    private async Task WritePacketAsync(
        Stream stream,
        VlessUser user,
        ReadOnlyMemory<byte> payload,
        bool handleFlowLocally,
        SemaphoreSlim writeLock,
        ActivityTimer activityTimer,
        CancellationToken cancellationToken)
    {
        await writeLock.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            await _udpPacketWriter.WriteAsync(stream, payload, cancellationToken).ConfigureAwait(false);
            activityTimer.Update();
            if (handleFlowLocally)
            {
                _trafficRegistry.RecordDownload(user, payload.Length);
            }
        }
        finally
        {
            writeLock.Release();
        }
    }

    private static async Task ObserveCancellationAsync(Task task, CancellationToken cancellationToken)
    {
        try
        {
            await task.ConfigureAwait(false);
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
        }
    }
}

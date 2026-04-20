using NodePanel.Core.Protocol;

namespace NodePanel.Core.Runtime;

public sealed class VmessUdpRelay
{
    private readonly IDispatcher _dispatcher;
    private readonly IRuntimeSniffer _runtimeSniffer;
    private readonly IRuntimeRateLimiterRegistry _rateLimiterRegistry;
    private readonly IRuntimeTrafficRegistry _trafficRegistry;

    public VmessUdpRelay(
        IDispatcher dispatcher,
        IRuntimeRateLimiterRegistry rateLimiterRegistry,
        IRuntimeTrafficRegistry trafficRegistry,
        IFakeDnsEngine? fakeDnsEngine = null)
        : this(
            dispatcher,
            rateLimiterRegistry,
            trafficRegistry,
            new DefaultRuntimeSniffer(fakeDnsEngine))
    {
    }

    internal VmessUdpRelay(
        IDispatcher dispatcher,
        IRuntimeRateLimiterRegistry rateLimiterRegistry,
        IRuntimeTrafficRegistry trafficRegistry,
        IRuntimeSniffer runtimeSniffer)
    {
        _dispatcher = dispatcher;
        _rateLimiterRegistry = rateLimiterRegistry;
        _trafficRegistry = trafficRegistry;
        _runtimeSniffer = runtimeSniffer;
    }

    internal async Task RelayAsync(
        VmessDataStream vmessStream,
        VmessRequest request,
        VmessInboundSessionOptions options,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(options);

        using var linkedCts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        await using var activityTimer = ActivityTimer.CancelAfterInactivity(
            linkedCts.Cancel,
            TimeSpan.FromSeconds(options.ConnectionIdleSeconds));
        using var writeLock = new SemaphoreSlim(1, 1);

        var userGate = _rateLimiterRegistry.GetUserGate(request.User);
        var globalGate = _rateLimiterRegistry.GlobalGate;
        var destination = new DispatchDestination
        {
            Host = request.TargetHost,
            Port = request.TargetPort,
            Network = DispatchNetwork.Udp
        };
        var dispatchContext = DispatchContextTargeting.SetOriginalAndTarget(
            VmessDispatchContextFactory.Create(request.User, options),
            destination);

        var firstPacket = await vmessStream.ReadPacketAsync(linkedCts.Token).ConfigureAwait(false);
        if (firstPacket is null)
        {
            return;
        }

        activityTimer.Update();

        var dispatchResult = await RuntimeUdpDispatchPipeline.DispatchAsync(
            _dispatcher,
            _runtimeSniffer,
            options.Sniffing,
            firstPacket,
            dispatchContext,
            destination,
            linkedCts.Token).ConfigureAwait(false);
        destination = dispatchResult.Destination;

        await using var udpTransport = dispatchResult.Transport;
        var handleFlowLocally = !RuntimeUdpTransportClassifier.IsFlowControlled(udpTransport);
        if (handleFlowLocally)
        {
            await userGate.WaitAsync(firstPacket.Length, linkedCts.Token).ConfigureAwait(false);
            await globalGate.WaitAsync(firstPacket.Length, linkedCts.Token).ConfigureAwait(false);
        }

        await udpTransport.SendAsync(destination, firstPacket, linkedCts.Token).ConfigureAwait(false);
        activityTimer.Update();
        if (handleFlowLocally)
        {
            _trafficRegistry.RecordUpload(request.User, firstPacket.Length);
        }

        var requestTask = RunRequestLoopAsync(
            vmessStream,
            udpTransport,
            destination,
            request.User,
            userGate,
            globalGate,
            handleFlowLocally,
            activityTimer,
            linkedCts.Token);

        var responseTask = RunResponseLoopAsync(
            vmessStream,
            udpTransport,
            request.User,
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
        VmessDataStream vmessStream,
        IOutboundUdpTransport udpTransport,
        DispatchDestination destination,
        VmessUser user,
        ByteRateGate userGate,
        ByteRateGate globalGate,
        bool handleFlowLocally,
        ActivityTimer activityTimer,
        CancellationToken cancellationToken)
    {
        while (!cancellationToken.IsCancellationRequested)
        {
            var packet = await vmessStream.ReadPacketAsync(cancellationToken).ConfigureAwait(false);
            if (packet is null)
            {
                return;
            }

            activityTimer.Update();
            if (handleFlowLocally)
            {
                await userGate.WaitAsync(packet.Length, cancellationToken).ConfigureAwait(false);
                await globalGate.WaitAsync(packet.Length, cancellationToken).ConfigureAwait(false);
            }
            await udpTransport.SendAsync(destination, packet, cancellationToken).ConfigureAwait(false);

            activityTimer.Update();
            if (handleFlowLocally)
            {
                _trafficRegistry.RecordUpload(user, packet.Length);
            }
        }
    }

    private async Task RunResponseLoopAsync(
        VmessDataStream vmessStream,
        IOutboundUdpTransport udpTransport,
        VmessUser user,
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
                vmessStream,
                user,
                datagram.Payload,
                handleFlowLocally,
                writeLock,
                activityTimer,
                cancellationToken).ConfigureAwait(false);
        }
    }

    private async Task WritePacketAsync(
        VmessDataStream vmessStream,
        VmessUser user,
        ReadOnlyMemory<byte> payload,
        bool handleFlowLocally,
        SemaphoreSlim writeLock,
        ActivityTimer activityTimer,
        CancellationToken cancellationToken)
    {
        await writeLock.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            await vmessStream.WritePacketAsync(payload, cancellationToken).ConfigureAwait(false);
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

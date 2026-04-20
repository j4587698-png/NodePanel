using NodePanel.Core.Protocol;

namespace NodePanel.Core.Runtime;
public sealed class TrojanUdpAssociateRelay
{
    private readonly IDispatcher _dispatcher;
    private readonly IRuntimeSniffer _runtimeSniffer;
    private readonly IRuntimeRateLimiterRegistry _rateLimiterRegistry;
    private readonly IRuntimeTrafficRegistry _trafficRegistry;
    private readonly TrojanUdpPacketReader _udpPacketReader;
    private readonly TrojanUdpPacketWriter _udpPacketWriter;

    public TrojanUdpAssociateRelay(
        IDispatcher dispatcher,
        IRuntimeRateLimiterRegistry rateLimiterRegistry,
        IRuntimeTrafficRegistry trafficRegistry,
        TrojanUdpPacketReader udpPacketReader,
        TrojanUdpPacketWriter udpPacketWriter,
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

    internal TrojanUdpAssociateRelay(
        IDispatcher dispatcher,
        IRuntimeRateLimiterRegistry rateLimiterRegistry,
        IRuntimeTrafficRegistry trafficRegistry,
        TrojanUdpPacketReader udpPacketReader,
        TrojanUdpPacketWriter udpPacketWriter,
        IRuntimeSniffer runtimeSniffer)
    {
        _dispatcher = dispatcher;
        _rateLimiterRegistry = rateLimiterRegistry;
        _trafficRegistry = trafficRegistry;
        _udpPacketReader = udpPacketReader;
        _udpPacketWriter = udpPacketWriter;
        _runtimeSniffer = runtimeSniffer;
    }

    public async Task RelayAsync(
        Stream stream,
        TrojanUser user,
        IRuntimeInboundConnectionOptions options,
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
        var firstPacket = await _udpPacketReader.ReadAsync(stream, linkedCts.Token).ConfigureAwait(false);
        if (firstPacket is null)
        {
            return;
        }

        activityTimer.Update();

        var firstDestination = new DispatchDestination
        {
            Host = firstPacket.DestinationHost,
            Port = firstPacket.DestinationPort,
            Network = DispatchNetwork.Udp
        };
        var dispatchContext = DispatchContextTargeting.SetOriginalAndTarget(
            TrojanDispatchContextFactory.Create(user, options),
            firstDestination);

        var dispatchResult = await RuntimeUdpDispatchPipeline.DispatchAsync(
            _dispatcher,
            _runtimeSniffer,
            options.Sniffing,
            firstPacket.Payload,
            dispatchContext,
            firstDestination,
            linkedCts.Token).ConfigureAwait(false);
        firstDestination = dispatchResult.Destination;

        await using var udpTransport = dispatchResult.Transport;
        var handleFlowLocally = !RuntimeUdpTransportClassifier.IsFlowControlled(udpTransport);
        if (handleFlowLocally)
        {
            await userGate.WaitAsync(firstPacket.Payload.Length, linkedCts.Token).ConfigureAwait(false);
            await globalGate.WaitAsync(firstPacket.Payload.Length, linkedCts.Token).ConfigureAwait(false);
        }

        await udpTransport.SendAsync(
            firstDestination,
            firstPacket.Payload,
            linkedCts.Token).ConfigureAwait(false);
        activityTimer.Update();
        if (handleFlowLocally)
        {
            _trafficRegistry.RecordUpload(user, firstPacket.Payload.Length);
        }

        var requestTask = RunRequestLoopAsync(
            stream,
            udpTransport,
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
        TrojanUser user,
        ByteRateGate userGate,
        ByteRateGate globalGate,
        bool handleFlowLocally,
        ActivityTimer activityTimer,
        CancellationToken cancellationToken)
    {
        while (!cancellationToken.IsCancellationRequested)
        {
            var packet = await _udpPacketReader.ReadAsync(stream, cancellationToken).ConfigureAwait(false);
            if (packet is null)
            {
                return;
            }

            activityTimer.Update();
            if (handleFlowLocally)
            {
                await userGate.WaitAsync(packet.Payload.Length, cancellationToken).ConfigureAwait(false);
                await globalGate.WaitAsync(packet.Payload.Length, cancellationToken).ConfigureAwait(false);
            }

            await udpTransport.SendAsync(
                new DispatchDestination
                {
                    Host = packet.DestinationHost,
                    Port = packet.DestinationPort,
                    Network = DispatchNetwork.Udp
                },
                packet.Payload,
                cancellationToken).ConfigureAwait(false);

            activityTimer.Update();
            if (handleFlowLocally)
            {
                _trafficRegistry.RecordUpload(user, packet.Payload.Length);
            }
        }
    }

    private async Task RunResponseLoopAsync(
        Stream stream,
        IOutboundUdpTransport udpTransport,
        TrojanUser user,
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
                new TrojanUdpPacket
                {
                    DestinationHost = datagram.SourceHost,
                    DestinationPort = datagram.SourcePort,
                    Payload = datagram.Payload
                },
                handleFlowLocally,
                writeLock,
                activityTimer,
                cancellationToken).ConfigureAwait(false);
        }
    }

    private async Task WritePacketAsync(
        Stream clientStream,
        TrojanUser user,
        TrojanUdpPacket packet,
        bool handleFlowLocally,
        SemaphoreSlim writeLock,
        ActivityTimer activityTimer,
        CancellationToken cancellationToken)
    {
        await writeLock.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            await _udpPacketWriter.WriteAsync(clientStream, packet, cancellationToken).ConfigureAwait(false);
            activityTimer.Update();
            if (handleFlowLocally)
            {
                _trafficRegistry.RecordDownload(user, packet.Payload.Length);
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

using NodePanel.Core.Protocol;

namespace NodePanel.Core.Runtime;
public sealed class TrojanUdpAssociateRelay
{
    private readonly IDispatcher _dispatcher;
    private readonly RateLimiterRegistry _rateLimiterRegistry;
    private readonly TrafficRegistry _trafficRegistry;
    private readonly TrojanUdpPacketReader _udpPacketReader;
    private readonly TrojanUdpPacketWriter _udpPacketWriter;

    public TrojanUdpAssociateRelay(
        IDispatcher dispatcher,
        RateLimiterRegistry rateLimiterRegistry,
        TrafficRegistry trafficRegistry,
        TrojanUdpPacketReader udpPacketReader,
        TrojanUdpPacketWriter udpPacketWriter)
    {
        _dispatcher = dispatcher;
        _rateLimiterRegistry = rateLimiterRegistry;
        _trafficRegistry = trafficRegistry;
        _udpPacketReader = udpPacketReader;
        _udpPacketWriter = udpPacketWriter;
    }

    public async Task RelayAsync(
        Stream stream,
        TrojanUser user,
        ITrojanInboundConnectionOptions options,
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
        var dispatchContext = TrojanDispatchContextFactory.Create(user, options);
        var firstPacket = await _udpPacketReader.ReadAsync(stream, linkedCts.Token).ConfigureAwait(false);
        if (firstPacket is null)
        {
            return;
        }

        activityTimer.Update();
        await userGate.WaitAsync(firstPacket.Payload.Length, linkedCts.Token).ConfigureAwait(false);
        await globalGate.WaitAsync(firstPacket.Payload.Length, linkedCts.Token).ConfigureAwait(false);

        var firstDestination = new DispatchDestination
        {
            Host = firstPacket.DestinationHost,
            Port = firstPacket.DestinationPort,
            Network = DispatchNetwork.Udp
        };
        dispatchContext = dispatchContext with
        {
            OriginalDestinationHost = firstPacket.DestinationHost,
            OriginalDestinationPort = firstPacket.DestinationPort
        };

        if (options.Sniffing.Enabled && !options.Sniffing.MetadataOnly)
        {
            var sniffing = TrojanSniffingEvaluator.Evaluate(
                options.Sniffing,
                firstPacket.Payload,
                DispatchNetwork.Udp,
                firstDestination);

            dispatchContext = dispatchContext with
            {
                DetectedProtocol = sniffing.Protocol,
                DetectedDomain = sniffing.Domain
            };

            if (sniffing.OverrideDestination is not null)
            {
                firstDestination = sniffing.OverrideDestination;
            }
        }

        await using var udpTransport = await _dispatcher.DispatchUdpAsync(
            dispatchContext,
            linkedCts.Token).ConfigureAwait(false);
        await udpTransport.SendAsync(
            firstDestination,
            firstPacket.Payload,
            linkedCts.Token).ConfigureAwait(false);
        activityTimer.Update();
        _trafficRegistry.RecordUpload(user.UserId, firstPacket.Payload.Length);

        var requestTask = RunRequestLoopAsync(
            stream,
            udpTransport,
            user,
            userGate,
            globalGate,
            activityTimer,
            linkedCts.Token);

        var responseTask = RunResponseLoopAsync(
            stream,
            udpTransport,
            user,
            userGate,
            globalGate,
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
            await userGate.WaitAsync(packet.Payload.Length, cancellationToken).ConfigureAwait(false);
            await globalGate.WaitAsync(packet.Payload.Length, cancellationToken).ConfigureAwait(false);

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
            _trafficRegistry.RecordUpload(user.UserId, packet.Payload.Length);
        }
    }

    private async Task RunResponseLoopAsync(
        Stream stream,
        IOutboundUdpTransport udpTransport,
        TrojanUser user,
        ByteRateGate userGate,
        ByteRateGate globalGate,
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
            await userGate.WaitAsync(datagram.Payload.Length, cancellationToken).ConfigureAwait(false);
            await globalGate.WaitAsync(datagram.Payload.Length, cancellationToken).ConfigureAwait(false);

            await WritePacketAsync(
                stream,
                user,
                new TrojanUdpPacket
                {
                    DestinationHost = datagram.SourceHost,
                    DestinationPort = datagram.SourcePort,
                    Payload = datagram.Payload
                },
                writeLock,
                activityTimer,
                cancellationToken).ConfigureAwait(false);
        }
    }

    private async Task WritePacketAsync(
        Stream clientStream,
        TrojanUser user,
        TrojanUdpPacket packet,
        SemaphoreSlim writeLock,
        ActivityTimer activityTimer,
        CancellationToken cancellationToken)
    {
        await writeLock.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            await _udpPacketWriter.WriteAsync(clientStream, packet, cancellationToken).ConfigureAwait(false);
            activityTimer.Update();
            _trafficRegistry.RecordDownload(user.UserId, packet.Payload.Length);
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

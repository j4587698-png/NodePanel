using NodePanel.Core.Protocol;

namespace NodePanel.Core.Runtime;

public sealed class VmessUdpRelay
{
    private readonly IDispatcher _dispatcher;
    private readonly RateLimiterRegistry _rateLimiterRegistry;
    private readonly TrafficRegistry _trafficRegistry;

    public VmessUdpRelay(
        IDispatcher dispatcher,
        RateLimiterRegistry rateLimiterRegistry,
        TrafficRegistry trafficRegistry)
    {
        _dispatcher = dispatcher;
        _rateLimiterRegistry = rateLimiterRegistry;
        _trafficRegistry = trafficRegistry;
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
        var dispatchContext = VmessDispatchContextFactory.Create(request.User, options);
        var destination = new DispatchDestination
        {
            Host = request.TargetHost,
            Port = request.TargetPort,
            Network = DispatchNetwork.Udp
        };
        dispatchContext = dispatchContext with
        {
            OriginalDestinationHost = request.TargetHost,
            OriginalDestinationPort = request.TargetPort
        };

        var firstPacket = await vmessStream.ReadPacketAsync(linkedCts.Token).ConfigureAwait(false);
        if (firstPacket is null)
        {
            return;
        }

        activityTimer.Update();
        await userGate.WaitAsync(firstPacket.Length, linkedCts.Token).ConfigureAwait(false);
        await globalGate.WaitAsync(firstPacket.Length, linkedCts.Token).ConfigureAwait(false);

        if (options.Sniffing.Enabled && !options.Sniffing.MetadataOnly)
        {
            var sniffing = TrojanSniffingEvaluator.Evaluate(
                options.Sniffing,
                firstPacket,
                DispatchNetwork.Udp,
                destination);

            dispatchContext = dispatchContext with
            {
                DetectedProtocol = sniffing.Protocol,
                DetectedDomain = sniffing.Domain
            };

            if (sniffing.OverrideDestination is not null)
            {
                destination = sniffing.OverrideDestination with
                {
                    Network = DispatchNetwork.Udp
                };
            }
        }

        await using var udpTransport = await _dispatcher.DispatchUdpAsync(
            dispatchContext,
            linkedCts.Token).ConfigureAwait(false);
        await udpTransport.SendAsync(destination, firstPacket, linkedCts.Token).ConfigureAwait(false);
        activityTimer.Update();
        _trafficRegistry.RecordUpload(request.User.UserId, firstPacket.Length);

        var requestTask = RunRequestLoopAsync(
            vmessStream,
            udpTransport,
            destination,
            request.User,
            userGate,
            globalGate,
            activityTimer,
            linkedCts.Token);

        var responseTask = RunResponseLoopAsync(
            vmessStream,
            udpTransport,
            request.User,
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
        VmessDataStream vmessStream,
        IOutboundUdpTransport udpTransport,
        DispatchDestination destination,
        VmessUser user,
        ByteRateGate userGate,
        ByteRateGate globalGate,
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
            await userGate.WaitAsync(packet.Length, cancellationToken).ConfigureAwait(false);
            await globalGate.WaitAsync(packet.Length, cancellationToken).ConfigureAwait(false);
            await udpTransport.SendAsync(destination, packet, cancellationToken).ConfigureAwait(false);

            activityTimer.Update();
            _trafficRegistry.RecordUpload(user.UserId, packet.Length);
        }
    }

    private async Task RunResponseLoopAsync(
        VmessDataStream vmessStream,
        IOutboundUdpTransport udpTransport,
        VmessUser user,
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
                vmessStream,
                user,
                datagram.Payload,
                writeLock,
                activityTimer,
                cancellationToken).ConfigureAwait(false);
        }
    }

    private async Task WritePacketAsync(
        VmessDataStream vmessStream,
        VmessUser user,
        ReadOnlyMemory<byte> payload,
        SemaphoreSlim writeLock,
        ActivityTimer activityTimer,
        CancellationToken cancellationToken)
    {
        await writeLock.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            await vmessStream.WritePacketAsync(payload, cancellationToken).ConfigureAwait(false);
            activityTimer.Update();
            _trafficRegistry.RecordDownload(user.UserId, payload.Length);
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

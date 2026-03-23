using NodePanel.Core.Protocol;

namespace NodePanel.Core.Runtime;

public sealed class VlessUdpRelay
{
    private readonly IDispatcher _dispatcher;
    private readonly RateLimiterRegistry _rateLimiterRegistry;
    private readonly TrafficRegistry _trafficRegistry;
    private readonly VlessUdpPacketReader _udpPacketReader;
    private readonly VlessUdpPacketWriter _udpPacketWriter;

    public VlessUdpRelay(
        IDispatcher dispatcher,
        RateLimiterRegistry rateLimiterRegistry,
        TrafficRegistry trafficRegistry,
        VlessUdpPacketReader udpPacketReader,
        VlessUdpPacketWriter udpPacketWriter)
    {
        _dispatcher = dispatcher;
        _rateLimiterRegistry = rateLimiterRegistry;
        _trafficRegistry = trafficRegistry;
        _udpPacketReader = udpPacketReader;
        _udpPacketWriter = udpPacketWriter;
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
        var dispatchContext = VlessDispatchContextFactory.Create(user, options);
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

        byte[]? firstPacket = null;
        if (options.Sniffing.Enabled && !options.Sniffing.MetadataOnly)
        {
            firstPacket = await _udpPacketReader.ReadAsync(stream, linkedCts.Token).ConfigureAwait(false);
            if (firstPacket is null)
            {
                return;
            }

            activityTimer.Update();
            await userGate.WaitAsync(firstPacket.Length, linkedCts.Token).ConfigureAwait(false);
            await globalGate.WaitAsync(firstPacket.Length, linkedCts.Token).ConfigureAwait(false);

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
        await VlessHandshakeReader.WriteResponseAsync(stream, request.Version, linkedCts.Token).ConfigureAwait(false);
        activityTimer.Update();

        if (firstPacket is not null)
        {
            await udpTransport.SendAsync(destination, firstPacket, linkedCts.Token).ConfigureAwait(false);
            activityTimer.Update();
            _trafficRegistry.RecordUpload(user.UserId, firstPacket.Length);
        }

        var requestTask = RunRequestLoopAsync(
            stream,
            udpTransport,
            destination,
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
        DispatchDestination destination,
        VlessUser user,
        ByteRateGate userGate,
        ByteRateGate globalGate,
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
            await userGate.WaitAsync(payload.Length, cancellationToken).ConfigureAwait(false);
            await globalGate.WaitAsync(payload.Length, cancellationToken).ConfigureAwait(false);
            await udpTransport.SendAsync(destination, payload, cancellationToken).ConfigureAwait(false);

            activityTimer.Update();
            _trafficRegistry.RecordUpload(user.UserId, payload.Length);
        }
    }

    private async Task RunResponseLoopAsync(
        Stream stream,
        IOutboundUdpTransport udpTransport,
        VlessUser user,
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
                datagram.Payload,
                writeLock,
                activityTimer,
                cancellationToken).ConfigureAwait(false);
        }
    }

    private async Task WritePacketAsync(
        Stream stream,
        VlessUser user,
        ReadOnlyMemory<byte> payload,
        SemaphoreSlim writeLock,
        ActivityTimer activityTimer,
        CancellationToken cancellationToken)
    {
        await writeLock.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            await _udpPacketWriter.WriteAsync(stream, payload, cancellationToken).ConfigureAwait(false);
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

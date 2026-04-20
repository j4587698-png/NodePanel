using System.Net.Sockets;

namespace NodePanel.Core.Runtime;

public interface IRuntimeRelayService
{
    Task RelayAsync(
        Stream clientStream,
        Stream remoteStream,
        CancellationToken cancellationToken);

    Task RelayAsync(
        Stream clientStream,
        Stream remoteStream,
        IRuntimeInboundConnectionOptions options,
        CancellationToken cancellationToken);

    Task RelayAsync(
        Stream clientStream,
        Stream remoteStream,
        IRuntimeUserDefinition user,
        ByteRateGate userGate,
        ByteRateGate globalGate,
        IRuntimeTrafficRegistry trafficRegistry,
        CancellationToken cancellationToken);

    Task RelayAsync(
        Stream clientStream,
        Stream remoteStream,
        IRuntimeUserDefinition user,
        ByteRateGate userGate,
        ByteRateGate globalGate,
        IRuntimeTrafficRegistry trafficRegistry,
        IRuntimeInboundConnectionOptions options,
        CancellationToken cancellationToken);
}

public sealed class RelayService : IRuntimeRelayService
{
    public Task RelayAsync(
        Stream clientStream,
        Stream remoteStream,
        CancellationToken cancellationToken)
        => RelayAsync(
            clientStream,
            remoteStream,
            DefaultRuntimeInboundConnectionOptions.Instance,
            cancellationToken);

    public async Task RelayAsync(
        Stream clientStream,
        Stream remoteStream,
        IRuntimeInboundConnectionOptions options,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(options);
        SkipPreSentInitialPayload(clientStream, remoteStream);

        using var linkedCts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        await using var activityTimer = ActivityTimer.CancelAfterInactivity(
            linkedCts.Cancel,
            TimeSpan.FromSeconds(options.ConnectionIdleSeconds));

        var uplink = PumpPassthroughAsync(
            clientStream,
            remoteStream,
            activityTimer,
            TimeSpan.FromSeconds(options.DownlinkOnlySeconds),
            linkedCts.Token);
        var downlink = PumpPassthroughAsync(
            remoteStream,
            clientStream,
            activityTimer,
            TimeSpan.FromSeconds(options.UplinkOnlySeconds),
            linkedCts.Token);
        await RelayDuplexAsync(uplink, downlink, clientStream, remoteStream, linkedCts).ConfigureAwait(false);
    }

    public Task RelayAsync(
        Stream clientStream,
        Stream remoteStream,
        IRuntimeUserDefinition user,
        ByteRateGate userGate,
        ByteRateGate globalGate,
        IRuntimeTrafficRegistry trafficRegistry,
        CancellationToken cancellationToken)
        => RelayAsync(
            clientStream,
            remoteStream,
            user,
            userGate,
            globalGate,
            trafficRegistry,
            DefaultRuntimeInboundConnectionOptions.Instance,
            cancellationToken);

    public async Task RelayAsync(
        Stream clientStream,
        Stream remoteStream,
        IRuntimeUserDefinition user,
        ByteRateGate userGate,
        ByteRateGate globalGate,
        IRuntimeTrafficRegistry trafficRegistry,
        IRuntimeInboundConnectionOptions options,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(options);
        if (remoteStream is FlowControlledStream)
        {
            await RelayAsync(clientStream, remoteStream, options, cancellationToken).ConfigureAwait(false);
            return;
        }

        SkipPreSentInitialPayload(clientStream, remoteStream);

        using var linkedCts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        await using var activityTimer = ActivityTimer.CancelAfterInactivity(
            linkedCts.Cancel,
            TimeSpan.FromSeconds(options.ConnectionIdleSeconds));
        var trackedRemoteStream = new FlowControlledStream(
            remoteStream,
            writeControl: new StreamFlowControl(
                userGate,
                globalGate,
                bytes => trafficRegistry.RecordUpload(user, bytes)),
            activityTimer: activityTimer,
            leaveOpen: true);
        var trackedClientStream = new FlowControlledStream(
            clientStream,
            writeControl: new StreamFlowControl(
                userGate,
                globalGate,
                bytes => trafficRegistry.RecordDownload(user, bytes)),
            activityTimer: activityTimer,
            leaveOpen: true);

        var uplink = PumpPassthroughAsync(
            clientStream,
            trackedRemoteStream,
            activityTimer,
            TimeSpan.FromSeconds(options.DownlinkOnlySeconds),
            linkedCts.Token);

        var downlink = PumpPassthroughAsync(
            remoteStream,
            trackedClientStream,
            activityTimer,
            TimeSpan.FromSeconds(options.UplinkOnlySeconds),
            linkedCts.Token);
        await RelayDuplexAsync(uplink, downlink, clientStream, remoteStream, linkedCts).ConfigureAwait(false);
    }

    private static async Task PumpPassthroughAsync(
        Stream source,
        Stream destination,
        ActivityTimer activityTimer,
        TimeSpan completionTimeout,
        CancellationToken cancellationToken)
    {
        var buffer = new byte[32 * 1024];

        try
        {
            while (!cancellationToken.IsCancellationRequested)
            {
                var read = await source.ReadAsync(buffer.AsMemory(0, buffer.Length), cancellationToken).ConfigureAwait(false);
                if (read == 0)
                {
                    break;
                }

                activityTimer.Update();
                await destination.WriteAsync(buffer.AsMemory(0, read), cancellationToken).ConfigureAwait(false);
                activityTimer.Update();
            }
        }
        catch (Exception ex) when (!cancellationToken.IsCancellationRequested && IsPeerDisconnected(ex))
        {
        }
        finally
        {
            activityTimer.SetTimeout(completionTimeout);
        }
    }

    private static async Task RelayDuplexAsync(
        Task uplink,
        Task downlink,
        Stream clientStream,
        Stream remoteStream,
        CancellationTokenSource linkedCts)
    {
        var completed = await Task.WhenAny(uplink, downlink).ConfigureAwait(false);
        if (ReferenceEquals(completed, uplink))
        {
            if (!await CompleteFirstTaskAsync(uplink, downlink, linkedCts).ConfigureAwait(false))
            {
                return;
            }

            TryShutdownWrite(remoteStream);
            await CompleteRemainingTaskAsync(downlink, linkedCts).ConfigureAwait(false);
            return;
        }

        if (!await CompleteFirstTaskAsync(downlink, uplink, linkedCts).ConfigureAwait(false))
        {
            return;
        }

        TryShutdownWrite(clientStream);
        await CompleteRemainingTaskAsync(uplink, linkedCts).ConfigureAwait(false);
    }

    private static async Task<bool> CompleteFirstTaskAsync(
        Task firstTask,
        Task otherTask,
        CancellationTokenSource linkedCts)
    {
        try
        {
            await firstTask.ConfigureAwait(false);
            return true;
        }
        catch (OperationCanceledException) when (linkedCts.IsCancellationRequested)
        {
            await DrainCanceledTaskAsync(otherTask, linkedCts).ConfigureAwait(false);
            return false;
        }
        catch
        {
            linkedCts.Cancel();
            await DrainCanceledTaskAsync(otherTask, linkedCts).ConfigureAwait(false);
            throw;
        }
    }

    private static async Task CompleteRemainingTaskAsync(Task task, CancellationTokenSource linkedCts)
    {
        try
        {
            await task.ConfigureAwait(false);
        }
        catch (OperationCanceledException) when (linkedCts.IsCancellationRequested)
        {
        }
    }

    private static async Task DrainCanceledTaskAsync(Task task, CancellationTokenSource linkedCts)
    {
        try
        {
            await task.ConfigureAwait(false);
        }
        catch (OperationCanceledException) when (linkedCts.IsCancellationRequested)
        {
        }
        catch
        {
        }
    }

    private static void TryShutdownWrite(Stream stream)
    {
        if (!TryGetSocketForShutdown(stream, out var socket) || socket is null)
        {
            return;
        }

        try
        {
            socket.Shutdown(SocketShutdown.Send);
        }
        catch (ObjectDisposedException)
        {
        }
        catch (InvalidOperationException)
        {
        }
        catch (SocketException)
        {
        }
    }

    private static bool IsPeerDisconnected(Exception exception)
    {
        for (Exception? current = exception; current is not null; current = current.InnerException)
        {
            if (current is EndOfStreamException)
            {
                return true;
            }

            if (current is SocketException socketException &&
                socketException.SocketErrorCode is SocketError.ConnectionReset or
                    SocketError.ConnectionAborted or
                    SocketError.OperationAborted or
                    SocketError.Shutdown)
            {
                return true;
            }
        }

        return false;
    }

    private static bool TryGetSocketForShutdown(Stream stream, out Socket? socket)
    {
        while (true)
        {
            switch (stream)
            {
                case NetworkStream networkStream:
                    socket = networkStream.Socket;
                    return true;
                case IInnerStreamAccessor accessor:
                    stream = accessor.InnerStream;
                    continue;
                default:
                    socket = null;
                    return false;
            }
        }
    }

    private static void SkipPreSentInitialPayload(Stream clientStream, Stream remoteStream)
    {
        if (clientStream is not IReplayablePrefixStream replayable)
        {
            return;
        }

        var sentInitialPayloadBytes = ResolveSentInitialPayloadBytes(remoteStream);
        if (sentInitialPayloadBytes <= 0)
        {
            return;
        }

        replayable.SkipReplayablePrefix(sentInitialPayloadBytes);
    }

    private static int ResolveSentInitialPayloadBytes(Stream stream)
    {
        var sentBytes = 0;
        while (true)
        {
            if (stream is IInitialPayloadSentMetadata metadata)
            {
                sentBytes += metadata.SentInitialPayloadBytes;
            }

            if (stream is IInnerStreamAccessor accessor)
            {
                stream = accessor.InnerStream;
                continue;
            }

            return sentBytes;
        }
    }
}

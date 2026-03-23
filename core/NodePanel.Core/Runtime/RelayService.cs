using System.Net.Sockets;

namespace NodePanel.Core.Runtime;

public sealed class RelayService
{
    public Task RelayAsync(
        Stream clientStream,
        Stream remoteStream,
        CancellationToken cancellationToken)
        => RelayAsync(
            clientStream,
            remoteStream,
            DefaultTrojanInboundConnectionOptions.Instance,
            cancellationToken);

    public async Task RelayAsync(
        Stream clientStream,
        Stream remoteStream,
        ITrojanInboundConnectionOptions options,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(options);

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
        TrafficRegistry trafficRegistry,
        CancellationToken cancellationToken)
        => RelayAsync(
            clientStream,
            remoteStream,
            user,
            userGate,
            globalGate,
            trafficRegistry,
            DefaultTrojanInboundConnectionOptions.Instance,
            cancellationToken);

    public async Task RelayAsync(
        Stream clientStream,
        Stream remoteStream,
        IRuntimeUserDefinition user,
        ByteRateGate userGate,
        ByteRateGate globalGate,
        TrafficRegistry trafficRegistry,
        ITrojanInboundConnectionOptions options,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(options);

        using var linkedCts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        await using var activityTimer = ActivityTimer.CancelAfterInactivity(
            linkedCts.Cancel,
            TimeSpan.FromSeconds(options.ConnectionIdleSeconds));

        var uplink = PumpAsync(
            clientStream,
            remoteStream,
            user.UserId,
            userGate,
            globalGate,
            trafficRegistry.RecordUpload,
            activityTimer,
            TimeSpan.FromSeconds(options.DownlinkOnlySeconds),
            linkedCts.Token);

        var downlink = PumpAsync(
            remoteStream,
            clientStream,
            user.UserId,
            userGate,
            globalGate,
            trafficRegistry.RecordDownload,
            activityTimer,
            TimeSpan.FromSeconds(options.UplinkOnlySeconds),
            linkedCts.Token);
        await RelayDuplexAsync(uplink, downlink, clientStream, remoteStream, linkedCts).ConfigureAwait(false);
    }

    private static async Task PumpAsync(
        Stream source,
        Stream destination,
        string userId,
        ByteRateGate userGate,
        ByteRateGate globalGate,
        Action<string, int> onWritten,
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
                await userGate.WaitAsync(read, cancellationToken).ConfigureAwait(false);
                await globalGate.WaitAsync(read, cancellationToken).ConfigureAwait(false);
                await destination.WriteAsync(buffer.AsMemory(0, read), cancellationToken).ConfigureAwait(false);
                activityTimer.Update();
                onWritten(userId, read);
            }
        }
        finally
        {
            activityTimer.SetTimeout(completionTimeout);
        }
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

    private static bool TryGetSocketForShutdown(Stream stream, out Socket? socket)
    {
        switch (stream)
        {
            case NetworkStream networkStream:
                socket = networkStream.Socket;
                return true;
            case PrefixedReadStream prefixedReadStream:
                return TryGetSocketForShutdown(prefixedReadStream.InnerStream, out socket);
            default:
                socket = null;
                return false;
        }
    }
}

using System.Buffers.Binary;
using System.Net;
using System.Net.Sockets;

namespace NodePanel.Core.Runtime;

public sealed class Socks5LocalProxyServer
{
    private readonly IDispatcher _dispatcher;
    private readonly RelayService _relayService;

    public Socks5LocalProxyServer(IDispatcher dispatcher, RelayService relayService)
    {
        _dispatcher = dispatcher;
        _relayService = relayService;
    }

    public async Task RunAsync(Socks5LocalProxyServerOptions options, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(options);

        if (options.Listeners.Count == 0)
        {
            return;
        }

        var activeListeners = new List<ListenerRuntime>(options.Listeners.Count);
        try
        {
            foreach (var listener in options.Listeners)
            {
                var handle = ListenerHandle.Create(listener.Binding);
                activeListeners.Add(new ListenerRuntime(listener, handle));
                options.Callbacks.ListenerStarted?.Invoke(listener);
            }

            var acceptTasks = activeListeners
                .Select(listener => AcceptLoopAsync(listener, options, cancellationToken))
                .ToArray();
            var acceptGroup = Task.WhenAll(acceptTasks);
            var completed = await Task.WhenAny(acceptGroup, WaitForCancellationAsync(cancellationToken)).ConfigureAwait(false);

            foreach (var listener in activeListeners)
            {
                listener.Handle.Stop();
            }

            try
            {
                await acceptGroup.ConfigureAwait(false);
            }
            catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
            {
            }

            if (completed == acceptGroup && acceptGroup.Exception is not null)
            {
                throw acceptGroup.Exception.InnerExceptions.Count == 1
                    ? acceptGroup.Exception.InnerExceptions[0]
                    : acceptGroup.Exception;
            }
        }
        finally
        {
            foreach (var listener in activeListeners)
            {
                listener.Handle.Dispose();
            }
        }
    }

    private async Task AcceptLoopAsync(
        ListenerRuntime listener,
        Socks5LocalProxyServerOptions options,
        CancellationToken cancellationToken)
    {
        while (!cancellationToken.IsCancellationRequested)
        {
            AcceptedConnection connection;
            try
            {
                connection = await listener.Handle.AcceptAsync(cancellationToken).ConfigureAwait(false);
            }
            catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
            {
                break;
            }
            catch (ObjectDisposedException)
            {
                break;
            }
            catch (SocketException) when (cancellationToken.IsCancellationRequested)
            {
                break;
            }

            _ = Task.Run(
                () => HandleAcceptedConnectionAsync(connection, listener.Definition, options, cancellationToken),
                CancellationToken.None);
        }
    }

    private async Task HandleAcceptedConnectionAsync(
        AcceptedConnection connection,
        LocalProxyListenerDefinition listener,
        Socks5LocalProxyServerOptions options,
        CancellationToken cancellationToken)
    {
        await using var connectionLease = connection;
        try
        {
            using var handshakeCts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
            handshakeCts.CancelAfter(TimeSpan.FromSeconds(listener.HandshakeTimeoutSeconds));

            if (!await PerformGreetingAsync(connection.Stream, handshakeCts.Token).ConfigureAwait(false))
            {
                return;
            }

            var request = await ReadRequestAsync(connection.Stream, handshakeCts.Token).ConfigureAwait(false);
            if (request is null)
            {
                return;
            }

            if (request.Command != SocksCommand.Connect)
            {
                await SendReplyAsync(connection.Stream, SocksReply.CommandNotSupported, handshakeCts.Token).ConfigureAwait(false);
                return;
            }

            var proxyOptions = CreateConnectionOptions(listener, connection, options.Limits);
            await using var remoteStream = await _dispatcher.DispatchTcpAsync(
                    new DispatchContext
                    {
                        InboundProtocol = LocalInboundProtocols.Socks,
                        InboundTag = listener.Tag,
                        ConnectTimeoutSeconds = proxyOptions.ConnectTimeoutSeconds,
                        ConnectionIdleSeconds = proxyOptions.ConnectionIdleSeconds,
                        UplinkOnlySeconds = proxyOptions.UplinkOnlySeconds,
                        DownlinkOnlySeconds = proxyOptions.DownlinkOnlySeconds,
                        SourceEndPoint = proxyOptions.RemoteEndPoint,
                        LocalEndPoint = proxyOptions.LocalEndPoint,
                        OriginalDestinationHost = request.Host,
                        OriginalDestinationPort = request.Port
                    },
                    new DispatchDestination
                    {
                        Host = request.Host,
                        Port = request.Port,
                        Network = DispatchNetwork.Tcp
                    },
                    cancellationToken)
                .ConfigureAwait(false);

            await SendReplyAsync(connection.Stream, SocksReply.Succeeded, cancellationToken).ConfigureAwait(false);
            await _relayService.RelayAsync(connection.Stream, remoteStream, proxyOptions, cancellationToken).ConfigureAwait(false);
        }
        catch (Exception ex) when (ex is not OperationCanceledException || !cancellationToken.IsCancellationRequested)
        {
            options.Callbacks.ConnectionError?.Invoke(new LocalProxyConnectionErrorContext
            {
                Protocol = LocalInboundProtocols.Socks,
                InboundTag = listener.Tag,
                Exception = ex,
                RemoteEndPoint = connection.LogRemoteEndPoint ?? connection.RemoteEndPoint
            });
        }
    }

    private static async Task<bool> PerformGreetingAsync(Stream stream, CancellationToken cancellationToken)
    {
        var header = new byte[2];
        if (!await ReadExactAsync(stream, header, cancellationToken).ConfigureAwait(false))
        {
            return false;
        }

        if (header[0] != 0x05)
        {
            return false;
        }

        var methods = new byte[header[1]];
        if (!await ReadExactAsync(stream, methods, cancellationToken).ConfigureAwait(false))
        {
            return false;
        }

        var supportsNoAuth = methods.Contains((byte)0x00);
        await stream.WriteAsync(new byte[] { 0x05, supportsNoAuth ? (byte)0x00 : (byte)0xFF }, cancellationToken).ConfigureAwait(false);
        await stream.FlushAsync(cancellationToken).ConfigureAwait(false);
        return supportsNoAuth;
    }

    private static async ValueTask<SocksRequest?> ReadRequestAsync(Stream stream, CancellationToken cancellationToken)
    {
        var header = new byte[4];
        if (!await ReadExactAsync(stream, header, cancellationToken).ConfigureAwait(false))
        {
            return null;
        }

        if (header[0] != 0x05)
        {
            return null;
        }

        var addressType = header[3];
        string host;
        switch (addressType)
        {
            case 0x01:
            {
                var buffer = new byte[4];
                if (!await ReadExactAsync(stream, buffer, cancellationToken).ConfigureAwait(false))
                {
                    return null;
                }

                host = new IPAddress(buffer).ToString();
                break;
            }
            case 0x03:
            {
                var lengthBuffer = new byte[1];
                if (!await ReadExactAsync(stream, lengthBuffer, cancellationToken).ConfigureAwait(false))
                {
                    return null;
                }

                var hostBuffer = new byte[lengthBuffer[0]];
                if (!await ReadExactAsync(stream, hostBuffer, cancellationToken).ConfigureAwait(false))
                {
                    return null;
                }

                host = System.Text.Encoding.ASCII.GetString(hostBuffer);
                break;
            }
            case 0x04:
            {
                var buffer = new byte[16];
                if (!await ReadExactAsync(stream, buffer, cancellationToken).ConfigureAwait(false))
                {
                    return null;
                }

                host = new IPAddress(buffer).ToString();
                break;
            }
            default:
                return null;
        }

        var portBuffer = new byte[2];
        if (!await ReadExactAsync(stream, portBuffer, cancellationToken).ConfigureAwait(false))
        {
            return null;
        }

        return new SocksRequest
        {
            Command = header[1],
            Host = host,
            Port = BinaryPrimitives.ReadUInt16BigEndian(portBuffer)
        };
    }

    private static Task SendReplyAsync(Stream stream, byte reply, CancellationToken cancellationToken)
        => stream.WriteAsync(
                new byte[]
                {
                    0x05,
                    reply,
                    0x00,
                    0x01,
                    0x00, 0x00, 0x00, 0x00,
                    0x00, 0x00
                },
                cancellationToken)
            .AsTask();

    private static async Task<bool> ReadExactAsync(Stream stream, byte[] buffer, CancellationToken cancellationToken)
    {
        var offset = 0;
        while (offset < buffer.Length)
        {
            var read = await stream.ReadAsync(buffer.AsMemory(offset, buffer.Length - offset), cancellationToken).ConfigureAwait(false);
            if (read == 0)
            {
                return false;
            }

            offset += read;
        }

        return true;
    }

    private static LocalProxyConnectionOptions CreateConnectionOptions(
        LocalProxyListenerDefinition listener,
        AcceptedConnection connection,
        LocalProxyServerLimits limits)
        => new()
        {
            InboundTag = listener.Tag,
            HandshakeTimeoutSeconds = listener.HandshakeTimeoutSeconds,
            ConnectTimeoutSeconds = limits.ConnectTimeoutSeconds,
            ConnectionIdleSeconds = limits.ConnectionIdleSeconds,
            UplinkOnlySeconds = limits.UplinkOnlySeconds,
            DownlinkOnlySeconds = limits.DownlinkOnlySeconds,
            RemoteEndPoint = connection.RemoteEndPoint,
            LocalEndPoint = connection.LocalEndPoint
        };

    private static Task WaitForCancellationAsync(CancellationToken cancellationToken)
        => Task.Delay(Timeout.InfiniteTimeSpan, cancellationToken);

    private sealed record ListenerRuntime(LocalProxyListenerDefinition Definition, ListenerHandle Handle);

    private sealed record SocksRequest
    {
        public byte Command { get; init; }

        public string Host { get; init; } = string.Empty;

        public int Port { get; init; }
    }

    private static class SocksCommand
    {
        public const byte Connect = 0x01;
    }

    private static class SocksReply
    {
        public const byte Succeeded = 0x00;

        public const byte CommandNotSupported = 0x07;
    }
}

using System.Buffers.Binary;
using System.Net;
using System.Net.Sockets;
using System.Text;

namespace NodePanel.Core.Runtime;

public class SocksInboundServer
{
    private const int MaxSocks4FieldBytes = 4 * 1024;

    private readonly IDispatcher _dispatcher;
    private readonly IRuntimeRelayService _relayService;
    private readonly IRuntimeSniffer _runtimeSniffer;

    public SocksInboundServer(IDispatcher dispatcher, IRuntimeRelayService relayService)
        : this(dispatcher, relayService, fakeDnsEngine: null)
    {
    }

    public SocksInboundServer(
        IDispatcher dispatcher,
        IRuntimeRelayService relayService,
        IFakeDnsEngine? fakeDnsEngine)
        : this(
            dispatcher,
            relayService,
            new DefaultRuntimeSniffer(fakeDnsEngine))
    {
    }

    internal SocksInboundServer(
        IDispatcher dispatcher,
        IRuntimeRelayService relayService,
        IRuntimeSniffer runtimeSniffer)
    {
        _dispatcher = dispatcher;
        _relayService = relayService;
        _runtimeSniffer = runtimeSniffer ?? throw new ArgumentNullException(nameof(runtimeSniffer));
    }

    public async Task RunAsync(SocksInboundServerOptions options, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(options);

        if (options.Listeners.Count == 0)
        {
            return;
        }

        var activeListeners = options.Listeners
            .Select(listener =>
            {
                var authentication = ResolveAuthentication(listener.Tag, options.AuthenticationsByTag);
                return new ListenerRuntime(
                    listener,
                    authentication,
                    TryCreateUdpAssociateRelay(listener, options.Limits, options.UseCone, authentication));
            })
            .ToArray();

        try
        {
            await InboundServerRuntimeSupport.RunAsync(
                activeListeners,
                static listener => listener.Definition.Binding,
                listener => options.Callbacks.ListenerStarted?.Invoke(listener.Definition),
                (listener, handle, token) => InboundServerRuntimeSupport.AcceptLoopAsync(
                    listener,
                    handle,
                    (connection, definition, innerToken) => HandleAcceptedConnectionAsync(connection, definition, options, innerToken),
                    token),
                "SOCKS proxy inbound accept loop ended unexpectedly.",
                cancellationToken).ConfigureAwait(false);
        }
        finally
        {
            foreach (var listener in activeListeners)
            {
                if (listener.UdpAssociateRelay is not null)
                {
                    await listener.UdpAssociateRelay.DisposeAsync().ConfigureAwait(false);
                }
            }
        }
    }

    private async Task HandleAcceptedConnectionAsync(
        AcceptedConnection connection,
        ListenerRuntime listener,
        SocksInboundServerOptions options,
        CancellationToken cancellationToken)
    {
        await using var connectionLease = connection;
        try
        {
            using var handshakeCts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
            handshakeCts.CancelAfter(TimeSpan.FromSeconds(listener.Definition.HandshakeTimeoutSeconds));

            var proxyOptions = CreateConnectionOptions(
                listener.Definition,
                connection,
                options.Limits,
                options.UseCone,
                string.Empty);

            var firstByte = await ReadByteAsync(connection.Stream, handshakeCts.Token).ConfigureAwait(false);
            if (firstByte is null)
            {
                return;
            }

            switch (firstByte.Value)
            {
                case Socks5ProtocolConstants.Version:
                    await HandleSocks5ConnectionAsync(
                            connection.Stream,
                            listener,
                            proxyOptions,
                            cancellationToken,
                            handshakeCts.Token)
                        .ConfigureAwait(false);
                    break;
                case Socks4ProtocolConstants.Version:
                    await HandleSocks4ConnectionAsync(
                            connection.Stream,
                            listener,
                            proxyOptions,
                            cancellationToken,
                            handshakeCts.Token)
                        .ConfigureAwait(false);
                    break;
                default:
                    await HandleHttpFallbackAsync(
                            connection.Stream,
                            listener,
                            proxyOptions,
                            firstByte.Value,
                            cancellationToken)
                        .ConfigureAwait(false);
                    break;
            }
        }
        catch (Exception ex) when (ex is not OperationCanceledException || !cancellationToken.IsCancellationRequested)
        {
            options.Callbacks.ConnectionError?.Invoke(new ProxyInboundConnectionErrorContext
            {
                Protocol = ProxyInboundProtocols.Socks,
                InboundTag = listener.Definition.Tag,
                Exception = ex,
                RemoteEndPoint = connection.LogRemoteEndPoint ?? connection.RemoteEndPoint
            });
        }
    }

    private async Task HandleSocks5ConnectionAsync(
        Stream clientStream,
        ListenerRuntime listener,
        ProxyInboundConnectionOptions proxyOptions,
        CancellationToken cancellationToken,
        CancellationToken handshakeCancellationToken)
    {
        var greeting = await PerformGreetingAsync(
            clientStream,
            listener.Authentication,
            handshakeCancellationToken).ConfigureAwait(false);
        if (greeting is null)
        {
            return;
        }

        var request = await ReadRequestAsync(clientStream, handshakeCancellationToken).ConfigureAwait(false);
        if (request is null)
        {
            return;
        }

        var authenticatedOptions = string.IsNullOrEmpty(greeting.UserId)
            ? proxyOptions
            : proxyOptions with
            {
                UserId = greeting.UserId,
                ScopedUserId = greeting.UserId
            };

        if (request.Command == Socks5ProtocolConstants.CommandUdpAssociate)
        {
            if (listener.UdpAssociateRelay is null)
            {
                await SendReplyAsync(
                    clientStream,
                    Socks5ProtocolConstants.ReplyCommandNotSupported,
                    handshakeCancellationToken).ConfigureAwait(false);
                return;
            }

            await listener.UdpAssociateRelay.RelayAsync(
                clientStream,
                authenticatedOptions,
                cancellationToken).ConfigureAwait(false);
            return;
        }

        if (request.Command != Socks5ProtocolConstants.CommandConnect)
        {
            await SendReplyAsync(
                clientStream,
                Socks5ProtocolConstants.ReplyCommandNotSupported,
                handshakeCancellationToken).ConfigureAwait(false);
            return;
        }

        await RelayTcpAsync(
                clientStream,
                request.Host,
                request.Port,
                authenticatedOptions,
                cancellationToken,
                static (stream, token) => SendReplyAsync(stream, Socks5ProtocolConstants.ReplySucceeded, token))
            .ConfigureAwait(false);
    }

    private async Task HandleSocks4ConnectionAsync(
        Stream clientStream,
        ListenerRuntime listener,
        ProxyInboundConnectionOptions proxyOptions,
        CancellationToken cancellationToken,
        CancellationToken handshakeCancellationToken)
    {
        if (listener.Authentication.Enabled)
        {
            await Socks4ReplyWriter.WriteAsync(
                    clientStream,
                    Socks4ProtocolConstants.ReplyRejected,
                    bindEndPoint: null,
                    handshakeCancellationToken)
                .ConfigureAwait(false);
            TryShutdownWrite(clientStream);
            return;
        }

        var command = await ReadByteAsync(clientStream, handshakeCancellationToken).ConfigureAwait(false);
        if (command is null)
        {
            return;
        }

        var request = await ReadSocks4RequestAsync(
            clientStream,
            command.Value,
            handshakeCancellationToken).ConfigureAwait(false);
        if (request is null)
        {
            return;
        }

        await RelayTcpAsync(
                clientStream,
                request.Host,
                request.Port,
                proxyOptions,
                cancellationToken,
                static (stream, token) => Socks4ReplyWriter.WriteAsync(
                    stream,
                    Socks4ProtocolConstants.ReplyGranted,
                    bindEndPoint: null,
                    token))
            .ConfigureAwait(false);
    }

    private Task HandleHttpFallbackAsync(
        Stream clientStream,
        ListenerRuntime listener,
        ProxyInboundConnectionOptions proxyOptions,
        byte firstByte,
        CancellationToken cancellationToken)
        => HttpInboundProcessor.HandleAsync(
            new PrefixedReadStream(clientStream, new byte[] { firstByte }),
            _dispatcher,
            _relayService,
            _runtimeSniffer,
            proxyOptions,
            cancellationToken,
            listener.Authentication);

    private async Task RelayTcpAsync(
        Stream clientStream,
        string host,
        int port,
        ProxyInboundConnectionOptions proxyOptions,
        CancellationToken cancellationToken,
        Func<Stream, CancellationToken, Task> writeAcceptedReplyAsync)
    {
        var destination = new DispatchDestination
        {
            Host = host,
            Port = port,
            Network = DispatchNetwork.Tcp
        };
        var context = RuntimeInboundDispatchContextFactory.Create(
            ProxyInboundProtocols.Socks,
            proxyOptions,
            RoutingNetworks.Tcp,
            userId: proxyOptions.UserId,
            scopedUserId: proxyOptions.ScopedUserId,
            network: RoutingNetworks.Tcp,
            originalDestinationHost: host,
            originalDestinationPort: port);

        await writeAcceptedReplyAsync(clientStream, cancellationToken).ConfigureAwait(false);

        var dispatchResult = await RuntimeTcpDispatchPipeline.DispatchAsync(
                _dispatcher,
                _runtimeSniffer,
                proxyOptions.Sniffing,
                clientStream,
                context,
                destination,
                cancellationToken,
                cancellationToken)
            .ConfigureAwait(false);

        await using var remoteStream = dispatchResult.OutboundStream;
        await _relayService
            .RelayAsync(
                dispatchResult.InboundStream,
                remoteStream,
                proxyOptions,
                cancellationToken)
            .ConfigureAwait(false);
    }

    private static async ValueTask<SocksGreetingResult?> PerformGreetingAsync(
        Stream stream,
        Socks5LocalAuthenticationOptions authentication,
        CancellationToken cancellationToken)
    {
        var methodCount = await ReadByteAsync(stream, cancellationToken).ConfigureAwait(false);
        if (methodCount is null)
        {
            return null;
        }

        var methods = new byte[methodCount.Value];
        if (!await ReadExactAsync(stream, methods, cancellationToken).ConfigureAwait(false))
        {
            return null;
        }

        var expectedMethod = authentication.Enabled
            ? Socks5ProtocolConstants.AuthenticationMethodUsernamePassword
            : Socks5ProtocolConstants.AuthenticationMethodNone;
        if (!methods.Contains(expectedMethod))
        {
            await WriteMethodSelectionAsync(
                stream,
                Socks5ProtocolConstants.AuthenticationMethodNoAcceptable,
                cancellationToken).ConfigureAwait(false);
            return null;
        }

        await WriteMethodSelectionAsync(stream, expectedMethod, cancellationToken).ConfigureAwait(false);

        if (!authentication.Enabled)
        {
            return new SocksGreetingResult();
        }

        var credentials = await ReadUsernamePasswordAsync(stream, cancellationToken).ConfigureAwait(false);
        if (credentials is null ||
            !authentication.TryAuthenticate(credentials.Username, credentials.Password))
        {
            await WriteAuthenticationStatusAsync(
                stream,
                Socks5ProtocolConstants.AuthenticationStatusFailed,
                cancellationToken).ConfigureAwait(false);
            return null;
        }

        await WriteAuthenticationStatusAsync(
            stream,
            Socks5ProtocolConstants.AuthenticationStatusSucceeded,
            cancellationToken).ConfigureAwait(false);
        return new SocksGreetingResult
        {
            UserId = credentials.Username
        };
    }

    private static async ValueTask<SocksRequest?> ReadRequestAsync(Stream stream, CancellationToken cancellationToken)
    {
        var header = new byte[4];
        if (!await ReadExactAsync(stream, header, cancellationToken).ConfigureAwait(false))
        {
            return null;
        }

        if (header[0] != Socks5ProtocolConstants.Version)
        {
            return null;
        }

        byte[]? addressTail;
        switch (header[3])
        {
            case 0x01:
                addressTail = await ReadBytesAsync(stream, 6, cancellationToken).ConfigureAwait(false);
                break;
            case 0x03:
                addressTail = await ReadDomainAddressTailAsync(stream, cancellationToken).ConfigureAwait(false);
                break;
            case 0x04:
                addressTail = await ReadBytesAsync(stream, 18, cancellationToken).ConfigureAwait(false);
                break;
            default:
                return null;
        }

        if (addressTail is null)
        {
            return null;
        }

        var targetBuffer = new byte[1 + addressTail.Length];
        targetBuffer[0] = header[3];
        addressTail.CopyTo(targetBuffer, 1);
        var target = Socks5AddressCodec.ReadAddressPort(targetBuffer);

        return new SocksRequest
        {
            Command = header[1],
            Host = target.Host,
            Port = target.Port
        };
    }

    private static async ValueTask<SocksRequest?> ReadSocks4RequestAsync(
        Stream stream,
        byte command,
        CancellationToken cancellationToken)
    {
        var destination = await ReadBytesAsync(stream, 6, cancellationToken).ConfigureAwait(false);
        if (destination is null)
        {
            return null;
        }

        if (await ReadNullTerminatedStringAsync(stream, cancellationToken).ConfigureAwait(false) is null)
        {
            return null;
        }

        if (command != Socks4ProtocolConstants.CommandConnect)
        {
            await Socks4ReplyWriter.WriteAsync(
                    stream,
                    Socks4ProtocolConstants.ReplyRejected,
                    bindEndPoint: null,
                    cancellationToken)
                .ConfigureAwait(false);
            TryShutdownWrite(stream);
            return null;
        }

        var port = BinaryPrimitives.ReadUInt16BigEndian(destination.AsSpan(0, 2));
        var addressBytes = destination.AsSpan(2, 4).ToArray();
        var host = addressBytes[0] == 0x00
            ? await ReadNullTerminatedStringAsync(stream, cancellationToken).ConfigureAwait(false)
            : new IPAddress(addressBytes).ToString();
        if (string.IsNullOrWhiteSpace(host))
        {
            await Socks4ReplyWriter.WriteAsync(
                    stream,
                    Socks4ProtocolConstants.ReplyRejected,
                    bindEndPoint: null,
                    cancellationToken)
                .ConfigureAwait(false);
            TryShutdownWrite(stream);
            return null;
        }

        return new SocksRequest
        {
            Command = command,
            Host = host,
            Port = port
        };
    }

    private static Task SendReplyAsync(Stream stream, byte reply, CancellationToken cancellationToken)
        => Socks5ReplyWriter.WriteAsync(stream, reply, bindEndPoint: null, cancellationToken);

    private static async ValueTask<SocksUsernamePasswordCredentials?> ReadUsernamePasswordAsync(
        Stream stream,
        CancellationToken cancellationToken)
    {
        var header = new byte[2];
        if (!await ReadExactAsync(stream, header, cancellationToken).ConfigureAwait(false))
        {
            return null;
        }

        if (header[0] != Socks5ProtocolConstants.AuthenticationVersionUsernamePassword)
        {
            return null;
        }

        var username = await ReadBytesAsync(stream, header[1], cancellationToken).ConfigureAwait(false);
        if (username is null)
        {
            return null;
        }

        var passwordLength = await ReadBytesAsync(stream, 1, cancellationToken).ConfigureAwait(false);
        if (passwordLength is null)
        {
            return null;
        }

        var password = await ReadBytesAsync(stream, passwordLength[0], cancellationToken).ConfigureAwait(false);
        if (password is null)
        {
            return null;
        }

        return new SocksUsernamePasswordCredentials(
            Encoding.UTF8.GetString(username),
            Encoding.UTF8.GetString(password));
    }

    private static Task WriteMethodSelectionAsync(
        Stream stream,
        byte method,
        CancellationToken cancellationToken)
        => WriteBytesAsync(
            stream,
            new byte[]
            {
                Socks5ProtocolConstants.Version,
                method
            },
            cancellationToken);

    private static Task WriteAuthenticationStatusAsync(
        Stream stream,
        byte status,
        CancellationToken cancellationToken)
        => WriteBytesAsync(
            stream,
            new byte[]
            {
                Socks5ProtocolConstants.AuthenticationVersionUsernamePassword,
                status
            },
            cancellationToken);

    private static async Task WriteBytesAsync(
        Stream stream,
        byte[] payload,
        CancellationToken cancellationToken)
    {
        await stream.WriteAsync(payload, cancellationToken).ConfigureAwait(false);
        await stream.FlushAsync(cancellationToken).ConfigureAwait(false);
    }

    private static async ValueTask<byte[]?> ReadDomainAddressTailAsync(
        Stream stream,
        CancellationToken cancellationToken)
    {
        var lengthBuffer = new byte[1];
        if (!await ReadExactAsync(stream, lengthBuffer, cancellationToken).ConfigureAwait(false))
        {
            return null;
        }

        var tail = new byte[1 + lengthBuffer[0] + 2];
        tail[0] = lengthBuffer[0];
        var remainder = await ReadBytesAsync(stream, tail.Length - 1, cancellationToken).ConfigureAwait(false);
        if (remainder is null)
        {
            return null;
        }

        remainder.CopyTo(tail, 1);

        return tail;
    }

    private static async ValueTask<byte?> ReadByteAsync(
        Stream stream,
        CancellationToken cancellationToken)
    {
        var buffer = await ReadBytesAsync(stream, 1, cancellationToken).ConfigureAwait(false);
        return buffer?[0];
    }

    private static async ValueTask<string?> ReadNullTerminatedStringAsync(
        Stream stream,
        CancellationToken cancellationToken)
    {
        var bytes = new List<byte>(32);

        while (bytes.Count < MaxSocks4FieldBytes)
        {
            var value = await ReadByteAsync(stream, cancellationToken).ConfigureAwait(false);
            if (value is null)
            {
                return null;
            }

            if (value.Value == 0x00)
            {
                return Encoding.ASCII.GetString(bytes.ToArray());
            }

            bytes.Add(value.Value);
        }

        return null;
    }

    private static async ValueTask<byte[]?> ReadBytesAsync(
        Stream stream,
        int length,
        CancellationToken cancellationToken)
    {
        var buffer = new byte[length];
        return await ReadExactAsync(stream, buffer, cancellationToken).ConfigureAwait(false)
            ? buffer
            : null;
    }

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

    private static ProxyInboundConnectionOptions CreateConnectionOptions(
        ProxyInboundListenerDefinition listener,
        AcceptedConnection connection,
        ProxyInboundServerLimits limits,
        bool useCone,
        string userId)
        => new()
        {
            InboundTag = listener.Tag,
            UserLevel = Math.Max(0, listener.UserLevel),
            UserId = userId,
            ScopedUserId = userId,
            HandshakeTimeoutSeconds = listener.HandshakeTimeoutSeconds,
            ConnectTimeoutSeconds = limits.ConnectTimeoutSeconds,
            ConnectionIdleSeconds = limits.ConnectionIdleSeconds,
            UplinkOnlySeconds = limits.UplinkOnlySeconds,
            DownlinkOnlySeconds = limits.DownlinkOnlySeconds,
            UseCone = useCone,
            Sniffing = listener.Sniffing ?? new RuntimeSniffingOptions(),
            RemoteEndPoint = connection.RemoteEndPoint,
            LocalEndPoint = connection.LocalEndPoint
        };

    private static Socks5LocalAuthenticationOptions ResolveAuthentication(
        string inboundTag,
        IReadOnlyDictionary<string, Socks5LocalAuthenticationOptions> authenticationsByTag)
    {
        if (!string.IsNullOrWhiteSpace(inboundTag) &&
            authenticationsByTag.TryGetValue(inboundTag, out var authentication) &&
            authentication is not null)
        {
            return authentication;
        }

        return Socks5LocalAuthenticationOptions.Disabled;
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

    private Socks5UdpAssociateRelay? TryCreateUdpAssociateRelay(
        ProxyInboundListenerDefinition listener,
        ProxyInboundServerLimits limits,
        bool useCone,
        Socks5LocalAuthenticationOptions authentication)
        => listener.Binding.IsUnix
            ? null
            : new Socks5UdpAssociateRelay(
                _dispatcher,
                _runtimeSniffer,
                listener.Binding,
                new ProxyInboundConnectionOptions
                {
                    InboundTag = listener.Tag,
                    UserLevel = Math.Max(0, listener.UserLevel),
                    HandshakeTimeoutSeconds = listener.HandshakeTimeoutSeconds,
                    ConnectTimeoutSeconds = limits.ConnectTimeoutSeconds,
                    ConnectionIdleSeconds = limits.ConnectionIdleSeconds,
                    UplinkOnlySeconds = limits.UplinkOnlySeconds,
                    DownlinkOnlySeconds = limits.DownlinkOnlySeconds,
                    UseCone = useCone,
                    Sniffing = listener.Sniffing ?? new RuntimeSniffingOptions()
                },
                authentication.Enabled);

    private sealed record ListenerRuntime(
        ProxyInboundListenerDefinition Definition,
        Socks5LocalAuthenticationOptions Authentication,
        Socks5UdpAssociateRelay? UdpAssociateRelay);

    private sealed record SocksRequest
    {
        public byte Command { get; init; }

        public string Host { get; init; } = string.Empty;

        public int Port { get; init; }
    }

    private sealed record SocksGreetingResult
    {
        public string UserId { get; init; } = string.Empty;
    }

    private sealed record SocksUsernamePasswordCredentials(string Username, string Password);
}

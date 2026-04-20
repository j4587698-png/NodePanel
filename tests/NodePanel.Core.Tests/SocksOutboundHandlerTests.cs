using System.Net;
using System.Net.Sockets;
using System.Text;
using NodePanel.Core.Runtime;

namespace NodePanel.Core.Tests;

public sealed class SocksOutboundHandlerTests
{
    [Fact]
    public async Task OpenTcpAsync_performs_connect_handshake_and_relays_payload()
    {
        using var lifetimeCts = new CancellationTokenSource(TimeSpan.FromSeconds(10));
        var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();
        var serverPort = ((IPEndPoint)listener.LocalEndpoint).Port;

        try
        {
            var serverTask = RunTcpServerAsync(
                listener,
                expectedCommand: Socks5ProtocolConstants.CommandConnect,
                expectedUsername: null,
                expectedPassword: null,
                lifetimeCts.Token,
                async (request, stream, token) =>
                {
                    Assert.Equal("target.example.com", request.Host);
                    Assert.Equal(443, request.Port);

                    var buffer = new byte[64];
                    var read = await stream.ReadAsync(buffer.AsMemory(0, buffer.Length), token);
                    await stream.WriteAsync(buffer.AsMemory(0, read), token);
                });

            var handler = CreateHandler(
                new RuntimeSocksOutboundOptions
                {
                    Tag = "socks-edge",
                    ServerHost = "127.0.0.1",
                    ServerPort = serverPort
                });

            await using var stream = await handler.OpenTcpAsync(
                new DispatchContext
                {
                    OutboundTag = "socks-edge"
                },
                new DispatchDestination
                {
                    Host = "target.example.com",
                    Port = 443,
                    Network = DispatchNetwork.Tcp
                },
                lifetimeCts.Token);

            var payload = Encoding.UTF8.GetBytes("hello-socks-connect");
            await stream.WriteAsync(payload, lifetimeCts.Token);

            var echoed = new byte[payload.Length];
            await ReadExactAsync(stream, echoed, lifetimeCts.Token);
            Assert.Equal(payload, echoed);

            await serverTask;
        }
        finally
        {
            listener.Stop();
        }
    }

    [Fact]
    public async Task OpenTcpAsync_supports_username_password_authentication()
    {
        using var lifetimeCts = new CancellationTokenSource(TimeSpan.FromSeconds(10));
        var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();
        var serverPort = ((IPEndPoint)listener.LocalEndpoint).Port;

        try
        {
            var serverTask = RunTcpServerAsync(
                listener,
                expectedCommand: Socks5ProtocolConstants.CommandConnect,
                expectedUsername: "alice",
                expectedPassword: "secret",
                lifetimeCts.Token,
                static (_, _, _) => Task.CompletedTask);

            var handler = CreateHandler(
                new RuntimeSocksOutboundOptions
                {
                    Tag = "socks-auth",
                    ServerHost = "127.0.0.1",
                    ServerPort = serverPort,
                    Username = "alice",
                    Password = "secret"
                });

            await using var stream = await handler.OpenTcpAsync(
                new DispatchContext
                {
                    OutboundTag = "socks-auth"
                },
                new DispatchDestination
                {
                    Host = "auth.example.com",
                    Port = 8443,
                    Network = DispatchNetwork.Tcp
                },
                lifetimeCts.Token);

            await stream.DisposeAsync();
            await serverTask;
        }
        finally
        {
            listener.Stop();
        }
    }

    [Fact]
    public async Task OpenUdpAsync_performs_udp_associate_and_relays_datagrams()
    {
        using var lifetimeCts = new CancellationTokenSource(TimeSpan.FromSeconds(10));
        var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();
        var serverPort = ((IPEndPoint)listener.LocalEndpoint).Port;
        using var udpSocket = new Socket(AddressFamily.InterNetwork, SocketType.Dgram, ProtocolType.Udp);
        udpSocket.Bind(new IPEndPoint(IPAddress.Loopback, 0));

        try
        {
            var serverTask = RunUdpAssociateServerAsync(listener, udpSocket, lifetimeCts.Token);
            var handler = CreateHandler(
                new RuntimeSocksOutboundOptions
                {
                    Tag = "socks-udp",
                    ServerHost = "127.0.0.1",
                    ServerPort = serverPort
                });

            await using var transport = await handler.OpenUdpAsync(
                new DispatchContext
                {
                    OutboundTag = "socks-udp"
                },
                lifetimeCts.Token);

            var payload = Encoding.UTF8.GetBytes("hello-socks-udp");
            await transport.SendAsync(
                new DispatchDestination
                {
                    Host = "udp.example.com",
                    Port = 53,
                    Network = DispatchNetwork.Udp
                },
                payload,
                lifetimeCts.Token);

            var datagram = await transport.ReceiveAsync(lifetimeCts.Token);
            Assert.NotNull(datagram);
            Assert.Equal("udp.example.com", datagram!.SourceHost);
            Assert.Equal(53, datagram.SourcePort);
            Assert.Equal(payload, datagram.Payload);

            await serverTask;
        }
        finally
        {
            udpSocket.Dispose();
            listener.Stop();
        }
    }

    private static SocksOutboundHandler CreateHandler(RuntimeSocksOutboundOptions settings)
        => new(
            new StaticCommonSettingsProvider(new OutboundCommonSettings
            {
                Tag = settings.Tag,
                Protocol = OutboundProtocols.Socks
            }),
            new StaticRuntimeSettingsProvider(settings));

    private static async Task RunTcpServerAsync(
        TcpListener listener,
        byte expectedCommand,
        string? expectedUsername,
        string? expectedPassword,
        CancellationToken cancellationToken,
        Func<SocksServerRequest, Stream, CancellationToken, Task> continuation)
    {
        using var client = await listener.AcceptTcpClientAsync(cancellationToken);
        await using var stream = client.GetStream();

        var methods = await ReadGreetingMethodsAsync(stream, cancellationToken);
        if (expectedUsername is null)
        {
            Assert.Contains(Socks5ProtocolConstants.AuthenticationMethodNone, methods);
            await stream.WriteAsync(
                new byte[] { Socks5ProtocolConstants.Version, Socks5ProtocolConstants.AuthenticationMethodNone },
                cancellationToken);
        }
        else
        {
            Assert.Contains(Socks5ProtocolConstants.AuthenticationMethodUsernamePassword, methods);
            await stream.WriteAsync(
                new byte[] { Socks5ProtocolConstants.Version, Socks5ProtocolConstants.AuthenticationMethodUsernamePassword },
                cancellationToken);

            var credentials = await ReadCredentialsAsync(stream, cancellationToken);
            Assert.Equal(expectedUsername, credentials.Username);
            Assert.Equal(expectedPassword, credentials.Password);
            await stream.WriteAsync(
                new byte[]
                {
                    Socks5ProtocolConstants.AuthenticationVersionUsernamePassword,
                    Socks5ProtocolConstants.AuthenticationStatusSucceeded
                },
                cancellationToken);
        }

        var request = await ReadRequestAsync(stream, cancellationToken);
        Assert.Equal(expectedCommand, request.Command);

        await Socks5ReplyWriter.WriteAsync(
            stream,
            Socks5ProtocolConstants.ReplySucceeded,
            new IPEndPoint(IPAddress.Loopback, 32001),
            cancellationToken);

        await continuation(request, stream, cancellationToken);
    }

    private static async Task RunUdpAssociateServerAsync(
        TcpListener listener,
        Socket udpSocket,
        CancellationToken cancellationToken)
    {
        using var client = await listener.AcceptTcpClientAsync(cancellationToken);
        await using var stream = client.GetStream();

        var methods = await ReadGreetingMethodsAsync(stream, cancellationToken);
        Assert.Contains(Socks5ProtocolConstants.AuthenticationMethodNone, methods);
        await stream.WriteAsync(
            new byte[] { Socks5ProtocolConstants.Version, Socks5ProtocolConstants.AuthenticationMethodNone },
            cancellationToken);

        var request = await ReadRequestAsync(stream, cancellationToken);
        Assert.Equal(Socks5ProtocolConstants.CommandUdpAssociate, request.Command);
        Assert.Equal("udp.example.com", request.Host);
        Assert.Equal(53, request.Port);

        await Socks5ReplyWriter.WriteAsync(
            stream,
            Socks5ProtocolConstants.ReplySucceeded,
            udpSocket.LocalEndPoint,
            cancellationToken);

        var buffer = new byte[65535];
        var received = await udpSocket.ReceiveFromAsync(
            buffer.AsMemory(0, buffer.Length),
            SocketFlags.None,
            new IPEndPoint(IPAddress.Any, 0),
            cancellationToken);
        var packet = Socks5UdpPacketCodec.Decode(buffer.AsSpan(0, received.ReceivedBytes));
        Assert.Equal("udp.example.com", packet.Host);
        Assert.Equal(53, packet.Port);
        Assert.Equal("hello-socks-udp", Encoding.UTF8.GetString(packet.Payload));

        var response = Socks5UdpPacketCodec.Encode(packet.Host, packet.Port, packet.Payload);
        await udpSocket.SendToAsync(
            response,
            SocketFlags.None,
            received.RemoteEndPoint,
            cancellationToken);
    }

    private static async Task<byte[]> ReadGreetingMethodsAsync(Stream stream, CancellationToken cancellationToken)
    {
        var header = new byte[2];
        await ReadExactAsync(stream, header, cancellationToken);
        Assert.Equal(Socks5ProtocolConstants.Version, header[0]);

        var methods = new byte[header[1]];
        await ReadExactAsync(stream, methods, cancellationToken);
        return methods;
    }

    private static async Task<SocksCredentials> ReadCredentialsAsync(Stream stream, CancellationToken cancellationToken)
    {
        var header = new byte[2];
        await ReadExactAsync(stream, header, cancellationToken);
        Assert.Equal(Socks5ProtocolConstants.AuthenticationVersionUsernamePassword, header[0]);

        var username = new byte[header[1]];
        await ReadExactAsync(stream, username, cancellationToken);

        var passwordLength = new byte[1];
        await ReadExactAsync(stream, passwordLength, cancellationToken);

        var password = new byte[passwordLength[0]];
        await ReadExactAsync(stream, password, cancellationToken);

        return new SocksCredentials(
            Encoding.UTF8.GetString(username),
            Encoding.UTF8.GetString(password));
    }

    private static async Task<SocksServerRequest> ReadRequestAsync(Stream stream, CancellationToken cancellationToken)
    {
        var header = new byte[4];
        await ReadExactAsync(stream, header, cancellationToken);
        Assert.Equal(Socks5ProtocolConstants.Version, header[0]);
        Assert.Equal(0x00, header[2]);

        var address = await SocksOutboundHandler.ReadAddressPortAsync(stream, header[3], cancellationToken);
        return new SocksServerRequest(header[1], address.Host, address.Port);
    }

    private static async Task ReadExactAsync(Stream stream, byte[] buffer, CancellationToken cancellationToken)
        => await SocksOutboundHandler.ReadExactOrThrowAsync(stream, buffer, cancellationToken);

    private sealed class StaticCommonSettingsProvider : IOutboundCommonSettingsProvider
    {
        private readonly OutboundCommonSettings _settings;

        public StaticCommonSettingsProvider(OutboundCommonSettings settings)
        {
            _settings = settings;
        }

        public bool TryResolve(DispatchContext context, out OutboundCommonSettings settings)
        {
            settings = _settings;
            return true;
        }
    }

    private sealed class StaticRuntimeSettingsProvider : IRuntimeOutboundSettingsProvider
    {
        private readonly IRuntimeOutboundOptions _settings;

        public StaticRuntimeSettingsProvider(IRuntimeOutboundOptions settings)
        {
            _settings = settings;
        }

        public bool TryResolve(DispatchContext context, out IRuntimeOutboundOptions settings)
        {
            settings = _settings;
            return true;
        }

        public bool TryResolve<TOptions>(DispatchContext context, out TOptions settings)
            where TOptions : class, IRuntimeOutboundOptions
        {
            if (_settings is TOptions typed)
            {
                settings = typed;
                return true;
            }

            settings = default!;
            return false;
        }
    }

    private sealed record SocksServerRequest(byte Command, string Host, int Port);

    private sealed record SocksCredentials(string Username, string Password);
}

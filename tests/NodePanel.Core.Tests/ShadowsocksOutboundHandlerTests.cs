using System.Net;
using System.Net.Sockets;
using System.Text;
using NodePanel.Core.Protocol;
using NodePanel.Core.Runtime;

namespace NodePanel.Core.Tests;

public sealed class ShadowsocksOutboundHandlerTests
{
    [Theory]
    [InlineData(ShadowsocksCipherTypes.ChaCha20Poly1305)]
    [InlineData(ShadowsocksCipherTypes.XChaCha20Poly1305)]
    public async Task OpenTcpAsync_performs_shadowsocks_handshake_and_relays_payload(string cipher)
    {
        using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(10));
        using var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();
        var serverPort = ((IPEndPoint)listener.LocalEndpoint).Port;
        var account = ShadowsocksAccount.Create(cipher, "secret");
        var payload = Encoding.ASCII.GetBytes("hello-ss-connect");

        var serverTask = Task.Run(async () =>
        {
            using var accepted = await listener.AcceptTcpClientAsync(cts.Token);
            await using var serverStream = accepted.GetStream();
            var session = await ShadowsocksProtocolCodec.AcceptServerTcpStreamAsync(serverStream, account, cts.Token);

            Assert.Equal("target.example.com", session.Destination.Host);
            Assert.Equal(443, session.Destination.Port);

            await using var tunneled = session.Stream;
            var buffer = new byte[payload.Length];
            await ReadExactAsync(tunneled, buffer, cts.Token);
            await tunneled.WriteAsync(buffer, cts.Token);
            await tunneled.FlushAsync(cts.Token);
        }, cts.Token);

        var handler = CreateHandler(
            new RuntimeShadowsocksOutboundOptions
            {
                Tag = "ss-edge",
                ServerHost = "127.0.0.1",
                ServerPort = serverPort,
                Cipher = cipher,
                Password = "secret"
            });

        await using var stream = await handler.OpenTcpAsync(
            new DispatchContext
            {
                OutboundTag = "ss-edge"
            },
            new DispatchDestination
            {
                Host = "target.example.com",
                Port = 443,
                Network = DispatchNetwork.Tcp
            },
            cts.Token);

        await stream.WriteAsync(payload, cts.Token);
        await stream.FlushAsync(cts.Token);

        var echoed = new byte[payload.Length];
        await ReadExactAsync(stream, echoed, cts.Token);
        Assert.Equal(payload, echoed);

        await serverTask;
    }

    [Fact]
    public async Task OpenTcpAsync_presends_initial_payload()
    {
        using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(10));
        using var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();
        var serverPort = ((IPEndPoint)listener.LocalEndpoint).Port;
        var account = ShadowsocksAccount.Create(ShadowsocksCipherTypes.Aes128Gcm, "secret");
        var initialPayload = Encoding.ASCII.GetBytes("prefetch-ss");

        var serverTask = Task.Run(async () =>
        {
            using var accepted = await listener.AcceptTcpClientAsync(cts.Token);
            await using var serverStream = accepted.GetStream();
            var session = await ShadowsocksProtocolCodec.AcceptServerTcpStreamAsync(serverStream, account, cts.Token);

            Assert.Equal("secure.example.com", session.Destination.Host);
            Assert.Equal(8443, session.Destination.Port);

            await using var tunneled = session.Stream;
            var buffer = new byte[initialPayload.Length];
            await ReadExactAsync(tunneled, buffer, cts.Token);
            Assert.Equal(initialPayload, buffer);
            await tunneled.WriteAsync(buffer, cts.Token);
            await tunneled.FlushAsync(cts.Token);
        }, cts.Token);

        var handler = CreateHandler(
            new RuntimeShadowsocksOutboundOptions
            {
                Tag = "ss-initial",
                ServerHost = "127.0.0.1",
                ServerPort = serverPort,
                Cipher = ShadowsocksCipherTypes.Aes128Gcm,
                Password = "secret"
            });

        await using var stream = await handler.OpenTcpAsync(
            new DispatchContext
            {
                OutboundTag = "ss-initial",
                InitialPayload = initialPayload
            },
            new DispatchDestination
            {
                Host = "secure.example.com",
                Port = 8443,
                Network = DispatchNetwork.Tcp
            },
            cts.Token);

        var echoed = new byte[initialPayload.Length];
        await ReadExactAsync(stream, echoed, cts.Token);
        Assert.Equal(initialPayload, echoed);

        await serverTask;
    }

    [Theory]
    [InlineData(ShadowsocksCipherTypes.ChaCha20Poly1305)]
    [InlineData(ShadowsocksCipherTypes.XChaCha20Poly1305)]
    public async Task OpenUdpAsync_encodes_and_decodes_datagrams(string cipher)
    {
        using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(10));
        using var udpSocket = new Socket(AddressFamily.InterNetwork, SocketType.Dgram, ProtocolType.Udp);
        udpSocket.Bind(new IPEndPoint(IPAddress.Loopback, 0));
        var serverPort = ((IPEndPoint)udpSocket.LocalEndPoint!).Port;
        var account = ShadowsocksAccount.Create(cipher, "secret");
        var payload = Encoding.ASCII.GetBytes("hello-ss-udp");

        var serverTask = Task.Run(async () =>
        {
            var buffer = new byte[65535];
            var received = await udpSocket.ReceiveFromAsync(
                buffer.AsMemory(0, buffer.Length),
                SocketFlags.None,
                new IPEndPoint(IPAddress.Any, 0),
                cts.Token);
            var packet = ShadowsocksProtocolCodec.DecodeUdpPacket(account, buffer.AsSpan(0, received.ReceivedBytes));
            Assert.Equal("udp.example.com", packet.Host);
            Assert.Equal(53, packet.Port);
            Assert.Equal(payload, packet.Payload);

            var response = ShadowsocksProtocolCodec.EncodeUdpPacket(
                account,
                packet.Host,
                packet.Port,
                packet.Payload);
            await udpSocket.SendToAsync(response, SocketFlags.None, received.RemoteEndPoint, cts.Token);
        }, cts.Token);

        var handler = CreateHandler(
            new RuntimeShadowsocksOutboundOptions
            {
                Tag = "ss-udp",
                ServerHost = "127.0.0.1",
                ServerPort = serverPort,
                Cipher = cipher,
                Password = "secret"
            });

        await using var transport = await handler.OpenUdpAsync(
            new DispatchContext
            {
                OutboundTag = "ss-udp"
            },
            cts.Token);

        await transport.SendAsync(
            new DispatchDestination
            {
                Host = "udp.example.com",
                Port = 53,
                Network = DispatchNetwork.Udp
            },
            payload,
            cts.Token);

        var datagram = await transport.ReceiveAsync(cts.Token);
        Assert.NotNull(datagram);
        Assert.Equal("udp.example.com", datagram!.SourceHost);
        Assert.Equal(53, datagram.SourcePort);
        Assert.Equal(payload, datagram.Payload);

        await serverTask;
    }

    [Fact]
    public void RuntimeCapabilities_contains_shadowsocks_outbound()
        => Assert.Contains(OutboundProtocols.Shadowsocks, RuntimeCapabilities.SupportedOutboundProtocols);

    [Fact]
    public async Task OpenTcpAsync_rejects_shadowsocks_2022_on_legacy_handler()
    {
        var handler = CreateHandler(
            new RuntimeShadowsocksOutboundOptions
            {
                Tag = "ss-2022",
                ServerHost = "127.0.0.1",
                ServerPort = 8388,
                Cipher = ShadowsocksCipherTypes.Blake3Aes128Gcm,
                Password = Convert.ToBase64String(new byte[16])
            });

        var exception = await Assert.ThrowsAsync<NotSupportedException>(() => handler.OpenTcpAsync(
            new DispatchContext
            {
                OutboundTag = "ss-2022"
            },
            new DispatchDestination
            {
                Host = "example.com",
                Port = 443,
                Network = DispatchNetwork.Tcp
            },
            CancellationToken.None).AsTask());

        Assert.Contains("Shadowsocks 2022", exception.Message, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void ResolveSettings_ignores_udp_over_tcp_on_regular_shadowsocks()
    {
        var handler = CreateHandler(
            new RuntimeShadowsocksOutboundOptions
            {
                Tag = "ss-uot",
                ServerHost = "127.0.0.1",
                ServerPort = 8388,
                Cipher = ShadowsocksCipherTypes.Aes256Gcm,
                Password = "secret",
                UdpOverTcp = true,
                UdpOverTcpVersion = 2
            });

        var settings = handler.ResolveSettings(new DispatchContext
        {
            OutboundTag = "ss-uot"
        });

        Assert.False(settings.Outbound.UdpOverTcp);
        Assert.Equal(0, settings.Outbound.UdpOverTcpVersion);
    }

    private static ShadowsocksOutboundHandler CreateHandler(RuntimeShadowsocksOutboundOptions settings)
        => new(
            new StaticCommonSettingsProvider(new OutboundCommonSettings
            {
                Tag = settings.Tag,
                Protocol = OutboundProtocols.Shadowsocks
            }),
            new StaticRuntimeSettingsProvider(settings));

    private static async Task ReadExactAsync(Stream stream, byte[] buffer, CancellationToken cancellationToken)
    {
        var offset = 0;
        while (offset < buffer.Length)
        {
            var read = await stream.ReadAsync(buffer.AsMemory(offset, buffer.Length - offset), cancellationToken);
            if (read == 0)
            {
                throw new EndOfStreamException("Unexpected EOF while reading Shadowsocks test payload.");
            }

            offset += read;
        }
    }

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
}

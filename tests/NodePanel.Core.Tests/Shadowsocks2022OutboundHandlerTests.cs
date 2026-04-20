using System.Net;
using System.Net.Sockets;
using System.Text;
using NodePanel.Core.Protocol;
using NodePanel.Core.Runtime;

namespace NodePanel.Core.Tests;

public sealed class Shadowsocks2022OutboundHandlerTests
{
    private static readonly string TestKey = CreateTestKey(ShadowsocksCipherTypes.Blake3Aes256Gcm);

    [Fact]
    public void ResolveSettings_translates_runtime_plan_into_protocol_settings()
    {
        var planState = new RuntimePlanState();
        planState.Apply(new RuntimePlan
        {
            Plan = new NodeRuntimePlan
            {
                Outbound = new OutboundRuntimePlan
                {
                    DefaultOutboundTag = "ss-2022",
                    Outbounds =
                    [
                        new OutboundRuntime
                        {
                            Tag = "ss-2022",
                            Protocol = OutboundProtocols.Shadowsocks,
                            Via = "eth0",
                            ViaCidr = "10.0.0.0/24",
                            TargetStrategy = OutboundTargetStrategies.UseIpv4,
                            ProxyOutboundTag = "proxy-1"
                        }
                    ]
                }
            },
            OutboundSettings = RuntimeOutboundSettingsCatalog.Create(
            [
                new RuntimeShadowsocks2022OutboundOptions
                {
                    Tag = "ss-2022",
                    ServerHost = " server.example.com ",
                    ServerPort = 9443,
                    Method = " 2022-blake3-aes-128-gcm ",
                    Key = " secret-key ",
                    UdpOverTcp = true,
                    UdpOverTcpVersion = 2,
                    ConnectTimeoutSeconds = 15
                }
            ])
        });

        var handler = new Shadowsocks2022OutboundHandler(
            new Shadowsocks2022OutboundClient(),
            planState,
            planState);

        var settings = handler.ResolveSettings(new DispatchContext
        {
            OutboundTag = "ss-2022"
        });

        Assert.Equal("ss-2022", settings.Tag);
        Assert.Equal("eth0", settings.Via);
        Assert.Equal("10.0.0.0/24", settings.ViaCidr);
        Assert.Equal(OutboundTargetStrategies.UseIpv4, settings.TargetStrategy);
        Assert.Equal("proxy-1", settings.ProxyOutboundTag);
        Assert.Equal("server.example.com", settings.ServerHost);
        Assert.Equal(9443, settings.ServerPort);
        Assert.Equal(ShadowsocksCipherTypes.Blake3Aes128Gcm, settings.Method);
        Assert.Equal("secret-key", settings.Key);
        Assert.True(settings.UdpOverTcp);
        Assert.Equal(2, settings.UdpOverTcpVersion);
        Assert.Equal(15, settings.ConnectTimeoutSeconds);
    }

    [Fact]
    public void ResolveSettings_can_resolve_2022_method_from_legacy_runtime_container()
    {
        var planState = new RuntimePlanState();
        planState.Apply(new RuntimePlan
        {
            Plan = new NodeRuntimePlan
            {
                Outbound = new OutboundRuntimePlan
                {
                    DefaultOutboundTag = "ss-2022",
                    Outbounds =
                    [
                        new OutboundRuntime
                        {
                            Tag = "ss-2022",
                            Protocol = OutboundProtocols.Shadowsocks
                        }
                    ]
                }
            },
            OutboundSettings = RuntimeOutboundSettingsCatalog.Create(
            [
                new RuntimeShadowsocksOutboundOptions
                {
                    Tag = "ss-2022",
                    ServerHost = " server.example.com ",
                    ServerPort = 8388,
                    Cipher = " 2022-blake3-aes-256-gcm ",
                    Password = $" {CreateTestKey(ShadowsocksCipherTypes.Blake3Aes256Gcm)} ",
                    UdpOverTcp = true,
                    UdpOverTcpVersion = 2
                }
            ])
        });

        var handler = new Shadowsocks2022OutboundHandler(
            new Shadowsocks2022OutboundClient(),
            planState,
            planState);

        var settings = handler.ResolveSettings(new DispatchContext
        {
            OutboundTag = "ss-2022"
        });

        Assert.Equal(ShadowsocksCipherTypes.Blake3Aes256Gcm, settings.Method);
        Assert.True(settings.UdpOverTcp);
        Assert.Equal(2, settings.UdpOverTcpVersion);
    }

    [Theory]
    [InlineData(ShadowsocksCipherTypes.Blake3Aes128Gcm)]
    [InlineData(ShadowsocksCipherTypes.Blake3Aes256Gcm)]
    [InlineData(ShadowsocksCipherTypes.Blake3ChaCha20Poly1305)]
    public async Task OpenTcpAsync_performs_shadowsocks_2022_handshake_and_relays_payload(string method)
    {
        using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(10));
        using var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();
        var serverPort = ((IPEndPoint)listener.LocalEndpoint).Port;
        var key = CreateTestKey(method);
        var account = Shadowsocks2022Account.Create(method, key);
        var payload = Encoding.ASCII.GetBytes("hello-ss2022-connect");

        var serverTask = Task.Run(async () =>
        {
            using var accepted = await listener.AcceptTcpClientAsync(cts.Token);
            await using var serverStream = accepted.GetStream();
            var session = await Shadowsocks2022ProtocolCodec.AcceptServerTcpStreamAsync(serverStream, account, cts.Token);

            Assert.Equal("target.example.com", session.Destination.Host);
            Assert.Equal(443, session.Destination.Port);

            await using var tunneled = session.Stream;
            var buffer = new byte[payload.Length];
            await ReadExactAsync(tunneled, buffer, cts.Token);
            await tunneled.WriteAsync(buffer, cts.Token);
            await tunneled.FlushAsync(cts.Token);
        }, cts.Token);

        var handler = CreateHandler(new Shadowsocks2022OutboundSettings
        {
            Tag = "ss-2022",
            ServerHost = "127.0.0.1",
            ServerPort = serverPort,
            Method = method,
            Key = key
        });

        await using var stream = await handler.OpenTcpAsync(
            new DispatchContext
            {
                OutboundTag = "ss-2022"
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
        var key = CreateTestKey(ShadowsocksCipherTypes.Blake3Aes128Gcm);
        var account = Shadowsocks2022Account.Create(ShadowsocksCipherTypes.Blake3Aes128Gcm, key);
        var initialPayload = Encoding.ASCII.GetBytes("prefetch-ss2022");

        var serverTask = Task.Run(async () =>
        {
            using var accepted = await listener.AcceptTcpClientAsync(cts.Token);
            await using var serverStream = accepted.GetStream();
            var session = await Shadowsocks2022ProtocolCodec.AcceptServerTcpStreamAsync(serverStream, account, cts.Token);

            Assert.Equal("secure.example.com", session.Destination.Host);
            Assert.Equal(8443, session.Destination.Port);

            await using var tunneled = session.Stream;
            var buffer = new byte[initialPayload.Length];
            await ReadExactAsync(tunneled, buffer, cts.Token);
            Assert.Equal(initialPayload, buffer);
            await tunneled.WriteAsync(buffer, cts.Token);
            await tunneled.FlushAsync(cts.Token);
        }, cts.Token);

        var handler = CreateHandler(new Shadowsocks2022OutboundSettings
        {
            Tag = "ss-2022-initial",
            ServerHost = "127.0.0.1",
            ServerPort = serverPort,
            Method = ShadowsocksCipherTypes.Blake3Aes128Gcm,
            Key = key
        });

        await using var stream = await handler.OpenTcpAsync(
            new DispatchContext
            {
                OutboundTag = "ss-2022-initial",
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
    [InlineData(ShadowsocksCipherTypes.Blake3Aes128Gcm)]
    [InlineData(ShadowsocksCipherTypes.Blake3Aes256Gcm)]
    [InlineData(ShadowsocksCipherTypes.Blake3ChaCha20Poly1305)]
    public async Task OpenUdpAsync_encodes_and_decodes_datagrams(string method)
    {
        using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(10));
        using var udpSocket = new Socket(AddressFamily.InterNetwork, SocketType.Dgram, ProtocolType.Udp);
        udpSocket.Bind(new IPEndPoint(IPAddress.Loopback, 0));
        var serverPort = ((IPEndPoint)udpSocket.LocalEndPoint!).Port;
        var key = CreateTestKey(method);
        var account = Shadowsocks2022Account.Create(method, key);
        var payload = Encoding.ASCII.GetBytes("hello-ss2022-udp");

        var serverTask = Task.Run(async () =>
        {
            var buffer = new byte[65535];
            var received = await udpSocket.ReceiveFromAsync(
                buffer.AsMemory(0, buffer.Length),
                SocketFlags.None,
                new IPEndPoint(IPAddress.Any, 0),
                cts.Token);
            var packet = Shadowsocks2022ProtocolCodec.DecodeUdpPacket(account, buffer.AsSpan(0, received.ReceivedBytes));
            Assert.Equal("udp.example.com", packet.Host);
            Assert.Equal(53, packet.Port);
            Assert.Equal(payload, packet.Payload);

            var response = Shadowsocks2022ProtocolCodec.EncodeUdpPacket(
                account,
                packet.Host,
                packet.Port,
                packet.Payload);
            await udpSocket.SendToAsync(response, SocketFlags.None, received.RemoteEndPoint, cts.Token);
        }, cts.Token);

        var handler = CreateHandler(new Shadowsocks2022OutboundSettings
        {
            Tag = "ss-2022-udp",
            ServerHost = "127.0.0.1",
            ServerPort = serverPort,
            Method = method,
            Key = key
        });

        await using var transport = await handler.OpenUdpAsync(
            new DispatchContext
            {
                OutboundTag = "ss-2022-udp"
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

    [Theory]
    [InlineData(0)]
    [InlineData(1)]
    [InlineData(2)]
    public async Task OpenUdpAsync_supports_udp_over_tcp(int uotVersion)
    {
        using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(10));
        using var udpEchoSocket = new Socket(AddressFamily.InterNetwork, SocketType.Dgram, ProtocolType.Udp);
        udpEchoSocket.Bind(new IPEndPoint(IPAddress.Loopback, 0));
        var udpEchoPort = ((IPEndPoint)udpEchoSocket.LocalEndPoint!).Port;

        var udpServerTask = Task.Run(async () =>
        {
            var buffer = new byte[65535];
            var received = await udpEchoSocket.ReceiveFromAsync(
                buffer.AsMemory(0, buffer.Length),
                SocketFlags.None,
                new IPEndPoint(IPAddress.Any, 0),
                cts.Token);
            await udpEchoSocket.SendToAsync(
                buffer.AsMemory(0, received.ReceivedBytes),
                SocketFlags.None,
                received.RemoteEndPoint,
                cts.Token);
        }, cts.Token);

        using var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();
        var serverPort = ((IPEndPoint)listener.LocalEndpoint).Port;
        var key = CreateTestKey(ShadowsocksCipherTypes.Blake3Aes256Gcm);
        var account = Shadowsocks2022Account.Create(ShadowsocksCipherTypes.Blake3Aes256Gcm, key);
        var payload = Encoding.ASCII.GetBytes("hello-ss2022-uot");

        var serverTask = Task.Run(async () =>
        {
            using var accepted = await listener.AcceptTcpClientAsync(cts.Token);
            await using var serverStream = accepted.GetStream();
            var session = await Shadowsocks2022ProtocolCodec.AcceptServerTcpStreamAsync(serverStream, account, cts.Token);

            var expectedRequest = UdpOverTcpProtocol.CreateRequestDestination(uotVersion);
            Assert.Equal(expectedRequest.Host, session.Destination.Host);
            Assert.Equal(expectedRequest.Port, session.Destination.Port);

            await using var tunneled = session.Stream;
            var request = await UdpOverTcpProtocol.ReadRequestAsync(tunneled, uotVersion, cts.Token);
            Assert.False(request.IsConnect);
            Assert.Equal("127.0.0.1", request.Destination.Host);
            Assert.Equal(udpEchoPort, request.Destination.Port);

            using var relaySocket = new Socket(AddressFamily.InterNetwork, SocketType.Dgram, ProtocolType.Udp);
            await relaySocket.ConnectAsync(IPAddress.Loopback, udpEchoPort, cts.Token);

            var requestPayload = await UdpOverTcpProtocol.ReadPacketAsync(tunneled, cts.Token);
            Assert.NotNull(requestPayload);
            Assert.Equal(payload, requestPayload!);

            await relaySocket.SendAsync(requestPayload, SocketFlags.None, cts.Token);
            var responseBuffer = new byte[requestPayload!.Length];
            var responseRead = await relaySocket.ReceiveAsync(responseBuffer, SocketFlags.None, cts.Token);

            await UdpOverTcpProtocol.WritePacketAsync(
                tunneled,
                responseBuffer.AsMemory(0, responseRead),
                cts.Token);
            await tunneled.FlushAsync(cts.Token);
        }, cts.Token);

        var handler = CreateHandler(new Shadowsocks2022OutboundSettings
        {
            Tag = "ss-2022-uot",
            ServerHost = "127.0.0.1",
            ServerPort = serverPort,
            Method = ShadowsocksCipherTypes.Blake3Aes256Gcm,
            Key = key,
            UdpOverTcp = true,
            UdpOverTcpVersion = uotVersion
        });

        await using var transport = await handler.OpenUdpAsync(
            new DispatchContext
            {
                OutboundTag = "ss-2022-uot"
            },
            cts.Token);

        await transport.SendAsync(
            new DispatchDestination
            {
                Host = "127.0.0.1",
                Port = udpEchoPort,
                Network = DispatchNetwork.Udp
            },
            payload,
            cts.Token);

        var datagram = await transport.ReceiveAsync(cts.Token);
        Assert.NotNull(datagram);
        Assert.Equal("127.0.0.1", datagram!.SourceHost);
        Assert.Equal(udpEchoPort, datagram.SourcePort);
        Assert.Equal(payload, datagram.Payload);

        await serverTask;
        await udpServerTask;
    }

    [Fact]
    public async Task OpenTcpAsync_rejects_non_2022_method()
    {
        var handler = CreateHandler(new Shadowsocks2022OutboundSettings
        {
            Tag = "ss-2022",
            ServerHost = "127.0.0.1",
            ServerPort = 8388,
            Method = ShadowsocksCipherTypes.Aes128Gcm,
            Key = TestKey
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

        Assert.Equal("Unsupported Shadowsocks 2022 method: aes-128-gcm.", exception.Message);
    }

    [Fact]
    public async Task OpenTcpAsync_rejects_invalid_key_length()
    {
        var handler = CreateHandler(new Shadowsocks2022OutboundSettings
        {
            Tag = "ss-2022",
            ServerHost = "127.0.0.1",
            ServerPort = 8388,
            Method = ShadowsocksCipherTypes.Blake3Aes128Gcm,
            Key = Convert.ToBase64String(new byte[32])
        });

        var exception = await Assert.ThrowsAsync<InvalidOperationException>(() => handler.OpenTcpAsync(
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

        Assert.Equal("Shadowsocks 2022 key must decode to 16 bytes.", exception.Message);
    }

    [Fact]
    public async Task OpenTcpAsync_accepts_two_segment_identity_header_password_material()
    {
        using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(10));
        using var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();
        var serverPort = ((IPEndPoint)listener.LocalEndpoint).Port;
        var serverKey = CreateTestKey(ShadowsocksCipherTypes.Blake3Aes256Gcm);
        var userKey = CreateTestKey(ShadowsocksCipherTypes.Blake3Aes256Gcm, 64);
        var compositeKey = $"{serverKey}:{userKey}";
        var account = Shadowsocks2022Account.Create(ShadowsocksCipherTypes.Blake3Aes256Gcm, compositeKey);
        var payload = Encoding.ASCII.GetBytes("hello-ss2022-identity-header");

        var serverTask = Task.Run(async () =>
        {
            using var accepted = await listener.AcceptTcpClientAsync(cts.Token);
            await using var serverStream = accepted.GetStream();
            var session = await Shadowsocks2022ProtocolCodec.AcceptServerTcpStreamAsync(serverStream, account, cts.Token);

            Assert.Equal("identity.example.com", session.Destination.Host);
            Assert.Equal(8443, session.Destination.Port);

            await using var tunneled = session.Stream;
            var buffer = new byte[payload.Length];
            await ReadExactAsync(tunneled, buffer, cts.Token);
            Assert.Equal(payload, buffer);
        }, cts.Token);

        var handler = CreateHandler(new Shadowsocks2022OutboundSettings
        {
            Tag = "ss-2022",
            ServerHost = "127.0.0.1",
            ServerPort = serverPort,
            Method = ShadowsocksCipherTypes.Blake3Aes256Gcm,
            Key = compositeKey
        });

        await using var stream = await handler.OpenTcpAsync(
            new DispatchContext
            {
                OutboundTag = "ss-2022"
            },
            new DispatchDestination
            {
                Host = "identity.example.com",
                Port = 8443,
                Network = DispatchNetwork.Tcp
            },
            cts.Token);

        await stream.WriteAsync(payload, cts.Token);
        await stream.FlushAsync(cts.Token);

        await serverTask;
    }

    [Fact]
    public async Task OpenTcpAsync_accepts_multiple_identity_headers_password_material()
    {
        using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(10));
        using var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();
        var serverPort = ((IPEndPoint)listener.LocalEndpoint).Port;
        var serverKey = CreateTestKey(ShadowsocksCipherTypes.Blake3Aes256Gcm);
        var identityKeyA = CreateTestKey(ShadowsocksCipherTypes.Blake3Aes256Gcm, 64);
        var identityKeyB = CreateTestKey(ShadowsocksCipherTypes.Blake3Aes256Gcm, 96);
        var userKey = CreateTestKey(ShadowsocksCipherTypes.Blake3Aes256Gcm, 128);
        var compositeKey = $"{serverKey}:{identityKeyA}:{identityKeyB}:{userKey}";
        var account = Shadowsocks2022Account.Create(ShadowsocksCipherTypes.Blake3Aes256Gcm, compositeKey);
        var payload = Encoding.ASCII.GetBytes("hello-ss2022-multi-identity-header");

        var serverTask = Task.Run(async () =>
        {
            using var accepted = await listener.AcceptTcpClientAsync(cts.Token);
            await using var serverStream = accepted.GetStream();
            var session = await Shadowsocks2022ProtocolCodec.AcceptServerTcpStreamAsync(serverStream, account, cts.Token);

            Assert.Equal("multi-identity.example.com", session.Destination.Host);
            Assert.Equal(9443, session.Destination.Port);

            await using var tunneled = session.Stream;
            var buffer = new byte[payload.Length];
            await ReadExactAsync(tunneled, buffer, cts.Token);
            Assert.Equal(payload, buffer);
        }, cts.Token);

        var handler = CreateHandler(new Shadowsocks2022OutboundSettings
        {
            Tag = "ss-2022",
            ServerHost = "127.0.0.1",
            ServerPort = serverPort,
            Method = ShadowsocksCipherTypes.Blake3Aes256Gcm,
            Key = compositeKey
        });

        await using var stream = await handler.OpenTcpAsync(
            new DispatchContext
            {
                OutboundTag = "ss-2022"
            },
            new DispatchDestination
            {
                Host = "multi-identity.example.com",
                Port = 9443,
                Network = DispatchNetwork.Tcp
            },
            cts.Token);

        await stream.WriteAsync(payload, cts.Token);
        await stream.FlushAsync(cts.Token);

        await serverTask;
    }

    private static string CreateTestKey(string method, int seed = 0)
    {
        var keySize = method switch
        {
            ShadowsocksCipherTypes.Blake3Aes128Gcm => 16,
            ShadowsocksCipherTypes.Blake3Aes256Gcm => 32,
            ShadowsocksCipherTypes.Blake3ChaCha20Poly1305 => 32,
            _ => throw new NotSupportedException($"Unsupported Shadowsocks 2022 method: {method}.")
        };

        return Convert.ToBase64String(
            Enumerable.Range(seed, keySize)
                .Select(static value => (byte)(value & 0xFF))
                .ToArray());
    }

    private static Shadowsocks2022OutboundHandler CreateHandler(Shadowsocks2022OutboundSettings settings)
        => new(
            new Shadowsocks2022OutboundClient(),
            new StaticShadowsocks2022OutboundSettingsProvider(settings));

    private static async Task ReadExactAsync(Stream stream, byte[] buffer, CancellationToken cancellationToken)
    {
        var offset = 0;
        while (offset < buffer.Length)
        {
            var read = await stream.ReadAsync(buffer.AsMemory(offset, buffer.Length - offset), cancellationToken);
            if (read == 0)
            {
                throw new EndOfStreamException("Unexpected EOF while reading Shadowsocks 2022 test payload.");
            }

            offset += read;
        }
    }

    private sealed class StaticShadowsocks2022OutboundSettingsProvider : IShadowsocks2022OutboundSettingsProvider
    {
        private readonly Shadowsocks2022OutboundSettings _settings;

        public StaticShadowsocks2022OutboundSettingsProvider(Shadowsocks2022OutboundSettings settings)
        {
            _settings = settings;
        }

        public bool TryResolve(DispatchContext context, out Shadowsocks2022OutboundSettings settings)
        {
            settings = _settings;
            return true;
        }
    }
}

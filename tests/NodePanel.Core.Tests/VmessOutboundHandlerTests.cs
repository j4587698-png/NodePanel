using System.Net;
using System.Net.Sockets;
using System.Text;
using NodePanel.Core.Protocol;
using NodePanel.Core.Runtime;

namespace NodePanel.Core.Tests;

public sealed class VmessOutboundHandlerTests
{
    [Fact]
    public async Task DispatchTcpAsync_routes_through_vmess_outbound()
    {
        using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(10));
        using var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();

        var uuid = "11111111-1111-1111-1111-111111111111";
        var user = CreateUser(uuid);
        var port = ((IPEndPoint)listener.LocalEndpoint).Port;
        var dispatcher = CreateDispatcher(
            new VmessOutboundSettings
            {
                Tag = "proxy",
                ServerHost = IPAddress.Loopback.ToString(),
                ServerPort = port,
                Transport = VmessOutboundTransports.Tcp,
                UserUuid = uuid,
                Security = VmessOutboundSecurityTypes.Aes128Gcm
            });

        var serverTask = Task.Run(async () =>
        {
            using var client = await listener.AcceptTcpClientAsync(cts.Token);
            await using var stream = client.GetStream();

            var request = await new VmessHandshakeReader().ReadAsync(stream, [user], cts.Token);
            await VmessHandshakeReader.WriteResponseAsync(stream, request, cts.Token);

            await using var vmessStream = new VmessDataStream(stream, request);
            var payload = new byte[4];
            await vmessStream.ReadExactlyAsync(payload.AsMemory(0, payload.Length), cts.Token);
            await vmessStream.WriteAsync(Encoding.ASCII.GetBytes("pong"), cts.Token);
            await vmessStream.CompleteResponseAsync(cts.Token);
            await vmessStream.FlushAsync(cts.Token);

            return new TcpCapture(request, Encoding.ASCII.GetString(payload));
        }, cts.Token);

        await using var outbound = await dispatcher.DispatchTcpAsync(
            new DispatchContext
            {
                InboundProtocol = InboundProtocols.Vmess,
                InboundTag = "edge",
                UserId = "user-1",
                ConnectTimeoutSeconds = 5
            },
            new DispatchDestination
            {
                Host = "example.org",
                Port = 443,
                Network = DispatchNetwork.Tcp
            },
            cts.Token);

        await outbound.WriteAsync(Encoding.ASCII.GetBytes("ping"), cts.Token);
        await outbound.FlushAsync(cts.Token);

        var response = new byte[4];
        await outbound.ReadExactlyAsync(response.AsMemory(0, response.Length), cts.Token);

        var capture = await serverTask;
        Assert.Equal(VmessCommand.Connect, capture.Request.Command);
        Assert.Equal("example.org", capture.Request.TargetHost);
        Assert.Equal(443, capture.Request.TargetPort);
        Assert.Equal("ping", capture.PayloadText);
        Assert.Equal("pong", Encoding.ASCII.GetString(response));
    }

    [Fact]
    public async Task DispatchTcpAsync_uses_system_dns_for_server_when_skip_dns_resolve_is_enabled()
    {
        using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(10));
        using var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();

        var uuid = "11111111-1111-1111-1111-111111111111";
        var user = CreateUser(uuid);
        var port = ((IPEndPoint)listener.LocalEndpoint).Port;
        var dispatcher = CreateDispatcher(
            new VmessOutboundSettings
            {
                Tag = "proxy",
                ServerHost = "localhost",
                ServerPort = port,
                Transport = VmessOutboundTransports.Tcp,
                UserUuid = uuid,
                Security = VmessOutboundSecurityTypes.Aes128Gcm
            },
            new VmessOutboundClient(
                new VmessHandshakeWriter(),
                new ThrowingDnsResolver()));

        var serverTask = Task.Run(async () =>
        {
            using var client = await listener.AcceptTcpClientAsync(cts.Token);
            await using var stream = client.GetStream();

            var request = await new VmessHandshakeReader().ReadAsync(stream, [user], cts.Token);
            await VmessHandshakeReader.WriteResponseAsync(stream, request, cts.Token);
            return request;
        }, cts.Token);

        await using var outbound = await dispatcher.DispatchTcpAsync(
            new DispatchContext
            {
                InboundProtocol = InboundProtocols.Vmess,
                InboundTag = "edge",
                UserId = "user-1",
                ConnectTimeoutSeconds = 5,
                Content = new DispatchContent
                {
                    SkipDnsResolve = true
                }
            },
            new DispatchDestination
            {
                Host = "example.org",
                Port = 443,
                Network = DispatchNetwork.Tcp
            },
            cts.Token);

        var capture = await serverTask;
        Assert.Equal(VmessCommand.Connect, capture.Command);
        Assert.Equal("example.org", capture.TargetHost);
        Assert.Equal(443, capture.TargetPort);
    }

    [Fact]
    public async Task DispatchTcpAsync_allows_server_to_delay_response_header_until_first_payload()
    {
        using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(10));
        using var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();

        var uuid = "11111111-1111-1111-1111-111111111111";
        var user = CreateUser(uuid);
        var port = ((IPEndPoint)listener.LocalEndpoint).Port;
        var dispatcher = CreateDispatcher(
            new VmessOutboundSettings
            {
                Tag = "proxy",
                ServerHost = IPAddress.Loopback.ToString(),
                ServerPort = port,
                Transport = VmessOutboundTransports.Tcp,
                UserUuid = uuid,
                Security = VmessOutboundSecurityTypes.Aes128Gcm
            });

        var serverTask = Task.Run(async () =>
        {
            using var client = await listener.AcceptTcpClientAsync(cts.Token);
            await using var stream = client.GetStream();

            var request = await new VmessHandshakeReader().ReadAsync(stream, [user], cts.Token);
            await using var vmessStream = new VmessDataStream(stream, request);

            var payload = new byte[4];
            await vmessStream.ReadExactlyAsync(payload.AsMemory(0, payload.Length), cts.Token);

            await VmessHandshakeReader.WriteResponseAsync(stream, request, cts.Token);
            await vmessStream.WriteAsync(Encoding.ASCII.GetBytes("pong"), cts.Token);
            await vmessStream.CompleteResponseAsync(cts.Token);
            await vmessStream.FlushAsync(cts.Token);

            return new TcpCapture(request, Encoding.ASCII.GetString(payload));
        }, cts.Token);

        await using var outbound = await dispatcher.DispatchTcpAsync(
            new DispatchContext
            {
                InboundProtocol = InboundProtocols.Vmess,
                InboundTag = "edge",
                UserId = "user-1",
                ConnectTimeoutSeconds = 5
            },
            new DispatchDestination
            {
                Host = "example.org",
                Port = 443,
                Network = DispatchNetwork.Tcp
            },
            cts.Token);

        await outbound.WriteAsync(Encoding.ASCII.GetBytes("ping"), cts.Token);
        await outbound.FlushAsync(cts.Token);

        var response = new byte[4];
        await outbound.ReadExactlyAsync(response.AsMemory(0, response.Length), cts.Token);

        var capture = await serverTask;
        Assert.Equal(VmessCommand.Connect, capture.Request.Command);
        Assert.Equal("example.org", capture.Request.TargetHost);
        Assert.Equal(443, capture.Request.TargetPort);
        Assert.Equal("ping", capture.PayloadText);
        Assert.Equal("pong", Encoding.ASCII.GetString(response));
    }

    [Fact]
    public async Task DispatchUdpAsync_routes_through_vmess_udp_transport()
    {
        using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(10));
        using var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();

        var uuid = "11111111-1111-1111-1111-111111111111";
        var user = CreateUser(uuid);
        var port = ((IPEndPoint)listener.LocalEndpoint).Port;
        var dispatcher = CreateDispatcher(
            new VmessOutboundSettings
            {
                Tag = "proxy",
                ServerHost = IPAddress.Loopback.ToString(),
                ServerPort = port,
                Transport = VmessOutboundTransports.Tcp,
                UserUuid = uuid,
                Security = VmessOutboundSecurityTypes.Aes128Gcm
            });

        var serverTask = Task.Run(async () =>
        {
            using var client = await listener.AcceptTcpClientAsync(cts.Token);
            await using var stream = client.GetStream();

            var request = await new VmessHandshakeReader().ReadAsync(stream, [user], cts.Token);
            await VmessHandshakeReader.WriteResponseAsync(stream, request, cts.Token);

            await using var vmessStream = new VmessDataStream(stream, request);
            var packet = await vmessStream.ReadPacketAsync(cts.Token)
                ?? throw new InvalidDataException("Expected a VMess UDP packet.");

            await vmessStream.WritePacketAsync(Encoding.ASCII.GetBytes("pong"), cts.Token);
            await vmessStream.CompleteResponseAsync(cts.Token);
            await vmessStream.FlushAsync(cts.Token);

            return new UdpCapture(request, Encoding.ASCII.GetString(packet));
        }, cts.Token);

        await using var transport = await dispatcher.DispatchUdpAsync(
            new DispatchContext
            {
                InboundProtocol = InboundProtocols.Vmess,
                InboundTag = "edge",
                UserId = "user-1",
                ConnectTimeoutSeconds = 5
            },
            cts.Token);

        await transport.SendAsync(
            new DispatchDestination
            {
                Host = "8.8.8.8",
                Port = 53,
                Network = DispatchNetwork.Udp
            },
            Encoding.ASCII.GetBytes("ping"),
            cts.Token);

        var datagram = await transport.ReceiveAsync(cts.Token);
        var capture = await serverTask;

        Assert.NotNull(datagram);
        Assert.Equal(VmessCommand.Udp, capture.Request.Command);
        Assert.Equal("8.8.8.8", capture.Request.TargetHost);
        Assert.Equal(53, capture.Request.TargetPort);
        Assert.Equal("ping", capture.PayloadText);
        Assert.Equal("8.8.8.8", datagram!.SourceHost);
        Assert.Equal(53, datagram.SourcePort);
        Assert.Equal("pong", Encoding.ASCII.GetString(datagram.Payload));
    }

    [Fact]
    public async Task DispatchUdpAsync_opens_distinct_vmess_associations_per_destination()
    {
        using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(10));
        using var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();

        var uuid = "11111111-1111-1111-1111-111111111111";
        var user = CreateUser(uuid);
        var port = ((IPEndPoint)listener.LocalEndpoint).Port;
        var dispatcher = CreateDispatcher(
            new VmessOutboundSettings
            {
                Tag = "proxy",
                ServerHost = IPAddress.Loopback.ToString(),
                ServerPort = port,
                Transport = VmessOutboundTransports.Tcp,
                UserUuid = uuid,
                Security = VmessOutboundSecurityTypes.Aes128Gcm
            });

        var firstSessionTask = CaptureUdpSessionAsync(listener, user, cts.Token);
        var secondSessionTask = CaptureUdpSessionAsync(listener, user, cts.Token);

        await using var transport = await dispatcher.DispatchUdpAsync(
            new DispatchContext
            {
                InboundProtocol = InboundProtocols.Vmess,
                InboundTag = "edge",
                UserId = "user-1",
                ConnectTimeoutSeconds = 5
            },
            cts.Token);

        await transport.SendAsync(
            new DispatchDestination
            {
                Host = "8.8.8.8",
                Port = 53,
                Network = DispatchNetwork.Udp
            },
            Encoding.ASCII.GetBytes("ping-1"),
            cts.Token);
        await transport.SendAsync(
            new DispatchDestination
            {
                Host = "1.1.1.1",
                Port = 53,
                Network = DispatchNetwork.Udp
            },
            Encoding.ASCII.GetBytes("ping-2"),
            cts.Token);

        var datagrams = new List<DispatchDatagram>(2);
        for (var index = 0; index < 2; index++)
        {
            var datagram = await transport.ReceiveAsync(cts.Token);
            Assert.NotNull(datagram);
            datagrams.Add(datagram!);
        }

        var captures = await Task.WhenAll(firstSessionTask, secondSessionTask);

        Assert.Contains(captures, static capture => capture.Request.TargetHost == "8.8.8.8" && capture.PayloadText == "ping-1");
        Assert.Contains(captures, static capture => capture.Request.TargetHost == "1.1.1.1" && capture.PayloadText == "ping-2");
        Assert.Contains(datagrams, static datagram => datagram.SourceHost == "8.8.8.8" && Encoding.ASCII.GetString(datagram.Payload) == "pong-1");
        Assert.Contains(datagrams, static datagram => datagram.SourceHost == "1.1.1.1" && Encoding.ASCII.GetString(datagram.Payload) == "pong-2");
    }

    [Fact]
    public async Task DispatchUdpAsync_routes_cone_udp_through_xudp_with_single_mux_session()
    {
        using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(10));
        using var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();

        var uuid = "11111111-1111-1111-1111-111111111111";
        var user = CreateUser(uuid);
        var port = ((IPEndPoint)listener.LocalEndpoint).Port;
        var dispatcher = CreateDispatcher(
            new VmessOutboundSettings
            {
                Tag = "proxy",
                ServerHost = IPAddress.Loopback.ToString(),
                ServerPort = port,
                Transport = VmessOutboundTransports.Tcp,
                UserUuid = uuid,
                Security = VmessOutboundSecurityTypes.Aes128Gcm
            });

        var serverTask = CaptureXudpSessionAsync(listener, user, cts.Token);

        await using var transport = await dispatcher.DispatchUdpAsync(
            new DispatchContext
            {
                InboundProtocol = InboundProtocols.Vmess,
                InboundTag = "edge",
                UserId = "user-1",
                ConnectTimeoutSeconds = 5,
                UseCone = true
            },
            cts.Token);

        await transport.SendAsync(
            new DispatchDestination
            {
                Host = "8.8.8.8",
                Port = 1234,
                Network = DispatchNetwork.Udp
            },
            Encoding.ASCII.GetBytes("ping-1"),
            cts.Token);
        await transport.SendAsync(
            new DispatchDestination
            {
                Host = "1.1.1.1",
                Port = 4321,
                Network = DispatchNetwork.Udp
            },
            Encoding.ASCII.GetBytes("ping-2"),
            cts.Token);

        var datagrams = new List<DispatchDatagram>(2);
        for (var index = 0; index < 2; index++)
        {
            var datagram = await transport.ReceiveAsync(cts.Token);
            Assert.NotNull(datagram);
            datagrams.Add(datagram!);
        }

        var capture = await serverTask;

        Assert.Equal(VmessCommand.Mux, capture.Request.Command);
        Assert.Equal("v1.mux.cool", capture.Request.TargetHost);
        Assert.Equal(0, capture.Request.TargetPort);

        Assert.Equal(2, capture.Frames.Length);
        Assert.Equal((ushort)0, capture.Frames[0].SessionId);
        Assert.Equal(TrojanMuxSessionStatus.New, capture.Frames[0].Status);
        Assert.Equal("8.8.8.8", capture.Frames[0].Target!.Host);
        Assert.Equal(1234, capture.Frames[0].Target!.Port);
        Assert.Equal("ping-1", Encoding.ASCII.GetString(capture.Frames[0].Payload));

        Assert.Equal((ushort)0, capture.Frames[1].SessionId);
        Assert.Equal(TrojanMuxSessionStatus.Keep, capture.Frames[1].Status);
        Assert.Equal("1.1.1.1", capture.Frames[1].Target!.Host);
        Assert.Equal(4321, capture.Frames[1].Target!.Port);
        Assert.Equal("ping-2", Encoding.ASCII.GetString(capture.Frames[1].Payload));

        Assert.Contains(datagrams, static datagram => datagram.SourceHost == "8.8.8.8" && datagram.SourcePort == 1234 && Encoding.ASCII.GetString(datagram.Payload) == "pong-1");
        Assert.Contains(datagrams, static datagram => datagram.SourceHost == "1.1.1.1" && datagram.SourcePort == 4321 && Encoding.ASCII.GetString(datagram.Payload) == "pong-2");
    }

    private static IDispatcher CreateDispatcher(VmessOutboundSettings settings, VmessOutboundClient? client = null)
        => new DefaultDispatcher(
            new DefaultOutboundRouter(
                new IOutboundHandler[]
                {
                    new FreedomOutboundHandler(),
                    new VmessOutboundHandler(
                        client ?? new VmessOutboundClient(),
                        new StaticVmessOutboundSettingsProvider(settings))
                },
                new StaticOutboundRuntimePlanProvider(
                    new OutboundRuntimePlan
                    {
                        Outbounds =
                        [
                            new OutboundRuntime
                            {
                                Tag = settings.Tag,
                                Protocol = OutboundProtocols.Vmess
                            }
                        ],
                        DefaultOutboundTag = settings.Tag
                    })));

    private static async Task<UdpCapture> CaptureUdpSessionAsync(
        TcpListener listener,
        VmessUser user,
        CancellationToken cancellationToken)
    {
        using var client = await listener.AcceptTcpClientAsync(cancellationToken);
        await using var stream = client.GetStream();

        var request = await new VmessHandshakeReader().ReadAsync(stream, [user], cancellationToken);
        await VmessHandshakeReader.WriteResponseAsync(stream, request, cancellationToken);

        await using var vmessStream = new VmessDataStream(stream, request);
        var packet = await vmessStream.ReadPacketAsync(cancellationToken)
            ?? throw new InvalidDataException("Expected a VMess UDP packet.");

        var responsePayload = request.TargetHost switch
        {
            "8.8.8.8" => "pong-1",
            "1.1.1.1" => "pong-2",
            _ => "pong"
        };

        await vmessStream.WritePacketAsync(Encoding.ASCII.GetBytes(responsePayload), cancellationToken);
        await vmessStream.CompleteResponseAsync(cancellationToken);
        await vmessStream.FlushAsync(cancellationToken);

        return new UdpCapture(request, Encoding.ASCII.GetString(packet));
    }

    private static async Task<XudpCapture> CaptureXudpSessionAsync(
        TcpListener listener,
        VmessUser user,
        CancellationToken cancellationToken)
    {
        using var client = await listener.AcceptTcpClientAsync(cancellationToken);
        await using var stream = client.GetStream();

        var request = await new VmessHandshakeReader().ReadAsync(stream, [user], cancellationToken);
        await VmessHandshakeReader.WriteResponseAsync(stream, request, cancellationToken);

        await using var vmessStream = new VmessDataStream(stream, request);
        var firstFrame = await TrojanMuxFrameCodec.ReadAsync(vmessStream, cancellationToken)
            ?? throw new InvalidDataException("Expected the first XUDP mux frame.");
        var secondFrame = await TrojanMuxFrameCodec.ReadAsync(vmessStream, cancellationToken)
            ?? throw new InvalidDataException("Expected the second XUDP mux frame.");

        await TrojanMuxFrameCodec.WriteAsync(
            vmessStream,
            new TrojanMuxFrame
            {
                SessionId = 0,
                Status = TrojanMuxSessionStatus.Keep,
                Option = TrojanMuxFrameOption.Data,
                Target = new TrojanMuxFrameTarget("8.8.8.8", 1234, DispatchNetwork.Udp),
                Payload = Encoding.ASCII.GetBytes("pong-1")
            },
            cancellationToken);
        await TrojanMuxFrameCodec.WriteAsync(
            vmessStream,
            new TrojanMuxFrame
            {
                SessionId = 0,
                Status = TrojanMuxSessionStatus.Keep,
                Option = TrojanMuxFrameOption.Data,
                Target = new TrojanMuxFrameTarget("1.1.1.1", 4321, DispatchNetwork.Udp),
                Payload = Encoding.ASCII.GetBytes("pong-2")
            },
            cancellationToken);
        await vmessStream.CompleteResponseAsync(cancellationToken);
        await vmessStream.FlushAsync(cancellationToken);

        return new XudpCapture(request, [firstFrame, secondFrame]);
    }

    private static VmessUser CreateUser(string uuid)
        => new()
        {
            UserId = "vmess-user",
            Uuid = uuid,
            CmdKey = VmessAccountCodec.CreateCommandKey(uuid),
            BytesPerSecond = 0
        };

    private sealed class StaticVmessOutboundSettingsProvider : IVmessOutboundSettingsProvider
    {
        private readonly VmessOutboundSettings _settings;

        public StaticVmessOutboundSettingsProvider(VmessOutboundSettings settings)
        {
            _settings = settings;
        }

        public bool TryResolve(DispatchContext context, out VmessOutboundSettings settings)
        {
            settings = _settings;
            return true;
        }
    }

    private sealed class StaticOutboundRuntimePlanProvider : IOutboundRuntimePlanProvider
    {
        private readonly OutboundRuntimePlan _plan;

        public StaticOutboundRuntimePlanProvider(OutboundRuntimePlan plan)
        {
            _plan = plan;
        }

        public OutboundRuntimePlan GetCurrentOutboundPlan() => _plan;
    }

    private sealed class ThrowingDnsResolver : IDnsResolver
    {
        public ValueTask<IReadOnlyList<IPAddress>> ResolveAsync(string host, CancellationToken cancellationToken = default)
            => throw new InvalidOperationException("The custom DNS resolver should not be used when SkipDnsResolve is enabled.");
    }

    private sealed record TcpCapture(VmessRequest Request, string PayloadText);

    private sealed record UdpCapture(VmessRequest Request, string PayloadText);

    private sealed record XudpCapture(VmessRequest Request, TrojanMuxFrame[] Frames);
}

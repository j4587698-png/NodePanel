using System.Buffers.Binary;
using System.Linq;
using System.Net;
using System.Net.Sockets;
using System.Net.Security;
using System.Reflection;
using System.Security.Authentication;
using System.Text;
using System.Threading.Channels;
using NodePanel.Core.Protocol;
using NodePanel.Core.Runtime;

namespace NodePanel.Core.Tests;

public sealed class VlessOutboundHandlerTests
{
    [Fact]
    public async Task DispatchTcpAsync_routes_through_vless_outbound()
    {
        using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(10));
        using var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();

        var port = ((IPEndPoint)listener.LocalEndpoint).Port;
        var dispatcher = CreateDispatcher(
            new VlessOutboundSettings
            {
                Tag = "proxy",
                ServerHost = IPAddress.Loopback.ToString(),
                ServerPort = port,
                Transport = VlessOutboundTransports.Tcp,
                UserUuid = "11111111-1111-1111-1111-111111111111"
            });

        var serverTask = Task.Run(async () =>
        {
            using var client = await listener.AcceptTcpClientAsync(cts.Token);
            await using var stream = client.GetStream();

            var request = await new VlessHandshakeReader().ReadAsync(stream, cts.Token);
            await VlessHandshakeReader.WriteResponseAsync(stream, request.Version, cts.Token);

            var payload = new byte[4];
            await stream.ReadExactlyAsync(payload.AsMemory(0, payload.Length), cts.Token);
            await stream.WriteAsync(Encoding.ASCII.GetBytes("pong"), cts.Token);

            return new TcpCapture(request, Encoding.ASCII.GetString(payload));
        }, cts.Token);

        await using var outbound = await dispatcher.DispatchTcpAsync(
            new DispatchContext
            {
                InboundProtocol = InboundProtocols.Vless,
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
        Assert.Equal(VlessCommand.Connect, capture.Request.Command);
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

        var port = ((IPEndPoint)listener.LocalEndpoint).Port;
        var dispatcher = CreateDispatcher(
            new VlessOutboundSettings
            {
                Tag = "proxy",
                ServerHost = "localhost",
                ServerPort = port,
                Transport = VlessOutboundTransports.Tcp,
                UserUuid = "11111111-1111-1111-1111-111111111111"
            },
            new VlessOutboundClient(
                new VlessHandshakeWriter(),
                new ThrowingDnsResolver()));

        var serverTask = Task.Run(async () =>
        {
            using var client = await listener.AcceptTcpClientAsync(cts.Token);
            await using var stream = client.GetStream();

            var request = await new VlessHandshakeReader().ReadAsync(stream, cts.Token);
            await VlessHandshakeReader.WriteResponseAsync(stream, request.Version, cts.Token);
            return request;
        }, cts.Token);

        await using var outbound = await dispatcher.DispatchTcpAsync(
            new DispatchContext
            {
                InboundProtocol = InboundProtocols.Vless,
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
        Assert.Equal(VlessCommand.Connect, capture.Command);
        Assert.Equal("example.org", capture.TargetHost);
        Assert.Equal(443, capture.TargetPort);
    }

    [Fact]
    public async Task DispatchTcpAsync_allows_server_to_delay_response_header_until_first_payload()
    {
        using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(10));
        using var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();

        var port = ((IPEndPoint)listener.LocalEndpoint).Port;
        var dispatcher = CreateDispatcher(
            new VlessOutboundSettings
            {
                Tag = "proxy",
                ServerHost = IPAddress.Loopback.ToString(),
                ServerPort = port,
                Transport = VlessOutboundTransports.Tcp,
                UserUuid = "11111111-1111-1111-1111-111111111111"
            });

        var serverTask = Task.Run(async () =>
        {
            using var client = await listener.AcceptTcpClientAsync(cts.Token);
            await using var stream = client.GetStream();

            var request = await new VlessHandshakeReader().ReadAsync(stream, cts.Token);

            var payload = new byte[4];
            await stream.ReadExactlyAsync(payload.AsMemory(0, payload.Length), cts.Token);

            await VlessHandshakeReader.WriteResponseAsync(stream, request.Version, cts.Token);
            await stream.WriteAsync(Encoding.ASCII.GetBytes("pong"), cts.Token);
            await stream.FlushAsync(cts.Token);

            return new TcpCapture(request, Encoding.ASCII.GetString(payload));
        }, cts.Token);

        await using var outbound = await dispatcher.DispatchTcpAsync(
            new DispatchContext
            {
                InboundProtocol = InboundProtocols.Vless,
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
        Assert.Equal(VlessCommand.Connect, capture.Request.Command);
        Assert.Equal("example.org", capture.Request.TargetHost);
        Assert.Equal(443, capture.Request.TargetPort);
        Assert.Equal("ping", capture.PayloadText);
        Assert.Equal("pong", Encoding.ASCII.GetString(response));
    }

    [Fact]
    public async Task DispatchTcpAsync_creates_testpre_pool_when_enabled()
    {
        using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(10));
        using var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();

        var port = ((IPEndPoint)listener.LocalEndpoint).Port;
        var dispatcher = CreateDispatcher(
            new VlessOutboundSettings
            {
                Tag = "proxy",
                ServerHost = IPAddress.Loopback.ToString(),
                ServerPort = port,
                Transport = VlessOutboundTransports.Tcp,
                UserUuid = "11111111-1111-1111-1111-111111111111",
                TestPre = 1
            },
            out var handler);
        await using var _ = handler;

        var serverTask = Task.Run(async () =>
        {
            using var client = await listener.AcceptTcpClientAsync(cts.Token);
            await using var stream = client.GetStream();

            var request = await new VlessHandshakeReader().ReadAsync(stream, cts.Token);
            await VlessHandshakeReader.WriteResponseAsync(stream, request.Version, cts.Token);

            var payload = new byte[4];
            await stream.ReadExactlyAsync(payload.AsMemory(0, payload.Length), cts.Token);
            await stream.WriteAsync(Encoding.ASCII.GetBytes("pong"), cts.Token);

            return new TcpCapture(request, Encoding.ASCII.GetString(payload));
        }, cts.Token);

        await using var outbound = await dispatcher.DispatchTcpAsync(
            new DispatchContext
            {
                InboundProtocol = InboundProtocols.Vless,
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
        Assert.Equal("ping", capture.PayloadText);
        Assert.Equal("pong", Encoding.ASCII.GetString(response));
        Assert.Equal(1, GetPreconnectStateCount(handler));
    }

    [Fact]
    public async Task DispatchTcpAsync_skips_testpre_for_websocket_early_data()
    {
        using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(10));
        using var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();

        var port = ((IPEndPoint)listener.LocalEndpoint).Port;
        var dispatcher = CreateDispatcher(
            new VlessOutboundSettings
            {
                Tag = "proxy",
                ServerHost = IPAddress.Loopback.ToString(),
                ServerPort = port,
                Transport = VlessOutboundTransports.Ws,
                WebSocketEarlyDataBytes = 4096,
                UserUuid = "11111111-1111-1111-1111-111111111111",
                TestPre = 1
            },
            out var handler,
            CreateWsClient());
        await using var _ = handler;

        var serverTask = Task.Run(async () =>
        {
            using var client = await listener.AcceptTcpClientAsync(cts.Token);
            await using var stream = client.GetStream();

            var request = await new VlessHandshakeReader().ReadAsync(stream, cts.Token);
            await VlessHandshakeReader.WriteResponseAsync(stream, request.Version, cts.Token);

            var payload = new byte[4];
            await stream.ReadExactlyAsync(payload.AsMemory(0, payload.Length), cts.Token);
            await stream.WriteAsync(Encoding.ASCII.GetBytes("pong"), cts.Token);

            return new TcpCapture(request, Encoding.ASCII.GetString(payload));
        }, cts.Token);

        await using var outbound = await dispatcher.DispatchTcpAsync(
            new DispatchContext
            {
                InboundProtocol = InboundProtocols.Vless,
                InboundTag = "edge",
                UserId = "user-1",
                ConnectTimeoutSeconds = 5
            },
            new DispatchDestination
            {
                Host = "example.org",
                Port = 80,
                Network = DispatchNetwork.Tcp
            },
            cts.Token);

        await outbound.WriteAsync(Encoding.ASCII.GetBytes("ping"), cts.Token);
        await outbound.FlushAsync(cts.Token);

        var response = new byte[4];
        await outbound.ReadExactlyAsync(response.AsMemory(0, response.Length), cts.Token);

        var capture = await serverTask;
        Assert.Equal("ping", capture.PayloadText);
        Assert.Equal("pong", Encoding.ASCII.GetString(response));
        Assert.Equal(0, GetPreconnectStateCount(handler));
    }

    [Fact]
    public async Task DispatchUdpAsync_routes_through_vless_udp_transport()
    {
        using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(10));
        using var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();

        var port = ((IPEndPoint)listener.LocalEndpoint).Port;
        var dispatcher = CreateDispatcher(
            new VlessOutboundSettings
            {
                Tag = "proxy",
                ServerHost = IPAddress.Loopback.ToString(),
                ServerPort = port,
                Transport = VlessOutboundTransports.Tcp,
                UserUuid = "11111111-1111-1111-1111-111111111111"
            });

        var serverTask = Task.Run(async () =>
        {
            using var client = await listener.AcceptTcpClientAsync(cts.Token);
            await using var stream = client.GetStream();

            var handshakeReader = new VlessHandshakeReader();
            var packetReader = new VlessUdpPacketReader();
            var packetWriter = new VlessUdpPacketWriter();

            var request = await handshakeReader.ReadAsync(stream, cts.Token);
            await VlessHandshakeReader.WriteResponseAsync(stream, request.Version, cts.Token);

            var packet = await packetReader.ReadAsync(stream, cts.Token)
                ?? throw new InvalidDataException("Expected a VLESS UDP packet.");

            await packetWriter.WriteAsync(stream, Encoding.ASCII.GetBytes("pong"), cts.Token);
            await stream.FlushAsync(cts.Token);

            return new UdpCapture(request, Encoding.ASCII.GetString(packet));
        }, cts.Token);

        await using var transport = await dispatcher.DispatchUdpAsync(
            new DispatchContext
            {
                InboundProtocol = InboundProtocols.Vless,
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
        Assert.Equal(VlessCommand.Udp, capture.Request.Command);
        Assert.Equal("8.8.8.8", capture.Request.TargetHost);
        Assert.Equal(53, capture.Request.TargetPort);
        Assert.Equal("ping", capture.PayloadText);
        Assert.Equal("8.8.8.8", datagram!.SourceHost);
        Assert.Equal(53, datagram.SourcePort);
        Assert.Equal("pong", Encoding.ASCII.GetString(datagram.Payload));
    }

    [Fact]
    public async Task DispatchUdpAsync_opens_distinct_vless_associations_per_destination()
    {
        using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(10));
        using var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();

        var port = ((IPEndPoint)listener.LocalEndpoint).Port;
        var dispatcher = CreateDispatcher(
            new VlessOutboundSettings
            {
                Tag = "proxy",
                ServerHost = IPAddress.Loopback.ToString(),
                ServerPort = port,
                Transport = VlessOutboundTransports.Tcp,
                UserUuid = "11111111-1111-1111-1111-111111111111"
            });

        var firstSessionTask = CaptureUdpSessionAsync(listener, cts.Token);
        var secondSessionTask = CaptureUdpSessionAsync(listener, cts.Token);

        await using var transport = await dispatcher.DispatchUdpAsync(
            new DispatchContext
            {
                InboundProtocol = InboundProtocols.Vless,
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

        var port = ((IPEndPoint)listener.LocalEndpoint).Port;
        var dispatcher = CreateDispatcher(
            new VlessOutboundSettings
            {
                Tag = "proxy",
                ServerHost = IPAddress.Loopback.ToString(),
                ServerPort = port,
                Transport = VlessOutboundTransports.Tcp,
                UserUuid = "11111111-1111-1111-1111-111111111111"
            });

        var serverTask = CaptureXudpSessionAsync(listener, cts.Token);

        await using var transport = await dispatcher.DispatchUdpAsync(
            new DispatchContext
            {
                InboundProtocol = InboundProtocols.Vless,
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

        Assert.Equal(VlessCommand.Mux, capture.Request.Command);
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

    [Fact]
    public async Task DispatchTcpAsync_routes_flow_vision_over_tls_body_stream()
    {
        using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(15));
        using var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();

        var port = ((IPEndPoint)listener.LocalEndpoint).Port;
        var dispatcher = CreateDispatcher(
            new VlessOutboundSettings
            {
                Tag = "proxy",
                ServerHost = IPAddress.Loopback.ToString(),
                ServerPort = port,
                ServerName = "edge.example.com",
                Transport = VlessOutboundTransports.Tls,
                UserUuid = "11111111-1111-1111-1111-111111111111",
                Flow = VlessFlowTypes.Vision,
                SkipCertificateValidation = true
            },
            CreateVisionClient());

        var serverTask = CaptureVisionTcpSessionAsync(listener, cts.Token);

        await using var outbound = await dispatcher.DispatchTcpAsync(
            new DispatchContext
            {
                InboundProtocol = InboundProtocols.Vless,
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
        Assert.Equal(VlessCommand.Connect, capture.Request.Command);
        Assert.Equal(VlessFlowTypes.Vision, capture.Request.Addons.Flow);
        Assert.Equal("example.org", capture.Request.TargetHost);
        Assert.Equal(443, capture.Request.TargetPort);
        Assert.Equal("ping", capture.PayloadText);
        Assert.Equal("pong", Encoding.ASCII.GetString(response));
    }

    [Fact]
    public async Task DispatchTcpAsync_routes_flow_vision_over_reality_like_secure_stream()
    {
        using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(15));
        using var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();

        var port = ((IPEndPoint)listener.LocalEndpoint).Port;
        var dispatcher = CreateDispatcher(
            new VlessOutboundSettings
            {
                Tag = "proxy",
                ServerHost = IPAddress.Loopback.ToString(),
                ServerPort = port,
                ServerName = "edge.example.com",
                Transport = VlessOutboundTransports.Tcp,
                TransportSecurity = RuntimeInternetSecurityTypes.Reality,
                RealityOptions = CreateValidRealityOptions(),
                UserUuid = "11111111-1111-1111-1111-111111111111",
                Flow = VlessFlowTypes.Vision,
                SkipCertificateValidation = true
            },
            CreateRealityVisionClient());

        var serverTask = CaptureVisionTcpSessionAsync(listener, cts.Token);

        await using var outbound = await dispatcher.DispatchTcpAsync(
            new DispatchContext
            {
                InboundProtocol = InboundProtocols.Vless,
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
        Assert.Equal(VlessCommand.Connect, capture.Request.Command);
        Assert.Equal(VlessFlowTypes.Vision, capture.Request.Addons.Flow);
        Assert.Equal("example.org", capture.Request.TargetHost);
        Assert.Equal(443, capture.Request.TargetPort);
        Assert.Equal("ping", capture.PayloadText);
        Assert.Equal("pong", Encoding.ASCII.GetString(response));
    }

    [Fact]
    public async Task DispatchTcpAsync_routes_flow_vision_over_reality_using_runtime_handshake_provider()
    {
        using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(15));
        using var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();

        var port = ((IPEndPoint)listener.LocalEndpoint).Port;
        var handshakeProvider = new FakeRealityHandshakeProvider();
        var dispatcher = CreateDispatcher(
            new VlessOutboundSettings
            {
                Tag = "proxy",
                ServerHost = IPAddress.Loopback.ToString(),
                ServerPort = port,
                ServerName = "edge.example.com",
                Transport = VlessOutboundTransports.Tcp,
                TransportSecurity = RuntimeInternetSecurityTypes.Reality,
                RealityOptions = CreateValidRealityOptions(),
                RealityHandshakeProvider = handshakeProvider,
                UserUuid = "11111111-1111-1111-1111-111111111111",
                Flow = VlessFlowTypes.Vision,
                SkipCertificateValidation = true
            });

        var serverTask = CaptureVisionTcpSessionAsync(listener, cts.Token);

        await using var outbound = await dispatcher.DispatchTcpAsync(
            new DispatchContext
            {
                InboundProtocol = InboundProtocols.Vless,
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
        Assert.True(handshakeProvider.WasCalled);
        Assert.Equal("edge.example.com", handshakeProvider.LastServerName);
        Assert.Equal("tcp", handshakeProvider.LastTransportProtocol);
        Assert.Equal(VlessCommand.Connect, capture.Request.Command);
        Assert.Equal(VlessFlowTypes.Vision, capture.Request.Addons.Flow);
        Assert.Equal("example.org", capture.Request.TargetHost);
        Assert.Equal(443, capture.Request.TargetPort);
        Assert.Equal("ping", capture.PayloadText);
        Assert.Equal("pong", Encoding.ASCII.GetString(response));
    }

    [Fact]
    public async Task DispatchTcpAsync_uses_custom_testseed_for_flow_vision_padding()
    {
        using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(15));
        using var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();

        var port = ((IPEndPoint)listener.LocalEndpoint).Port;
        var dispatcher = CreateDispatcher(
            new VlessOutboundSettings
            {
                Tag = "proxy",
                ServerHost = IPAddress.Loopback.ToString(),
                ServerPort = port,
                ServerName = "edge.example.com",
                Transport = VlessOutboundTransports.Tls,
                UserUuid = "11111111-1111-1111-1111-111111111111",
                Flow = VlessFlowTypes.Vision,
                TestSeed = [1u, 0u, 1u, 0u],
                SkipCertificateValidation = true
            },
            CreateVisionClient());

        var serverTask = CaptureVisionFrameSessionAsync(listener, cts.Token);

        await using var outbound = await dispatcher.DispatchTcpAsync(
            new DispatchContext
            {
                InboundProtocol = InboundProtocols.Vless,
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
        Assert.Equal(VlessFlowTypes.Vision, capture.Request.Addons.Flow);
        Assert.Equal((byte)VlessVisionCommand.Continue, capture.Command);
        Assert.Equal(4, capture.ContentLength);
        Assert.Equal(0, capture.PaddingLength);
        Assert.Equal("ping", capture.PayloadText);
        Assert.Equal("pong", Encoding.ASCII.GetString(response));
    }

    [Fact]
    public async Task DispatchUdpAsync_rejects_udp_443_for_flow_vision()
    {
        using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(5));
        var dispatcher = CreateDispatcher(
            new VlessOutboundSettings
            {
                Tag = "proxy",
                ServerHost = "127.0.0.1",
                ServerPort = 443,
                ServerName = "edge.example.com",
                Transport = VlessOutboundTransports.Tls,
                UserUuid = "11111111-1111-1111-1111-111111111111",
                Flow = VlessFlowTypes.Vision,
                SkipCertificateValidation = true
            });

        await using var transport = await dispatcher.DispatchUdpAsync(
            new DispatchContext
            {
                InboundProtocol = InboundProtocols.Vless,
                InboundTag = "edge",
                UserId = "user-1",
                ConnectTimeoutSeconds = 5
            },
            cts.Token);

        var exception = await Assert.ThrowsAsync<InvalidOperationException>(() => transport.SendAsync(
            new DispatchDestination
            {
                Host = "8.8.8.8",
                Port = 443,
                Network = DispatchNetwork.Udp
            },
            Encoding.ASCII.GetBytes("ping"),
            cts.Token).AsTask());

        Assert.Contains("UDP/443", exception.Message, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task DispatchUdpAsync_routes_flow_vision_udp443_through_xudp_over_tls()
    {
        using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(15));
        using var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();

        var port = ((IPEndPoint)listener.LocalEndpoint).Port;
        var dispatcher = CreateDispatcher(
            new VlessOutboundSettings
            {
                Tag = "proxy",
                ServerHost = IPAddress.Loopback.ToString(),
                ServerPort = port,
                ServerName = "edge.example.com",
                Transport = VlessOutboundTransports.Tls,
                UserUuid = "11111111-1111-1111-1111-111111111111",
                Flow = VlessFlowTypes.VisionUdp443,
                SkipCertificateValidation = true
            },
            CreateVisionClient());

        var serverTask = CaptureVisionXudpSessionAsync(listener, cts.Token);

        await using var transport = await dispatcher.DispatchUdpAsync(
            new DispatchContext
            {
                InboundProtocol = InboundProtocols.Vless,
                InboundTag = "edge",
                UserId = "user-1",
                ConnectTimeoutSeconds = 5
            },
            cts.Token);

        await transport.SendAsync(
            new DispatchDestination
            {
                Host = "8.8.8.8",
                Port = 443,
                Network = DispatchNetwork.Udp
            },
            Encoding.ASCII.GetBytes("ping"),
            cts.Token);

        var datagram = await transport.ReceiveAsync(cts.Token);
        var capture = await serverTask;

        Assert.NotNull(datagram);
        Assert.Equal(VlessCommand.Mux, capture.Request.Command);
        Assert.Equal(VlessFlowTypes.Vision, capture.Request.Addons.Flow);
        Assert.Equal("v1.mux.cool", capture.Request.TargetHost);
        Assert.Equal(0, capture.Request.TargetPort);

        Assert.Single(capture.Frames);
        Assert.Equal((ushort)0, capture.Frames[0].SessionId);
        Assert.Equal(TrojanMuxSessionStatus.New, capture.Frames[0].Status);
        Assert.Equal("8.8.8.8", capture.Frames[0].Target!.Host);
        Assert.Equal(443, capture.Frames[0].Target!.Port);
        Assert.Equal("ping", Encoding.ASCII.GetString(capture.Frames[0].Payload));

        Assert.Equal("8.8.8.8", datagram!.SourceHost);
        Assert.Equal(443, datagram.SourcePort);
        Assert.Equal("pong", Encoding.ASCII.GetString(datagram.Payload));
    }

    [Fact]
    public async Task Start_establishes_reverse_portal_and_dispatches_tcp_sessions_locally()
    {
        using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(15));
        using var reverseListener = new TcpListener(IPAddress.Loopback, 0);
        using var localServiceListener = new TcpListener(IPAddress.Loopback, 0);
        reverseListener.Start();
        localServiceListener.Start();

        var reversePort = ((IPEndPoint)reverseListener.LocalEndpoint).Port;
        var localServicePort = ((IPEndPoint)localServiceListener.LocalEndpoint).Port;
        var localOutbound = new CapturingTcpForwardOutboundHandler();
        var localDispatcher = CreateReverseBridgeDispatcher(localOutbound, "direct");
        var muxInboundServer = new TrojanMuxInboundServer(
            localDispatcher,
            new RateLimiterRegistry(),
            new TrafficRegistry());
        var serviceProvider = new StaticReverseServiceProvider(localDispatcher, muxInboundServer);
        var settings = new VlessOutboundSettings
        {
            Tag = "bridge",
            ServerHost = IPAddress.Loopback.ToString(),
            ServerPort = reversePort,
            Transport = VlessOutboundTransports.Tcp,
            UserUuid = "11111111-1111-1111-1111-111111111111",
            ReverseTag = "reverse-edge",
            TestPre = 1
        };
        var handler = new VlessOutboundHandler(
            new VlessOutboundClient(),
            new StaticVlessOutboundSettingsProvider(settings),
            new VlessUdpPacketReader(),
            new VlessUdpPacketWriter(),
            serviceProvider);
        await using var _ = handler;

        var localServiceTask = Task.Run(async () =>
        {
            using var client = await localServiceListener.AcceptTcpClientAsync(cts.Token);
            await using var stream = client.GetStream();

            var payload = new byte[4];
            await stream.ReadExactlyAsync(payload.AsMemory(0, payload.Length), cts.Token);
            await stream.WriteAsync(Encoding.ASCII.GetBytes("pong"), cts.Token);
            await stream.FlushAsync(cts.Token);
            return Encoding.ASCII.GetString(payload);
        }, cts.Token);

        var reverseServerTask = Task.Run(async () =>
        {
            using var client = await reverseListener.AcceptTcpClientAsync(cts.Token);
            await using var stream = client.GetStream();

            var request = await new VlessHandshakeReader().ReadAsync(stream, cts.Token);
            await VlessHandshakeReader.WriteResponseAsync(stream, request.Version, cts.Token);

            await TrojanMuxFrameCodec.WriteAsync(
                stream,
                new TrojanMuxFrame
                {
                    SessionId = 1,
                    Status = TrojanMuxSessionStatus.New,
                    Option = TrojanMuxFrameOption.Data,
                    Target = new TrojanMuxFrameTarget(IPAddress.Loopback.ToString(), localServicePort, DispatchNetwork.Tcp),
                    Source = new TrojanMuxFrameTarget("203.0.113.25", 50000, DispatchNetwork.Tcp),
                    Local = new TrojanMuxFrameTarget("198.51.100.8", 8443, DispatchNetwork.Tcp),
                    Payload = Encoding.ASCII.GetBytes("ping")
                },
                cts.Token);
            await stream.FlushAsync(cts.Token);

            var responseFrame = await TrojanMuxFrameCodec.ReadAsync(stream, cts.Token)
                ?? throw new InvalidDataException("Expected reverse TCP response frame.");
            var endFrame = await TrojanMuxFrameCodec.ReadAsync(stream, cts.Token)
                ?? throw new InvalidDataException("Expected reverse TCP end frame.");
            return new ReverseTcpCapture(request, responseFrame, endFrame);
        }, cts.Token);

        handler.Start();

        var localPayload = await localServiceTask;
        var reverseCapture = await reverseServerTask;
        var dispatchContext = await localOutbound.ContextTcs.Task.WaitAsync(cts.Token);
        var destination = await localOutbound.DestinationTcs.Task.WaitAsync(cts.Token);

        Assert.Equal("ping", localPayload);
        Assert.Equal(VlessCommand.Rvs, reverseCapture.Request.Command);
        Assert.Equal("v1.rvs.cool", reverseCapture.Request.TargetHost);
        Assert.Equal(0, reverseCapture.Request.TargetPort);

        Assert.Equal((ushort)1, reverseCapture.ResponseFrame.SessionId);
        Assert.Equal(TrojanMuxSessionStatus.Keep, reverseCapture.ResponseFrame.Status);
        Assert.Equal(TrojanMuxFrameOption.Data, reverseCapture.ResponseFrame.Option);
        Assert.Equal("pong", Encoding.ASCII.GetString(reverseCapture.ResponseFrame.Payload));
        Assert.Null(reverseCapture.ResponseFrame.Target);

        Assert.Equal((ushort)1, reverseCapture.EndFrame.SessionId);
        Assert.Equal(TrojanMuxSessionStatus.End, reverseCapture.EndFrame.Status);

        Assert.Equal(InboundProtocols.Vless, dispatchContext.InboundProtocol);
        Assert.Equal("reverse-edge", dispatchContext.InboundTag);
        Assert.Equal(settings.UserUuid, dispatchContext.UserId);
        Assert.Equal(RoutingNetworks.Tcp, dispatchContext.InboundSourceNetwork);
        var tcpSource = Assert.IsType<IPEndPoint>(dispatchContext.SourceEndPoint);
        var tcpLocal = Assert.IsType<IPEndPoint>(dispatchContext.LocalEndPoint);
        Assert.Equal("203.0.113.25", tcpSource.Address.ToString());
        Assert.Equal(50000, tcpSource.Port);
        Assert.Equal("198.51.100.8", tcpLocal.Address.ToString());
        Assert.Equal(8443, tcpLocal.Port);
        Assert.Collection(
            dispatchContext.SourceAddresses,
            address => Assert.Equal("203.0.113.25", address.ToString()));
        Assert.Collection(
            dispatchContext.LocalAddresses,
            address => Assert.Equal("198.51.100.8", address.ToString()));
        Assert.Equal(IPAddress.Loopback.ToString(), destination.Host);
        Assert.Equal(localServicePort, destination.Port);
        Assert.Equal(0, GetPreconnectStateCount(handler));
    }

    [Fact]
    public async Task Start_establishes_reverse_portal_and_dispatches_udp_sessions_locally()
    {
        using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(15));
        using var reverseListener = new TcpListener(IPAddress.Loopback, 0);
        reverseListener.Start();

        var reversePort = ((IPEndPoint)reverseListener.LocalEndpoint).Port;
        var localOutbound = new CapturingEchoUdpOutboundHandler();
        var localDispatcher = CreateReverseBridgeDispatcher(localOutbound, "udp-target");
        var muxInboundServer = new TrojanMuxInboundServer(
            localDispatcher,
            new RateLimiterRegistry(),
            new TrafficRegistry());
        var serviceProvider = new StaticReverseServiceProvider(localDispatcher, muxInboundServer);
        var settings = new VlessOutboundSettings
        {
            Tag = "bridge",
            ServerHost = IPAddress.Loopback.ToString(),
            ServerPort = reversePort,
            Transport = VlessOutboundTransports.Tcp,
            UserUuid = "11111111-1111-1111-1111-111111111111",
            ReverseTag = "reverse-edge"
        };
        var handler = new VlessOutboundHandler(
            new VlessOutboundClient(),
            new StaticVlessOutboundSettingsProvider(settings),
            new VlessUdpPacketReader(),
            new VlessUdpPacketWriter(),
            serviceProvider);
        await using var _ = handler;

        var reverseServerTask = Task.Run(async () =>
        {
            using var client = await reverseListener.AcceptTcpClientAsync(cts.Token);
            await using var stream = client.GetStream();

            var request = await new VlessHandshakeReader().ReadAsync(stream, cts.Token);
            await VlessHandshakeReader.WriteResponseAsync(stream, request.Version, cts.Token);

            await TrojanMuxFrameCodec.WriteAsync(
                stream,
                new TrojanMuxFrame
                {
                    SessionId = 2,
                    Status = TrojanMuxSessionStatus.New,
                    Option = TrojanMuxFrameOption.Data,
                    Target = new TrojanMuxFrameTarget("1.1.1.1", 53, DispatchNetwork.Udp),
                    Source = new TrojanMuxFrameTarget("203.0.113.25", 50000, DispatchNetwork.Udp),
                    Local = new TrojanMuxFrameTarget("198.51.100.8", 5353, DispatchNetwork.Udp),
                    Payload = Encoding.ASCII.GetBytes("ping")
                },
                cts.Token);
            await stream.FlushAsync(cts.Token);

            var responseFrame = await TrojanMuxFrameCodec.ReadAsync(stream, cts.Token)
                ?? throw new InvalidDataException("Expected reverse UDP response frame.");
            await TrojanMuxFrameCodec.WriteAsync(
                stream,
                new TrojanMuxFrame
                {
                    SessionId = 2,
                    Status = TrojanMuxSessionStatus.End
                },
                cts.Token);
            await stream.FlushAsync(cts.Token);

            return new ReverseUdpCapture(request, responseFrame);
        }, cts.Token);

        handler.Start();

        var reverseCapture = await reverseServerTask;
        var dispatchContext = await localOutbound.ContextTcs.Task.WaitAsync(cts.Token);
        var udpCapture = await localOutbound.CaptureTcs.Task.WaitAsync(cts.Token);

        Assert.Equal(VlessCommand.Rvs, reverseCapture.Request.Command);
        Assert.Equal("v1.rvs.cool", reverseCapture.Request.TargetHost);
        Assert.Equal(0, reverseCapture.Request.TargetPort);

        Assert.Equal((ushort)2, reverseCapture.ResponseFrame.SessionId);
        Assert.Equal(TrojanMuxSessionStatus.Keep, reverseCapture.ResponseFrame.Status);
        Assert.Equal(TrojanMuxFrameOption.Data, reverseCapture.ResponseFrame.Option);
        Assert.NotNull(reverseCapture.ResponseFrame.Target);
        Assert.Equal("1.1.1.1", reverseCapture.ResponseFrame.Target!.Host);
        Assert.Equal(53, reverseCapture.ResponseFrame.Target.Port);
        Assert.Equal(DispatchNetwork.Udp, reverseCapture.ResponseFrame.Target.Network);
        Assert.Equal("pong", Encoding.ASCII.GetString(reverseCapture.ResponseFrame.Payload));

        Assert.Equal(InboundProtocols.Vless, dispatchContext.InboundProtocol);
        Assert.Equal("reverse-edge", dispatchContext.InboundTag);
        Assert.Equal(settings.UserUuid, dispatchContext.UserId);
        Assert.Equal(RoutingNetworks.Udp, dispatchContext.InboundSourceNetwork);
        var udpSource = Assert.IsType<IPEndPoint>(dispatchContext.SourceEndPoint);
        var udpLocal = Assert.IsType<IPEndPoint>(dispatchContext.LocalEndPoint);
        Assert.Equal("203.0.113.25", udpSource.Address.ToString());
        Assert.Equal(50000, udpSource.Port);
        Assert.Equal("198.51.100.8", udpLocal.Address.ToString());
        Assert.Equal(5353, udpLocal.Port);
        Assert.Collection(
            dispatchContext.SourceAddresses,
            address => Assert.Equal("203.0.113.25", address.ToString()));
        Assert.Collection(
            dispatchContext.LocalAddresses,
            address => Assert.Equal("198.51.100.8", address.ToString()));
        Assert.Equal("1.1.1.1", udpCapture.Host);
        Assert.Equal(53, udpCapture.Port);
        Assert.Equal("ping", udpCapture.PayloadText);
    }

    private static IDispatcher CreateDispatcher(
        VlessOutboundSettings settings,
        out VlessOutboundHandler handler,
        VlessOutboundClient? client = null)
    {
        handler = new VlessOutboundHandler(
            client ?? new VlessOutboundClient(),
            new StaticVlessOutboundSettingsProvider(settings),
            new VlessUdpPacketReader(),
            new VlessUdpPacketWriter());

        return new DefaultDispatcher(
            new DefaultOutboundRouter(
                new IOutboundHandler[]
                {
                    new FreedomOutboundHandler(),
                    handler
                },
                new StaticOutboundRuntimePlanProvider(
                    new OutboundRuntimePlan
                    {
                        Outbounds =
                        [
                            new OutboundRuntime
                            {
                                Tag = settings.Tag,
                                Protocol = OutboundProtocols.Vless
                            }
                        ],
                        DefaultOutboundTag = settings.Tag
                    })));
    }

    private static IDispatcher CreateDispatcher(VlessOutboundSettings settings, VlessOutboundClient? client = null)
        => CreateDispatcher(settings, out _, client);

    private static IDispatcher CreateReverseBridgeDispatcher(
        IOutboundHandler targetHandler,
        string targetTag)
        => new DefaultDispatcher(
            new DefaultOutboundRouter(
                new IOutboundHandler[]
                {
                    new ThrowingOutboundHandler("blocked"),
                    targetHandler
                },
                new StaticOutboundRuntimePlanProvider(
                    new OutboundRuntimePlan
                    {
                        Outbounds =
                        [
                            new OutboundRuntime
                            {
                                Tag = "blocked",
                                Protocol = "blocked"
                            },
                            new OutboundRuntime
                            {
                                Tag = targetTag,
                                Protocol = targetHandler.Protocol
                            }
                        ],
                        RoutingRules =
                        [
                            new RoutingRuleRuntime
                            {
                                InboundTags = ["reverse-edge"],
                                OutboundTag = targetTag
                            }
                        ],
                        DefaultOutboundTag = "blocked"
                    })));

    private static int GetPreconnectStateCount(VlessOutboundHandler handler)
    {
        var field = typeof(VlessOutboundHandler).GetField("_preconnectStates", BindingFlags.Instance | BindingFlags.NonPublic)
            ?? throw new InvalidOperationException("Could not access VLESS preconnect states.");
        var value = field.GetValue(handler)
            ?? throw new InvalidOperationException("VLESS preconnect states are unavailable.");
        var countProperty = value.GetType().GetProperty("Count")
            ?? throw new InvalidOperationException("VLESS preconnect state count is unavailable.");
        return (int)(countProperty.GetValue(value) ?? 0);
    }

    private static async Task<UdpCapture> CaptureUdpSessionAsync(
        TcpListener listener,
        CancellationToken cancellationToken)
    {
        using var client = await listener.AcceptTcpClientAsync(cancellationToken);
        await using var stream = client.GetStream();

        var handshakeReader = new VlessHandshakeReader();
        var packetReader = new VlessUdpPacketReader();
        var packetWriter = new VlessUdpPacketWriter();

        var request = await handshakeReader.ReadAsync(stream, cancellationToken);
        await VlessHandshakeReader.WriteResponseAsync(stream, request.Version, cancellationToken);

        var packet = await packetReader.ReadAsync(stream, cancellationToken)
            ?? throw new InvalidDataException("Expected a VLESS UDP packet.");

        var responsePayload = request.TargetHost switch
        {
            "8.8.8.8" => "pong-1",
            "1.1.1.1" => "pong-2",
            _ => "pong"
        };

        await packetWriter.WriteAsync(stream, Encoding.ASCII.GetBytes(responsePayload), cancellationToken);
        await stream.FlushAsync(cancellationToken);

        return new UdpCapture(request, Encoding.ASCII.GetString(packet));
    }

    private static async Task<XudpCapture> CaptureXudpSessionAsync(
        TcpListener listener,
        CancellationToken cancellationToken)
    {
        using var client = await listener.AcceptTcpClientAsync(cancellationToken);
        await using var stream = client.GetStream();

        var request = await new VlessHandshakeReader().ReadAsync(stream, cancellationToken);
        await VlessHandshakeReader.WriteResponseAsync(stream, request.Version, cancellationToken);

        var firstFrame = await TrojanMuxFrameCodec.ReadAsync(stream, cancellationToken)
            ?? throw new InvalidDataException("Expected the first XUDP mux frame.");
        var secondFrame = await TrojanMuxFrameCodec.ReadAsync(stream, cancellationToken)
            ?? throw new InvalidDataException("Expected the second XUDP mux frame.");

        await TrojanMuxFrameCodec.WriteAsync(
            stream,
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
            stream,
            new TrojanMuxFrame
            {
                SessionId = 0,
                Status = TrojanMuxSessionStatus.Keep,
                Option = TrojanMuxFrameOption.Data,
                Target = new TrojanMuxFrameTarget("1.1.1.1", 4321, DispatchNetwork.Udp),
                Payload = Encoding.ASCII.GetBytes("pong-2")
            },
            cancellationToken);
        await stream.FlushAsync(cancellationToken);

        return new XudpCapture(request, [firstFrame, secondFrame]);
    }

    private static async Task<TcpCapture> CaptureVisionTcpSessionAsync(
        TcpListener listener,
        CancellationToken cancellationToken)
    {
        using var client = await listener.AcceptTcpClientAsync(cancellationToken);
        await using var stream = client.GetStream();

        var request = await new VlessHandshakeReader().ReadAsync(stream, cancellationToken);
        await VlessHandshakeReader.WriteResponseAsync(stream, request.Version, cancellationToken);

        Span<byte> userBytes = stackalloc byte[VlessVisionPaddingCodec.UserUuidLength];
        Assert.True(ProtocolUuid.TryWriteBytes(request.UserUuid, userBytes));

        await using var visionStream = new VlessVisionDuplexStream(
            stream,
            new VlessVisionTrafficState(userBytes),
            readIsUplink: true,
            writeIsUplink: false);

        var payload = new byte[4];
        await visionStream.ReadExactlyAsync(payload.AsMemory(0, payload.Length), cancellationToken);
        await visionStream.WriteAsync(Encoding.ASCII.GetBytes("pong"), cancellationToken);
        await visionStream.FlushAsync(cancellationToken);

        return new TcpCapture(request, Encoding.ASCII.GetString(payload));
    }

    private static async Task<VisionFrameCapture> CaptureVisionFrameSessionAsync(
        TcpListener listener,
        CancellationToken cancellationToken)
    {
        using var client = await listener.AcceptTcpClientAsync(cancellationToken);
        await using var stream = client.GetStream();

        var request = await new VlessHandshakeReader().ReadAsync(stream, cancellationToken);
        await VlessHandshakeReader.WriteResponseAsync(stream, request.Version, cancellationToken);

        var prefix = new byte[VlessVisionPaddingCodec.InitialFramePrefixLength];
        await stream.ReadExactlyAsync(prefix.AsMemory(0, prefix.Length), cancellationToken);

        Assert.Equal(request.UserUuid, ProtocolUuid.Format(prefix.AsSpan(0, VlessVisionPaddingCodec.UserUuidLength)));

        var command = prefix[VlessVisionPaddingCodec.UserUuidLength];
        var contentLength = BinaryPrimitives.ReadUInt16BigEndian(
            prefix.AsSpan(VlessVisionPaddingCodec.UserUuidLength + 1, 2));
        var paddingLength = BinaryPrimitives.ReadUInt16BigEndian(
            prefix.AsSpan(VlessVisionPaddingCodec.UserUuidLength + 3, 2));

        var payload = new byte[contentLength];
        await stream.ReadExactlyAsync(payload.AsMemory(0, payload.Length), cancellationToken);

        if (paddingLength > 0)
        {
            var padding = new byte[paddingLength];
            await stream.ReadExactlyAsync(padding.AsMemory(0, padding.Length), cancellationToken);
        }

        Span<byte> userBytes = stackalloc byte[VlessVisionPaddingCodec.UserUuidLength];
        Assert.True(ProtocolUuid.TryWriteBytes(request.UserUuid, userBytes));

        await using var visionStream = new VlessVisionDuplexStream(
            stream,
            new VlessVisionTrafficState(userBytes),
            readIsUplink: true,
            writeIsUplink: false);
        await visionStream.WriteAsync(Encoding.ASCII.GetBytes("pong"), cancellationToken);
        await visionStream.FlushAsync(cancellationToken);

        return new VisionFrameCapture(
            request,
            command,
            contentLength,
            paddingLength,
            Encoding.ASCII.GetString(payload));
    }

    private static async Task<XudpCapture> CaptureVisionXudpSessionAsync(
        TcpListener listener,
        CancellationToken cancellationToken)
    {
        using var client = await listener.AcceptTcpClientAsync(cancellationToken);
        await using var stream = client.GetStream();

        var request = await new VlessHandshakeReader().ReadAsync(stream, cancellationToken);
        await VlessHandshakeReader.WriteResponseAsync(stream, request.Version, cancellationToken);

        Span<byte> userBytes = stackalloc byte[VlessVisionPaddingCodec.UserUuidLength];
        Assert.True(ProtocolUuid.TryWriteBytes(request.UserUuid, userBytes));

        await using var visionStream = new VlessVisionDuplexStream(
            stream,
            new VlessVisionTrafficState(userBytes),
            readIsUplink: true,
            writeIsUplink: false);

        var firstFrame = await TrojanMuxFrameCodec.ReadAsync(visionStream, cancellationToken)
            ?? throw new InvalidDataException("Expected the first Vision XUDP mux frame.");

        await TrojanMuxFrameCodec.WriteAsync(
            visionStream,
            new TrojanMuxFrame
            {
                SessionId = 0,
                Status = TrojanMuxSessionStatus.Keep,
                Option = TrojanMuxFrameOption.Data,
                Target = new TrojanMuxFrameTarget("8.8.8.8", 443, DispatchNetwork.Udp),
                Payload = Encoding.ASCII.GetBytes("pong")
            },
            cancellationToken);
        await visionStream.FlushAsync(cancellationToken);

        return new XudpCapture(request, [firstFrame]);
    }

    private static VlessOutboundClient CreateVisionClient()
        => new(
            new VlessHandshakeWriter(),
            dnsResolver: null,
            new RuntimeInternetProfile(
                [new TestTcpTransportFactory()],
                [new FakeTlsSecurityFactory()]));

    private static VlessOutboundClient CreateRealityVisionClient()
        => new(
            new VlessHandshakeWriter(),
            dnsResolver: null,
            TestRuntimeInternetProfileFactory.CreateWithRecordingSecurity(
                new TestRuntimeInternetProfileFactory.RecordingPassThroughSecurityFactory(
                    RuntimeInternetSecurityTypes.Reality,
                    "tls13")));

    private static VlessOutboundClient CreateWsClient()
        => new(
            new VlessHandshakeWriter(),
            dnsResolver: null,
            new RuntimeInternetProfile(
                [new TestWebSocketTransportFactory()],
                [new TestNoSecurityFactory()]));

    private static RuntimeRealityOptions CreateValidRealityOptions()
    {
        var publicKey = new byte[32];
        for (var index = 0; index < publicKey.Length; index++)
        {
            publicKey[index] = checked((byte)(index + 1));
        }

        return new RuntimeRealityOptions
        {
            Fingerprint = "chrome",
            PublicKey = ToBase64Url(publicKey),
            ShortId = "01"
        };
    }

    private static string ToBase64Url(byte[] bytes)
        => Convert.ToBase64String(bytes)
            .TrimEnd('=')
            .Replace('+', '-')
            .Replace('/', '_');

    private sealed class FakeRealityHandshakeProvider : IRuntimeRealityHandshakeProvider
    {
        public string Identity => "vless-outbound-test-provider";

        public bool WasCalled { get; private set; }

        public string LastServerName { get; private set; } = string.Empty;

        public string LastTransportProtocol { get; private set; } = string.Empty;

        public ValueTask<RuntimeRealityHandshakeResult> SecureAsync(
            RuntimeRealityHandshakeRequest request,
            CancellationToken cancellationToken)
        {
            WasCalled = true;
            LastServerName = request.ServerName;
            LastTransportProtocol = request.TransportProtocol;

            var tlsStream = new FakeTlsStream(request.TransportStream);
            return ValueTask.FromResult(new RuntimeRealityHandshakeResult
            {
                TransportStream = tlsStream,
                SslStream = tlsStream,
                SecurityState = RuntimeInternetSecurityState.Create(
                    RuntimeInternetSecurityTypes.Reality,
                    SslProtocols.Tls13,
                    request.ApplicationProtocols.FirstOrDefault())
            });
        }
    }

    private sealed class StaticVlessOutboundSettingsProvider : IVlessOutboundSettingsProvider
    {
        private readonly VlessOutboundSettings _settings;

        public StaticVlessOutboundSettingsProvider(VlessOutboundSettings settings)
        {
            _settings = settings;
        }

        public bool TryResolve(DispatchContext context, out VlessOutboundSettings settings)
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

    private sealed record ReverseTcpCapture(
        VlessRequest Request,
        TrojanMuxFrame ResponseFrame,
        TrojanMuxFrame EndFrame);

    private sealed record ReverseUdpCapture(
        VlessRequest Request,
        TrojanMuxFrame ResponseFrame);

    private sealed record TcpCapture(VlessRequest Request, string PayloadText);

    private sealed record UdpCapture(VlessRequest Request, string PayloadText);

    private sealed record XudpCapture(VlessRequest Request, TrojanMuxFrame[] Frames);

    private sealed record UdpSendCapture(string Host, int Port, string PayloadText);

    private sealed class ThrowingOutboundHandler : IOutboundHandler
    {
        public ThrowingOutboundHandler(string protocol)
        {
            Protocol = protocol;
        }

        public string Protocol { get; }

        public ValueTask<Stream> OpenTcpAsync(
            DispatchContext context,
            DispatchDestination destination,
            CancellationToken cancellationToken)
            => throw new InvalidOperationException($"Unexpected outbound route for protocol '{Protocol}'.");

        public ValueTask<IOutboundUdpTransport> OpenUdpAsync(
            DispatchContext context,
            CancellationToken cancellationToken)
            => throw new InvalidOperationException($"Unexpected outbound route for protocol '{Protocol}'.");
    }

    private sealed class CapturingTcpForwardOutboundHandler : IOutboundHandler
    {
        private readonly FreedomOutboundHandler _inner = new();

        public TaskCompletionSource<DispatchContext> ContextTcs { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);

        public TaskCompletionSource<DispatchDestination> DestinationTcs { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);

        public string Protocol => _inner.Protocol;

        public async ValueTask<Stream> OpenTcpAsync(
            DispatchContext context,
            DispatchDestination destination,
            CancellationToken cancellationToken)
        {
            ContextTcs.TrySetResult(context);
            DestinationTcs.TrySetResult(destination);
            return await _inner.OpenTcpAsync(context, destination, cancellationToken);
        }

        public ValueTask<IOutboundUdpTransport> OpenUdpAsync(
            DispatchContext context,
            CancellationToken cancellationToken)
            => throw new NotSupportedException();
    }

    private sealed class CapturingEchoUdpOutboundHandler : IOutboundHandler
    {
        public TaskCompletionSource<DispatchContext> ContextTcs { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);

        public TaskCompletionSource<UdpSendCapture> CaptureTcs { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);

        public string Protocol => "echo-udp";

        public ValueTask<Stream> OpenTcpAsync(
            DispatchContext context,
            DispatchDestination destination,
            CancellationToken cancellationToken)
            => throw new NotSupportedException();

        public ValueTask<IOutboundUdpTransport> OpenUdpAsync(
            DispatchContext context,
            CancellationToken cancellationToken)
        {
            ContextTcs.TrySetResult(context);
            return ValueTask.FromResult<IOutboundUdpTransport>(new CapturingEchoUdpTransport(CaptureTcs));
        }
    }

    private sealed class CapturingEchoUdpTransport : IOutboundUdpTransport
    {
        private readonly TaskCompletionSource<UdpSendCapture> _captureTcs;
        private readonly Channel<DispatchDatagram> _responses = Channel.CreateUnbounded<DispatchDatagram>();

        public CapturingEchoUdpTransport(TaskCompletionSource<UdpSendCapture> captureTcs)
        {
            _captureTcs = captureTcs;
        }

        public ValueTask SendAsync(
            DispatchDestination destination,
            ReadOnlyMemory<byte> payload,
            CancellationToken cancellationToken)
        {
            _captureTcs.TrySetResult(new UdpSendCapture(
                destination.Host,
                destination.Port,
                Encoding.ASCII.GetString(payload.Span)));
            _responses.Writer.TryWrite(
                new DispatchDatagram
                {
                    SourceHost = destination.Host,
                    SourcePort = destination.Port,
                    Payload = Encoding.ASCII.GetBytes("pong")
                });
            return ValueTask.CompletedTask;
        }

        public async ValueTask<DispatchDatagram?> ReceiveAsync(CancellationToken cancellationToken)
            => await _responses.Reader.ReadAsync(cancellationToken);

        public ValueTask DisposeAsync()
        {
            _responses.Writer.TryComplete();
            return ValueTask.CompletedTask;
        }
    }

    private sealed class StaticReverseServiceProvider : IServiceProvider
    {
        private readonly IDispatcher _dispatcher;
        private readonly TrojanMuxInboundServer _muxInboundServer;

        public StaticReverseServiceProvider(
            IDispatcher dispatcher,
            TrojanMuxInboundServer muxInboundServer)
        {
            _dispatcher = dispatcher;
            _muxInboundServer = muxInboundServer;
        }

        public object? GetService(Type serviceType)
            => serviceType == typeof(IDispatcher)
                ? _dispatcher
                : serviceType == typeof(TrojanMuxInboundServer)
                    ? _muxInboundServer
                    : null;
    }

    private sealed record VisionFrameCapture(
        VlessRequest Request,
        byte Command,
        int ContentLength,
        int PaddingLength,
        string PayloadText);

    private sealed class TestTcpTransportFactory : IRuntimeInternetTransportFactory
    {
        public string Name => RuntimeInternetTransportProtocols.Tcp;

        public ValueTask ApplyAsync(
            RuntimeInternetConnectionContext context,
            RuntimeInternetStack stack,
            IRuntimeInternetOptions options,
            byte[]? transportInitializationData,
            CancellationToken cancellationToken)
            => ValueTask.CompletedTask;
    }

    private sealed class TestWebSocketTransportFactory : IRuntimeInternetTransportFactory
    {
        public string Name => RuntimeInternetTransportProtocols.Ws;

        public async ValueTask ApplyAsync(
            RuntimeInternetConnectionContext context,
            RuntimeInternetStack stack,
            IRuntimeInternetOptions options,
            byte[]? transportInitializationData,
            CancellationToken cancellationToken)
        {
            if (transportInitializationData is null || transportInitializationData.Length == 0)
            {
                return;
            }

            await context.TransportStream.WriteAsync(transportInitializationData, cancellationToken);
            await context.TransportStream.FlushAsync(cancellationToken);
        }
    }

    private sealed class TestNoSecurityFactory : IRuntimeInternetSecurityFactory
    {
        public string Name => RuntimeInternetSecurityTypes.None;

        public ValueTask ApplyAsync(
            RuntimeInternetConnectionContext context,
            RuntimeInternetStack stack,
            IRuntimeInternetOptions options,
            CancellationToken cancellationToken)
            => ValueTask.CompletedTask;
    }

    private sealed class FakeTlsSecurityFactory : IRuntimeInternetSecurityFactory
    {
        public string Name => RuntimeInternetSecurityTypes.Tls;

        public ValueTask ApplyAsync(
            RuntimeInternetConnectionContext context,
            RuntimeInternetStack stack,
            IRuntimeInternetOptions options,
            CancellationToken cancellationToken)
        {
            var sslStream = new FakeTlsStream(context.TransportStream);
            context.SetTransportStream(sslStream, sslStream, "tls13");
            return ValueTask.CompletedTask;
        }
    }

    private sealed class FakeTlsStream : SslStream
    {
        private readonly Stream _innerStream;

        public FakeTlsStream(Stream innerStream)
            : base(innerStream, leaveInnerStreamOpen: false)
        {
            _innerStream = innerStream;
        }

        public override SslProtocols SslProtocol => SslProtocols.Tls13;

        public override bool CanRead => _innerStream.CanRead;

        public override bool CanSeek => false;

        public override bool CanWrite => _innerStream.CanWrite;

        public override bool CanTimeout => _innerStream.CanTimeout;

        public override long Length => throw new NotSupportedException();

        public override long Position
        {
            get => throw new NotSupportedException();
            set => throw new NotSupportedException();
        }

        public override int ReadTimeout
        {
            get => _innerStream.ReadTimeout;
            set => _innerStream.ReadTimeout = value;
        }

        public override int WriteTimeout
        {
            get => _innerStream.WriteTimeout;
            set => _innerStream.WriteTimeout = value;
        }

        public override void Flush()
            => _innerStream.Flush();

        public override Task FlushAsync(CancellationToken cancellationToken)
            => _innerStream.FlushAsync(cancellationToken);

        public override int Read(byte[] buffer, int offset, int count)
            => _innerStream.Read(buffer, offset, count);

        public override ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken cancellationToken = default)
            => _innerStream.ReadAsync(buffer, cancellationToken);

        public override Task<int> ReadAsync(byte[] buffer, int offset, int count, CancellationToken cancellationToken)
            => _innerStream.ReadAsync(buffer, offset, count, cancellationToken);

        public override void Write(byte[] buffer, int offset, int count)
            => _innerStream.Write(buffer, offset, count);

        public override ValueTask WriteAsync(ReadOnlyMemory<byte> buffer, CancellationToken cancellationToken = default)
            => _innerStream.WriteAsync(buffer, cancellationToken);

        public override Task WriteAsync(byte[] buffer, int offset, int count, CancellationToken cancellationToken)
            => _innerStream.WriteAsync(buffer, offset, count, cancellationToken);

        public override long Seek(long offset, SeekOrigin origin)
            => throw new NotSupportedException();

        public override void SetLength(long value)
            => throw new NotSupportedException();
    }
}

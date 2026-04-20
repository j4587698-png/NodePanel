using System.Buffers.Binary;
using System.Net;
using System.Net.Sockets;
using System.Security.Authentication;
using System.Security.Cryptography;
using System.Text;
using NodePanel.Core.Protocol;
using NodePanel.Core.Runtime;

namespace NodePanel.Core.Tests;

public sealed class VlessInboundConnectionHandlerTests
{
    [Fact]
    public async Task HandleAsync_rejects_vision_when_user_flow_missing()
    {
        var handler = CreateHandler();
        var uuid = "11111111-1111-1111-1111-111111111111";
        var stream = new RecordingDuplexStream(BuildHandshake(
            uuid,
            VlessCommand.Connect,
            addons: new VlessHeaderAddons
            {
                Flow = VlessFlowTypes.Vision
            }));

        var exception = await Assert.ThrowsAsync<InvalidOperationException>(() => handler.HandleAsync(
            stream,
            CreateOptions(new VlessUser
            {
                UserId = "user-a",
                Uuid = uuid,
                BytesPerSecond = 0,
                DeviceLimit = 0
            }),
            CancellationToken.None));

        Assert.Contains("not allowed", exception.Message, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task HandleAsync_rejects_empty_client_flow_for_vision_tcp_user()
    {
        var handler = CreateHandler();
        var uuid = "11111111-1111-1111-1111-111111111111";
        var stream = new RecordingDuplexStream(BuildHandshake(uuid, VlessCommand.Connect));

        var exception = await Assert.ThrowsAsync<InvalidOperationException>(() => handler.HandleAsync(
            stream,
            CreateOptions(new VlessUser
            {
                UserId = "user-a",
                Uuid = uuid,
                Flow = VlessFlowTypes.Vision,
                BytesPerSecond = 0,
                DeviceLimit = 0
            }),
            CancellationToken.None));

        Assert.Contains("requires request flow", exception.Message, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task HandleAsync_rejects_empty_client_flow_for_vision_non_xudp_mux()
    {
        var handler = CreateHandler();
        var uuid = "11111111-1111-1111-1111-111111111111";
        var stream = new RecordingDuplexStream(BuildMuxRequest(
            uuid,
            BuildMuxFrame(
                sessionId: 1,
                "example.org",
                443,
                DispatchNetwork.Tcp,
                Encoding.ASCII.GetBytes("ping"))));

        var exception = await Assert.ThrowsAsync<InvalidOperationException>(() => handler.HandleAsync(
            stream,
            CreateOptions(new VlessUser
            {
                UserId = "user-a",
                Uuid = uuid,
                Flow = VlessFlowTypes.Vision,
                BytesPerSecond = 0,
                DeviceLimit = 0
            }),
            CancellationToken.None));

        Assert.Contains("requires request flow", exception.Message, StringComparison.OrdinalIgnoreCase);
        Assert.Empty(stream.GetWrittenBytes());
    }

    [Fact]
    public async Task HandleAsync_rejects_forward_proxy_for_reverse_only_user()
    {
        var handler = CreateHandler();
        var uuid = "11111111-1111-1111-1111-111111111111";
        var stream = new RecordingDuplexStream(BuildHandshake(uuid, VlessCommand.Connect));

        var exception = await Assert.ThrowsAsync<InvalidOperationException>(() => handler.HandleAsync(
            stream,
            CreateOptions(new VlessUser
            {
                UserId = "user-a",
                Uuid = uuid,
                ReverseTag = "reverse-edge",
                BytesPerSecond = 0,
                DeviceLimit = 0
            }),
            CancellationToken.None));

        Assert.Contains("only allowed to use reverse proxy", exception.Message, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task HandleAsync_allows_empty_client_flow_for_vision_xudp_mux()
    {
        var dispatcher = new RecordingUdpDispatcher();
        var handler = CreateHandler(dispatcher: dispatcher);
        var uuid = "11111111-1111-1111-1111-111111111111";
        var stream = new RecordingDuplexStream(BuildMuxRequest(
            uuid,
            BuildMuxFrame(
                sessionId: 0,
                "8.8.8.8",
                53,
                DispatchNetwork.Udp,
                Encoding.ASCII.GetBytes("ping"),
                globalId: [1, 2, 3, 4, 5, 6, 7, 8])));

        await handler.HandleAsync(
            stream,
            CreateOptions(new VlessUser
            {
                UserId = "user-a",
                Uuid = uuid,
                Flow = VlessFlowTypes.Vision,
                BytesPerSecond = 0,
                DeviceLimit = 0
            }),
            CancellationToken.None);

        var capture = await dispatcher.Transport.CaptureTcs.Task.WaitAsync(TimeSpan.FromSeconds(1));
        Assert.Equal("8.8.8.8", capture.Host);
        Assert.Equal(53, capture.Port);
        Assert.Equal("ping", capture.Payload);

        var written = stream.GetWrittenBytes();
        Assert.True(written.Length is 2 or 8, $"Written bytes: {Convert.ToHexString(written)}");
        Assert.Equal(0, written[0]);
        Assert.Equal(0, written[1]);

        if (written.Length > 2)
        {
            var responseFrame = await TrojanMuxFrameCodec.ReadAsync(
                new MemoryStream(written, 2, written.Length - 2, writable: false),
                CancellationToken.None);
            Assert.NotNull(responseFrame);
            Assert.Equal(TrojanMuxSessionStatus.End, responseFrame!.Status);
            Assert.Equal((ushort)0, responseFrame.SessionId);
        }
    }

    [Fact]
    public async Task HandleAsync_rejects_vision_udp()
    {
        var handler = CreateHandler();
        var uuid = "11111111-1111-1111-1111-111111111111";
        var stream = new RecordingDuplexStream(BuildHandshake(
            uuid,
            VlessCommand.Udp,
            addons: new VlessHeaderAddons
            {
                Flow = VlessFlowTypes.Vision
            }));

        var exception = await Assert.ThrowsAsync<NotSupportedException>(() => handler.HandleAsync(
            stream,
            CreateOptions(new VlessUser
            {
                UserId = "user-a",
                Uuid = uuid,
                Flow = VlessFlowTypes.Vision,
                BytesPerSecond = 0,
                DeviceLimit = 0
            }),
            CancellationToken.None));

        Assert.Contains("does not support udp", exception.Message, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task HandleAsync_rejects_vision_over_tls12()
    {
        var handler = CreateHandler();
        var uuid = "11111111-1111-1111-1111-111111111111";
        var stream = new RecordingDuplexStream(BuildHandshake(
            uuid,
            VlessCommand.Connect,
            addons: new VlessHeaderAddons
            {
                Flow = VlessFlowTypes.Vision
            }));

        var exception = await Assert.ThrowsAsync<InvalidOperationException>(() => handler.HandleAsync(
            stream,
            CreateOptions(
                new VlessUser
                {
                    UserId = "user-a",
                    Uuid = uuid,
                    Flow = VlessFlowTypes.Vision,
                    BytesPerSecond = 0,
                    DeviceLimit = 0
                },
                outerTlsProtocol: SslProtocols.Tls12),
            CancellationToken.None));

        Assert.Contains("tls 1.3", exception.Message, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task HandleAsync_rejects_vision_over_wss()
    {
        var handler = CreateHandler();
        var uuid = "11111111-1111-1111-1111-111111111111";
        var stream = new RecordingDuplexStream(BuildHandshake(
            uuid,
            VlessCommand.Connect,
            addons: new VlessHeaderAddons
            {
                Flow = VlessFlowTypes.Vision
            }));

        var exception = await Assert.ThrowsAsync<NotSupportedException>(() => handler.HandleAsync(
            stream,
            CreateOptions(
                new VlessUser
                {
                    UserId = "user-a",
                    Uuid = uuid,
                    Flow = VlessFlowTypes.Vision,
                    BytesPerSecond = 0,
                    DeviceLimit = 0
                },
                transport: InboundTransports.Wss),
            CancellationToken.None));

        Assert.Contains("tls-like", exception.Message, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task HandleAsync_allows_vision_over_reality()
    {
        var relayService = new CapturingRelayService();
        var handler = CreateHandler(relayService);
        var uuid = "11111111-1111-1111-1111-111111111111";
        var stream = new RecordingDuplexStream(BuildVisionRequest(
            uuid,
            "example.org",
            443,
            Encoding.ASCII.GetBytes("ping")));

        await handler.HandleAsync(
            stream,
            CreateOptions(
                new VlessUser
                {
                    UserId = "user-a",
                    Uuid = uuid,
                    Flow = VlessFlowTypes.Vision,
                    BytesPerSecond = 0,
                    DeviceLimit = 0
                },
                transportProtocol: RuntimeInternetTransportProtocols.Tcp,
                securityType: RuntimeInternetSecurityTypes.Reality),
            CancellationToken.None);

        Assert.IsType<VlessVisionDuplexStream>(relayService.ObservedClientStream);
        Assert.Equal("ping", relayService.RequestPayloadText);

        var written = stream.GetWrittenBytes();
        Assert.True(written.Length >= 2);
        Assert.Equal(0, written[0]);
        Assert.Equal(0, written[1]);
    }

    [Fact]
    public async Task HandleAsync_decodes_vision_tcp_body_and_uses_user_testseed_for_downlink_padding()
    {
        var relayService = new CapturingRelayService();
        var handler = CreateHandler(relayService);
        var uuid = "11111111-1111-1111-1111-111111111111";
        var stream = new RecordingDuplexStream(BuildVisionRequest(
            uuid,
            "example.org",
            443,
            Encoding.ASCII.GetBytes("ping")));

        await handler.HandleAsync(
            stream,
            CreateOptions(new VlessUser
            {
                UserId = "user-a",
                Uuid = uuid,
                Flow = VlessFlowTypes.Vision,
                TestSeed = [1u, 0u, 1u, 0u],
                BytesPerSecond = 0,
                DeviceLimit = 0
            }),
            CancellationToken.None);

        Assert.IsType<VlessVisionDuplexStream>(relayService.ObservedClientStream);
        Assert.Equal("ping", relayService.RequestPayloadText);

        var written = stream.GetWrittenBytes();
        Assert.True(written.Length >= 2 + VlessVisionPaddingCodec.InitialFramePrefixLength + 4);
        Assert.Equal(0, written[0]);
        Assert.Equal(0, written[1]);

        var prefix = written.AsSpan(2, VlessVisionPaddingCodec.InitialFramePrefixLength);
        Assert.Equal(uuid, ProtocolUuid.Format(prefix[..VlessVisionPaddingCodec.UserUuidLength]));
        Assert.Equal((byte)VlessVisionCommand.Continue, prefix[VlessVisionPaddingCodec.UserUuidLength]);

        var contentLength = BinaryPrimitives.ReadUInt16BigEndian(
            prefix.Slice(VlessVisionPaddingCodec.UserUuidLength + 1, 2));
        var paddingLength = BinaryPrimitives.ReadUInt16BigEndian(
            prefix.Slice(VlessVisionPaddingCodec.UserUuidLength + 3, 2));
        Assert.Equal(4, contentLength);
        Assert.Equal(0, paddingLength);

        var payload = written.AsSpan(2 + VlessVisionPaddingCodec.InitialFramePrefixLength, contentLength);
        Assert.Equal("pong", Encoding.ASCII.GetString(payload));
    }

    [Fact]
    public async Task HandleAsync_accepts_transport_encrypted_vless_request_and_resumes_session()
    {
        if (!MLKem.IsSupported)
        {
            return;
        }

        using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(15));
        using var listener = new TcpListener(IPAddress.Loopback, 0);
        using var keyPair = RuntimeX25519.CreateKeyPair();
        listener.Start();

        var uuid = "11111111-1111-1111-1111-111111111111";
        var relayService = new CapturingRelayService();
        var handler = CreateHandler(relayService);
        var sessionOptions = CreateOptions(
            new VlessUser
            {
                UserId = "user-a",
                Uuid = uuid,
                BytesPerSecond = 0,
                DeviceLimit = 0
            },
            decryption: EncodeBase64Url(keyPair.PrivateKey),
            secondsFrom: 60);

        var serverTask = Task.Run(async () =>
        {
            for (var index = 0; index < 2; index++)
            {
                using var acceptedClient = await listener.AcceptTcpClientAsync(cts.Token);
                await using var acceptedStream = acceptedClient.GetStream();
                await handler.HandleAsync(acceptedStream, sessionOptions, cts.Token);
            }
        }, cts.Token);

        var client = new VlessOutboundClient();
        var clientOptions = new VlessClientOptions
        {
            ServerHost = IPAddress.Loopback.ToString(),
            ServerPort = ((IPEndPoint)listener.LocalEndpoint).Port,
            Transport = VlessClientTransportType.Tcp,
            UserUuid = uuid,
            Command = VlessCommand.Connect,
            TargetHost = "example.org",
            TargetPort = 443,
            Encryption = EncodeBase64Url(keyPair.PublicKey),
            Seconds = 60
        };

        for (var index = 0; index < 2; index++)
        {
            await using var connection = await client.ConnectAsync(clientOptions, cts.Token);
            await connection.Stream.WriteAsync(Encoding.ASCII.GetBytes("ping"), cts.Token);
            await connection.Stream.FlushAsync(cts.Token);

            var response = new byte[4];
            await connection.Stream.ReadExactlyAsync(response.AsMemory(0, response.Length), cts.Token);
            Assert.Equal("pong", Encoding.ASCII.GetString(response));
        }

        await serverTask;
        Assert.Equal("ping", relayService.RequestPayloadText);
    }

    [Fact]
    public async Task HandleAsync_accepts_reverse_proxy_session_and_opens_reverse_tcp_stream()
    {
        using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(15));
        using var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();

        var outboundManager = new DefaultOutboundManager(new StaticOutboundRuntimePlanProvider(OutboundRuntimePlan.Empty));
        var handler = CreateHandler(outboundManager: outboundManager);
        var uuid = "11111111-1111-1111-1111-111111111111";
        var sessionOptions = CreateOptions(
            new VlessUser
            {
                UserId = "user-a",
                Uuid = uuid,
                ReverseTag = "reverse-edge",
                BytesPerSecond = 0,
                DeviceLimit = 0
            });

        var serverTask = Task.Run(async () =>
        {
            using var acceptedClient = await listener.AcceptTcpClientAsync(cts.Token);
            await using var acceptedStream = acceptedClient.GetStream();
            await handler.HandleAsync(acceptedStream, sessionOptions, cts.Token);
        }, cts.Token);

        using var client = new TcpClient();
        await client.ConnectAsync(IPAddress.Loopback, ((IPEndPoint)listener.LocalEndpoint).Port, cts.Token);
        await using var clientStream = client.GetStream();

        var reverseHandshake = new VlessHandshakeWriter().Build(uuid, VlessCommand.Rvs, string.Empty, 0, version: 0);
        await clientStream.WriteAsync(reverseHandshake, cts.Token);
        await clientStream.FlushAsync(cts.Token);

        var responseHeader = new byte[2];
        await clientStream.ReadExactlyAsync(responseHeader.AsMemory(0, responseHeader.Length), cts.Token);
        Assert.Equal([0, 0], responseHeader);

        var reverseHandler = await WaitForReverseHandlerAsync(outboundManager, "reverse-edge", cts.Token);
        var reverseStreamTask = reverseHandler.OpenTcpAsync(
            new DispatchContext
            {
                InboundTag = "local",
                InboundProtocol = InboundProtocols.Trojan,
                Network = RoutingNetworks.Tcp,
                InboundSourceNetwork = RoutingNetworks.Tcp,
                SourceEndPoint = new IPEndPoint(IPAddress.Parse("203.0.113.25"), 50000),
                LocalEndPoint = new IPEndPoint(IPAddress.Parse("198.51.100.8"), 8443)
            },
            new DispatchDestination
            {
                Host = "example.org",
                Port = 443,
                Network = DispatchNetwork.Tcp
            },
            cts.Token).AsTask();

        var openFrame = await TrojanMuxFrameCodec.ReadAsync(
            clientStream,
            readSourceAndLocal: true,
            cts.Token);
        Assert.NotNull(openFrame);
        Assert.Equal(TrojanMuxSessionStatus.New, openFrame!.Status);
        Assert.NotNull(openFrame.Target);
        Assert.Equal("example.org", openFrame.Target!.Host);
        Assert.Equal(443, openFrame.Target.Port);
        Assert.Equal("203.0.113.25", openFrame.Source!.Host);
        Assert.Equal(50000, openFrame.Source.Port);
        Assert.Equal(DispatchNetwork.Tcp, openFrame.Source.Network);
        Assert.Equal("198.51.100.8", openFrame.Local!.Host);
        Assert.Equal(8443, openFrame.Local.Port);
        Assert.Equal(DispatchNetwork.Tcp, openFrame.Local.Network);

        await using var reverseStream = await reverseStreamTask;
        await reverseStream.WriteAsync(Encoding.ASCII.GetBytes("ping"), cts.Token);
        await reverseStream.FlushAsync(cts.Token);

        var payloadFrame = await TrojanMuxFrameCodec.ReadAsync(clientStream, cts.Token);
        Assert.NotNull(payloadFrame);
        Assert.Equal(TrojanMuxSessionStatus.Keep, payloadFrame!.Status);
        Assert.Equal(openFrame.SessionId, payloadFrame.SessionId);
        Assert.Equal("ping", Encoding.ASCII.GetString(payloadFrame.Payload));

        await TrojanMuxFrameCodec.WriteAsync(
            clientStream,
            new TrojanMuxFrame
            {
                SessionId = openFrame.SessionId,
                Status = TrojanMuxSessionStatus.Keep,
                Option = TrojanMuxFrameOption.Data,
                Payload = Encoding.ASCII.GetBytes("pong")
            },
            cts.Token);
        await clientStream.FlushAsync(cts.Token);

        var responsePayload = new byte[4];
        await reverseStream.ReadExactlyAsync(responsePayload.AsMemory(0, responsePayload.Length), cts.Token);
        Assert.Equal("pong", Encoding.ASCII.GetString(responsePayload));

        await reverseStream.DisposeAsync();
        var endFrame = await TrojanMuxFrameCodec.ReadAsync(clientStream, cts.Token);
        Assert.NotNull(endFrame);
        Assert.Equal(TrojanMuxSessionStatus.End, endFrame!.Status);
        Assert.Equal(openFrame.SessionId, endFrame.SessionId);

        client.Dispose();
        await serverTask;
    }

    [Fact]
    public async Task HandleAsync_accepts_reverse_proxy_session_and_opens_reverse_udp_transport_with_source_local_metadata()
    {
        using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(15));
        using var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();

        var outboundManager = new DefaultOutboundManager(new StaticOutboundRuntimePlanProvider(OutboundRuntimePlan.Empty));
        var handler = CreateHandler(outboundManager: outboundManager);
        var uuid = "11111111-1111-1111-1111-111111111111";
        var sessionOptions = CreateOptions(
            new VlessUser
            {
                UserId = "user-a",
                Uuid = uuid,
                ReverseTag = "reverse-edge",
                BytesPerSecond = 0,
                DeviceLimit = 0
            });

        var serverTask = Task.Run(async () =>
        {
            using var acceptedClient = await listener.AcceptTcpClientAsync(cts.Token);
            await using var acceptedStream = acceptedClient.GetStream();
            await handler.HandleAsync(acceptedStream, sessionOptions, cts.Token);
        }, cts.Token);

        using var client = new TcpClient();
        await client.ConnectAsync(IPAddress.Loopback, ((IPEndPoint)listener.LocalEndpoint).Port, cts.Token);
        await using var clientStream = client.GetStream();

        var reverseHandshake = new VlessHandshakeWriter().Build(uuid, VlessCommand.Rvs, string.Empty, 0, version: 0);
        await clientStream.WriteAsync(reverseHandshake, cts.Token);
        await clientStream.FlushAsync(cts.Token);

        var responseHeader = new byte[2];
        await clientStream.ReadExactlyAsync(responseHeader.AsMemory(0, responseHeader.Length), cts.Token);
        Assert.Equal([0, 0], responseHeader);

        var reverseHandler = await WaitForReverseHandlerAsync(outboundManager, "reverse-edge", cts.Token);
        var transport = await reverseHandler.OpenUdpAsync(
            new DispatchContext
            {
                InboundTag = "local",
                InboundProtocol = InboundProtocols.Trojan,
                Network = RoutingNetworks.Udp,
                InboundSourceNetwork = RoutingNetworks.Udp,
                SourceEndPoint = new IPEndPoint(IPAddress.Parse("203.0.113.25"), 50000),
                LocalEndPoint = new IPEndPoint(IPAddress.Parse("198.51.100.8"), 5353)
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

        var openFrame = await TrojanMuxFrameCodec.ReadAsync(
            clientStream,
            readSourceAndLocal: true,
            cts.Token);
        Assert.NotNull(openFrame);
        Assert.Equal(TrojanMuxSessionStatus.New, openFrame!.Status);
        Assert.Equal(TrojanMuxFrameOption.Data, openFrame.Option);
        Assert.NotNull(openFrame.Target);
        Assert.Equal("8.8.8.8", openFrame.Target!.Host);
        Assert.Equal(53, openFrame.Target.Port);
        Assert.Equal(DispatchNetwork.Udp, openFrame.Target.Network);
        Assert.Equal("203.0.113.25", openFrame.Source!.Host);
        Assert.Equal(50000, openFrame.Source.Port);
        Assert.Equal(DispatchNetwork.Udp, openFrame.Source.Network);
        Assert.Equal("198.51.100.8", openFrame.Local!.Host);
        Assert.Equal(5353, openFrame.Local.Port);
        Assert.Equal(DispatchNetwork.Udp, openFrame.Local.Network);
        Assert.Empty(openFrame.GlobalId);
        Assert.Equal("ping", Encoding.ASCII.GetString(openFrame.Payload));

        await TrojanMuxFrameCodec.WriteAsync(
            clientStream,
            new TrojanMuxFrame
            {
                SessionId = openFrame.SessionId,
                Status = TrojanMuxSessionStatus.Keep,
                Option = TrojanMuxFrameOption.Data,
                Target = new TrojanMuxFrameTarget("8.8.8.8", 53, DispatchNetwork.Udp),
                Payload = Encoding.ASCII.GetBytes("pong")
            },
            cts.Token);
        await clientStream.FlushAsync(cts.Token);

        var datagram = await transport.ReceiveAsync(cts.Token);
        Assert.NotNull(datagram);
        Assert.Equal("8.8.8.8", datagram!.SourceHost);
        Assert.Equal(53, datagram.SourcePort);
        Assert.Equal("pong", Encoding.ASCII.GetString(datagram.Payload));

        await transport.DisposeAsync();
        var endFrame = await TrojanMuxFrameCodec.ReadAsync(clientStream, cts.Token);
        Assert.NotNull(endFrame);
        Assert.Equal(TrojanMuxSessionStatus.End, endFrame!.Status);
        Assert.Equal(openFrame.SessionId, endFrame.SessionId);

        client.Dispose();
        await serverTask;
    }

    [Fact]
    public async Task HandleAsync_relays_http_probe_to_fallback_when_initial_payload_is_not_vless()
    {
        using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(10));
        var fallbackPort = ReserveTcpPort();
        using var listener = new TcpListener(IPAddress.Loopback, fallbackPort);
        listener.Start();

        var fallbackRequestTask = Task.Run(async () =>
        {
            using var client = await listener.AcceptTcpClientAsync(cts.Token);
            await using var fallbackStream = client.GetStream();
            var requestText = await ReadHttpRequestAsync(fallbackStream, cts.Token);
            await fallbackStream.WriteAsync(
                Encoding.ASCII.GetBytes("HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok"),
                cts.Token);
            await fallbackStream.FlushAsync(cts.Token);
            return requestText;
        }, cts.Token);

        var httpRequest = Encoding.ASCII.GetBytes("GET /health HTTP/1.1\r\nHost: edge.example.com\r\n\r\n");
        var stream = new RecordingDuplexStream(httpRequest);

        await CreateHandler().HandleAsync(
            stream,
            CreateOptions(
                new VlessUser
                {
                    UserId = "user-a",
                    Uuid = "11111111-1111-1111-1111-111111111111",
                    BytesPerSecond = 0,
                    DeviceLimit = 0
                },
                fallbacks:
                [
                    new TestTrojanFallback
                    {
                        Path = "health",
                        Dest = $"127.0.0.1:{fallbackPort}"
                    }
                ]),
            cts.Token);

        Assert.Equal("GET /health HTTP/1.1\r\nHost: edge.example.com\r\n\r\n", await fallbackRequestTask);
        Assert.Equal("HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok", Encoding.ASCII.GetString(stream.GetWrittenBytes()));
    }

    [Fact]
    public async Task HandleAsync_relays_malformed_vless_payload_to_default_fallback_after_uuid_match()
    {
        using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(10));
        var fallbackPort = ReserveTcpPort();
        using var listener = new TcpListener(IPAddress.Loopback, fallbackPort);
        listener.Start();

        var uuid = "11111111-1111-1111-1111-111111111111";
        var malformedPayload = BuildMalformedRequestWithKnownUuid(uuid, Encoding.ASCII.GetBytes("probe-body"));

        var fallbackRequestTask = Task.Run(async () =>
        {
            using var client = await listener.AcceptTcpClientAsync(cts.Token);
            await using var fallbackStream = client.GetStream();
            var requestBytes = new byte[malformedPayload.Length];
            await fallbackStream.ReadExactlyAsync(requestBytes.AsMemory(0, requestBytes.Length), cts.Token);
            await fallbackStream.WriteAsync(Encoding.ASCII.GetBytes("fallback-parse-ok"), cts.Token);
            await fallbackStream.FlushAsync(cts.Token);
            return requestBytes;
        }, cts.Token);

        var stream = new RecordingDuplexStream(malformedPayload);

        await CreateHandler().HandleAsync(
            stream,
            CreateOptions(
                new VlessUser
                {
                    UserId = "user-a",
                    Uuid = uuid,
                    BytesPerSecond = 0,
                    DeviceLimit = 0
                },
                fallbacks:
                [
                    new TestTrojanFallback
                    {
                        Dest = $"127.0.0.1:{fallbackPort}"
                    }
                ]),
            cts.Token);

        Assert.Equal(malformedPayload, await fallbackRequestTask);
        Assert.Equal("fallback-parse-ok", Encoding.ASCII.GetString(stream.GetWrittenBytes()));
    }

    private static VlessInboundConnectionHandler CreateHandler(
        IRuntimeRelayService? relayService = null,
        IDispatcher? dispatcher = null,
        DefaultOutboundManager? outboundManager = null)
    {
        dispatcher ??= new BlockingDispatcher(new MemoryStream());
        outboundManager ??= new DefaultOutboundManager(new StaticOutboundRuntimePlanProvider(OutboundRuntimePlan.Empty));
        var rateLimiterRegistry = new RateLimiterRegistry();
        var trafficRegistry = new TrafficRegistry();
        return new VlessInboundConnectionHandler(
            dispatcher,
            new VlessHandshakeReader(),
            new TrojanMuxInboundServer(
                dispatcher,
                rateLimiterRegistry,
                trafficRegistry),
            new VlessUdpRelay(
                dispatcher,
                rateLimiterRegistry,
                trafficRegistry,
                new VlessUdpPacketReader(),
                new VlessUdpPacketWriter()),
            new SessionRegistry(),
            relayService ?? new RelayService(),
            rateLimiterRegistry,
            trafficRegistry,
            outboundManager);
    }

    private static async Task<VlessReverseOutboundHandler> WaitForReverseHandlerAsync(
        DefaultOutboundManager outboundManager,
        string tag,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(outboundManager);
        ArgumentException.ThrowIfNullOrWhiteSpace(tag);

        while (!cancellationToken.IsCancellationRequested)
        {
            if (outboundManager.GetHandler(tag) is VlessReverseOutboundHandler reverseHandler)
            {
                return reverseHandler;
            }

            await Task.Delay(TimeSpan.FromMilliseconds(10), cancellationToken);
        }

        throw new OperationCanceledException("Timed out while waiting for the reverse outbound handler.", cancellationToken);
    }

    private static VlessInboundSessionOptions CreateOptions(
        VlessUser user,
        string? transport = null,
        string? transportProtocol = null,
        string? securityType = null,
        SslProtocols outerTlsProtocol = SslProtocols.Tls13,
        IReadOnlyList<IRuntimeFallbackDefinition>? fallbacks = null,
        string decryption = "",
        uint xorMode = 0,
        int secondsFrom = 0,
        int secondsTo = 0,
        string padding = "")
    {
        var stack = InboundInternetStackResolver.Resolve(transport, transportProtocol, securityType);
        return new VlessInboundSessionOptions
        {
            RuntimeState = new VlessInboundRuntimeState([user]),
            InboundTag = "vless-in",
            Transport = stack.Transport,
            TransportProtocol = stack.TransportProtocol,
            SecurityType = stack.SecurityType,
            OuterTlsProtocol = outerTlsProtocol,
            RemoteEndPoint = new IPEndPoint(IPAddress.Parse("203.0.113.10"), 50001),
            Decryption = decryption,
            XorMode = xorMode,
            SecondsFrom = secondsFrom,
            SecondsTo = secondsTo,
            Padding = padding,
            Fallbacks = fallbacks ?? Array.Empty<IRuntimeFallbackDefinition>()
        };
    }

    private static byte[] BuildHandshake(
        string uuid,
        VlessCommand command,
        VlessHeaderAddons? addons = null)
        => new VlessHandshakeWriter().Build(uuid, command, "example.org", 443, version: 0, addons: addons);

    private static byte[] BuildMuxRequest(string uuid, byte[] firstFrame, VlessHeaderAddons? addons = null)
    {
        using var buffer = new MemoryStream();
        var handshake = new VlessHandshakeWriter().Build(uuid, VlessCommand.Mux, string.Empty, 0, version: 0, addons: addons);
        buffer.Write(handshake, 0, handshake.Length);
        buffer.Write(firstFrame, 0, firstFrame.Length);
        return buffer.ToArray();
    }

    private static byte[] BuildMuxFrame(
        ushort sessionId,
        string host,
        int port,
        DispatchNetwork network,
        byte[] payload,
        byte[]? globalId = null)
    {
        using var stream = new MemoryStream();
        TrojanMuxFrameCodec.WriteAsync(
            stream,
            new TrojanMuxFrame
            {
                SessionId = sessionId,
                Status = TrojanMuxSessionStatus.New,
                Option = TrojanMuxFrameOption.Data,
                Target = new TrojanMuxFrameTarget(host, port, network),
                GlobalId = globalId ?? Array.Empty<byte>(),
                Payload = payload
            },
            CancellationToken.None).AsTask().GetAwaiter().GetResult();
        return stream.ToArray();
    }

    private static byte[] BuildVisionRequest(
        string uuid,
        string host,
        int port,
        byte[] payload)
    {
        using var transport = new MemoryStream();
        var handshake = new VlessHandshakeWriter().Build(
            uuid,
            VlessCommand.Connect,
            host,
            port,
            version: 0,
            addons: new VlessHeaderAddons
            {
                Flow = VlessFlowTypes.Vision
            });
        transport.Write(handshake, 0, handshake.Length);

        Span<byte> userBytes = stackalloc byte[VlessVisionPaddingCodec.UserUuidLength];
        Assert.True(ProtocolUuid.TryWriteBytes(uuid, userBytes));

        using var visionStream = new VlessVisionDuplexStream(
            transport,
            new VlessVisionTrafficState(userBytes),
            readIsUplink: false,
            writeIsUplink: true);
        visionStream.WriteAsync(payload, CancellationToken.None).AsTask().GetAwaiter().GetResult();
        visionStream.Flush();

        return transport.ToArray();
    }

    private static byte[] BuildMalformedRequestWithKnownUuid(string uuid, byte[] trailingPayload)
    {
        using var buffer = new MemoryStream();
        buffer.WriteByte(0);

        Span<byte> uuidBytes = stackalloc byte[16];
        Assert.True(ProtocolUuid.TryWriteBytes(uuid, uuidBytes));
        buffer.Write(uuidBytes);

        buffer.WriteByte(0);
        buffer.WriteByte((byte)VlessCommand.Connect);
        buffer.WriteByte(0x01);
        buffer.WriteByte(0xBB);
        buffer.WriteByte(0x05);
        buffer.Write(trailingPayload, 0, trailingPayload.Length);
        return buffer.ToArray();
    }

    private static int ReserveTcpPort()
    {
        using var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();
        return ((IPEndPoint)listener.LocalEndpoint).Port;
    }

    private static string EncodeBase64Url(ReadOnlySpan<byte> value)
        => Convert.ToBase64String(value)
            .TrimEnd('=')
            .Replace('+', '-')
            .Replace('/', '_');

    private static async Task<string> ReadHttpRequestAsync(Stream stream, CancellationToken cancellationToken)
    {
        using var buffer = new MemoryStream();
        var chunk = new byte[256];
        var terminator = Encoding.ASCII.GetBytes("\r\n\r\n");

        while (true)
        {
            var read = await stream.ReadAsync(chunk.AsMemory(0, chunk.Length), cancellationToken);
            if (read == 0)
            {
                throw new EndOfStreamException("Unexpected EOF while reading fallback HTTP request.");
            }

            await buffer.WriteAsync(chunk.AsMemory(0, read), cancellationToken);
            var bufferedBytes = buffer.ToArray();
            if (bufferedBytes.Length >= terminator.Length &&
                bufferedBytes.AsSpan().IndexOf(terminator) >= 0)
            {
                return Encoding.ASCII.GetString(bufferedBytes);
            }
        }
    }

    private sealed class CapturingRelayService : IRuntimeRelayService
    {
        public Stream? ObservedClientStream { get; private set; }

        public string RequestPayloadText { get; private set; } = string.Empty;

        public Task RelayAsync(
            Stream clientStream,
            Stream remoteStream,
            CancellationToken cancellationToken)
            => throw new NotSupportedException();

        public Task RelayAsync(
            Stream clientStream,
            Stream remoteStream,
            IRuntimeInboundConnectionOptions options,
            CancellationToken cancellationToken)
            => throw new NotSupportedException();

        public Task RelayAsync(
            Stream clientStream,
            Stream remoteStream,
            IRuntimeUserDefinition user,
            ByteRateGate userGate,
            ByteRateGate globalGate,
            IRuntimeTrafficRegistry trafficRegistry,
            CancellationToken cancellationToken)
            => throw new NotSupportedException();

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
            ObservedClientStream = clientStream;

            var payload = new byte[4];
            await clientStream.ReadExactlyAsync(payload.AsMemory(0, payload.Length), cancellationToken);
            RequestPayloadText = Encoding.ASCII.GetString(payload);

            await clientStream.WriteAsync(Encoding.ASCII.GetBytes("pong"), cancellationToken);
            await clientStream.FlushAsync(cancellationToken);
        }
    }

    private sealed record UdpSendCapture(string Host, int Port, string Payload);

    private sealed class RecordingUdpDispatcher : IDispatcher
    {
        public RecordingUdpTransport Transport { get; } = new();

        public ValueTask<Stream> DispatchTcpAsync(
            DispatchContext context,
            DispatchDestination destination,
            CancellationToken cancellationToken)
            => throw new NotSupportedException();

        public ValueTask<IOutboundUdpTransport> DispatchUdpAsync(
            DispatchContext context,
            CancellationToken cancellationToken)
            => ValueTask.FromResult<IOutboundUdpTransport>(Transport);
    }

    private sealed class RecordingUdpTransport : IOutboundUdpTransport
    {
        public TaskCompletionSource<UdpSendCapture> CaptureTcs { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);

        public ValueTask SendAsync(
            DispatchDestination destination,
            ReadOnlyMemory<byte> payload,
            CancellationToken cancellationToken)
        {
            CaptureTcs.TrySetResult(new UdpSendCapture(
                destination.Host,
                destination.Port,
                Encoding.ASCII.GetString(payload.Span)));
            return ValueTask.CompletedTask;
        }

        public ValueTask<DispatchDatagram?> ReceiveAsync(CancellationToken cancellationToken)
            => ValueTask.FromResult<DispatchDatagram?>(null);

        public ValueTask DisposeAsync() => ValueTask.CompletedTask;
    }

    private sealed class RecordingDuplexStream : Stream
    {
        private readonly MemoryStream _readStream;
        private readonly MemoryStream _writeStream = new();

        public RecordingDuplexStream(byte[] readBuffer)
        {
            _readStream = new MemoryStream(readBuffer, writable: false);
        }

        public override bool CanRead => true;

        public override bool CanSeek => false;

        public override bool CanWrite => true;

        public override bool CanTimeout => _readStream.CanTimeout;

        public override long Length => throw new NotSupportedException();

        public override long Position
        {
            get => throw new NotSupportedException();
            set => throw new NotSupportedException();
        }

        public byte[] GetWrittenBytes() => _writeStream.ToArray();

        public override void Flush()
            => _writeStream.Flush();

        public override Task FlushAsync(CancellationToken cancellationToken)
            => _writeStream.FlushAsync(cancellationToken);

        public override int Read(byte[] buffer, int offset, int count)
            => _readStream.Read(buffer, offset, count);

        public override Task<int> ReadAsync(byte[] buffer, int offset, int count, CancellationToken cancellationToken)
            => _readStream.ReadAsync(buffer, offset, count, cancellationToken);

        public override ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken cancellationToken = default)
            => _readStream.ReadAsync(buffer, cancellationToken);

        public override long Seek(long offset, SeekOrigin origin)
            => throw new NotSupportedException();

        public override void SetLength(long value)
            => throw new NotSupportedException();

        public override void Write(byte[] buffer, int offset, int count)
            => _writeStream.Write(buffer, offset, count);

        public override Task WriteAsync(byte[] buffer, int offset, int count, CancellationToken cancellationToken)
            => _writeStream.WriteAsync(buffer, offset, count, cancellationToken);

        public override ValueTask WriteAsync(ReadOnlyMemory<byte> buffer, CancellationToken cancellationToken = default)
            => _writeStream.WriteAsync(buffer, cancellationToken);

        protected override void Dispose(bool disposing)
        {
            if (disposing)
            {
                _readStream.Dispose();
                _writeStream.Dispose();
            }

            base.Dispose(disposing);
        }

        public override async ValueTask DisposeAsync()
        {
            await _readStream.DisposeAsync();
            await _writeStream.DisposeAsync();
            await base.DisposeAsync();
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
}

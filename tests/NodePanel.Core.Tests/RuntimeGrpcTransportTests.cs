using System.Buffers.Binary;
using System.Net;
using System.Net.Security;
using System.Net.Sockets;
using System.Reflection;
using System.Security.Authentication;
using System.Text;
using NodePanel.Core.Runtime;

namespace NodePanel.Core.Tests;

public sealed class RuntimeGrpcTransportTests
{
    [Fact]
    public async Task OpenAsync_opens_grpc_stream_with_expected_headers_and_hunk_payload()
    {
        using var lifetimeCts = new CancellationTokenSource(TimeSpan.FromSeconds(10));
        using var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();

        var port = ((IPEndPoint)listener.LocalEndpoint).Port;
        var serverTask = CaptureGrpcExchangeAsync(listener, lifetimeCts.Token);
        var tlsSecurityFactory = new TestRuntimeInternetProfileFactory.RecordingFakeTlsSecurityFactory("h2");
        var profile = TestRuntimeInternetProfileFactory.CreateWithFakeTls(tlsSecurityFactory);
        using var client = new TcpClient();
        await client.ConnectAsync(IPAddress.Loopback, port, lifetimeCts.Token);

        var context = await profile.OpenAsync(
            client.GetStream(),
            RuntimeInternetStack.Create(RuntimeInternetTransportProtocols.Grpc, RuntimeInternetSecurityTypes.Tls),
            new TestGrpcInternetOptions
            {
                ServerHost = "127.0.0.1",
                ServerName = "edge.example.com",
                ApplicationProtocols = ["http/1.1"],
                GrpcServiceName = "/my/service/Tun|TunMulti",
                GrpcUserAgent = "TestGrpc/1.0"
            },
            transportInitializationData: null,
            lifetimeCts.Token);

        await using var applicationStream = context.ApplicationStream;
        var requestPayload = Encoding.ASCII.GetBytes("client-hunk");
        await applicationStream.WriteAsync(requestPayload, lifetimeCts.Token);
        await applicationStream.FlushAsync(lifetimeCts.Token);

        var responsePayload = new byte["server-hunk".Length];
        await ReadExactAsync(applicationStream, responsePayload, lifetimeCts.Token);

        var captured = await serverTask;
        Assert.Equal("POST", captured.Headers[":method"]);
        Assert.Equal("https", captured.Headers[":scheme"]);
        Assert.Equal("/my/service/Tun", captured.Headers[":path"]);
        Assert.Equal("edge.example.com", captured.Headers[":authority"]);
        Assert.Equal("application/grpc", captured.Headers["content-type"]);
        Assert.Equal("trailers", captured.Headers["te"]);
        Assert.Equal("TestGrpc/1.0", captured.Headers["user-agent"]);
        Assert.Equal("client-hunk", captured.RequestPayloadText);
        Assert.Equal("server-hunk", Encoding.ASCII.GetString(responsePayload));
        Assert.Equal(["h2"], tlsSecurityFactory.ObservedApplicationProtocols);
        Assert.Equal("h2", tlsSecurityFactory.NegotiatedApplicationProtocol);
    }

    [Fact]
    public async Task OpenAsync_does_not_use_websocket_host_header_as_grpc_authority()
    {
        using var lifetimeCts = new CancellationTokenSource(TimeSpan.FromSeconds(10));
        using var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();

        var port = ((IPEndPoint)listener.LocalEndpoint).Port;
        var serverTask = CaptureGrpcExchangeAsync(listener, lifetimeCts.Token);
        var profile = TestRuntimeInternetProfileFactory.CreateWithFakeTls("h2");
        using var client = new TcpClient();
        await client.ConnectAsync(IPAddress.Loopback, port, lifetimeCts.Token);

        var context = await profile.OpenAsync(
            client.GetStream(),
            RuntimeInternetStack.Create(RuntimeInternetTransportProtocols.Grpc, RuntimeInternetSecurityTypes.Tls),
            new TestGrpcInternetOptions
            {
                ServerHost = "127.0.0.1",
                ServerName = "edge.example.com",
                ApplicationProtocols = ["http/1.1"],
                WebSocketHeaders = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
                {
                    ["Host"] = "ws.example.com"
                },
                GrpcServiceName = "/my/service/Tun"
            },
            transportInitializationData: null,
            lifetimeCts.Token);

        await using var applicationStream = context.ApplicationStream;
        await applicationStream.WriteAsync("client-hunk"u8.ToArray(), lifetimeCts.Token);
        await applicationStream.FlushAsync(lifetimeCts.Token);

        var responsePayload = new byte["server-hunk".Length];
        await ReadExactAsync(applicationStream, responsePayload, lifetimeCts.Token);

        var captured = await serverTask;
        Assert.Equal("edge.example.com", captured.Headers[":authority"]);
    }

    [Fact]
    public async Task OpenAsync_includes_custom_initial_window_size_in_client_settings()
    {
        using var lifetimeCts = new CancellationTokenSource(TimeSpan.FromSeconds(10));
        using var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();

        const int expectedInitialWindowSize = 262_144;
        var port = ((IPEndPoint)listener.LocalEndpoint).Port;
        var serverTask = CaptureInitialWindowSizeAsync(listener, lifetimeCts.Token);
        var profile = TestRuntimeInternetProfileFactory.CreateWithFakeTls("h2");
        using var client = new TcpClient();
        await client.ConnectAsync(IPAddress.Loopback, port, lifetimeCts.Token);

        var context = await profile.OpenAsync(
            client.GetStream(),
            RuntimeInternetStack.Create(RuntimeInternetTransportProtocols.Grpc, RuntimeInternetSecurityTypes.Tls),
            new TestGrpcInternetOptions
            {
                ServerHost = "127.0.0.1",
                ServerName = "edge.example.com",
                GrpcServiceName = "/window/test/Tun",
                GrpcInitialWindowSize = expectedInitialWindowSize
            },
            transportInitializationData: null,
            lifetimeCts.Token);

        await using var applicationStream = context.ApplicationStream;
        var observedInitialWindowSize = await serverTask;
        Assert.Equal(expectedInitialWindowSize, observedInitialWindowSize);
    }

    [Fact]
    public async Task OpenAsync_sends_keepalive_ping_and_continues_after_ack()
    {
        using var lifetimeCts = new CancellationTokenSource(TimeSpan.FromSeconds(10));
        using var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();

        var port = ((IPEndPoint)listener.LocalEndpoint).Port;
        var serverTask = AcknowledgeKeepAlivePingAndRespondAsync(listener, lifetimeCts.Token);
        var profile = TestRuntimeInternetProfileFactory.CreateWithFakeTls("h2");
        using var client = new TcpClient();
        await client.ConnectAsync(IPAddress.Loopback, port, lifetimeCts.Token);

        var context = await profile.OpenAsync(
            client.GetStream(),
            RuntimeInternetStack.Create(RuntimeInternetTransportProtocols.Grpc, RuntimeInternetSecurityTypes.Tls),
            new TestGrpcInternetOptions
            {
                ServerHost = "127.0.0.1",
                ServerName = "edge.example.com",
                GrpcServiceName = "/keepalive/test/Tun",
                GrpcIdleTimeoutSeconds = 1,
                GrpcHealthCheckTimeoutSeconds = 2
            },
            transportInitializationData: null,
            lifetimeCts.Token);

        await using var applicationStream = context.ApplicationStream;
        var firstResponsePayload = new byte["server-after-ping".Length];
        await ReadExactAsync(applicationStream, firstResponsePayload, lifetimeCts.Token);

        var secondResponsePayload = new byte["server-still-alive".Length];
        await ReadExactAsync(applicationStream, secondResponsePayload, lifetimeCts.Token);

        Assert.Equal("server-after-ping", Encoding.ASCII.GetString(firstResponsePayload));
        Assert.Equal("server-still-alive", Encoding.ASCII.GetString(secondResponsePayload));
        await serverTask;
    }

    [Fact]
    public async Task OpenAsync_fails_when_keepalive_ping_is_not_acknowledged()
    {
        using var lifetimeCts = new CancellationTokenSource(TimeSpan.FromSeconds(10));
        using var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();

        var port = ((IPEndPoint)listener.LocalEndpoint).Port;
        var serverTask = HoldKeepAlivePingWithoutAckAsync(listener, lifetimeCts.Token);
        var profile = TestRuntimeInternetProfileFactory.CreateWithFakeTls("h2");
        using var client = new TcpClient();
        await client.ConnectAsync(IPAddress.Loopback, port, lifetimeCts.Token);

        var context = await profile.OpenAsync(
            client.GetStream(),
            RuntimeInternetStack.Create(RuntimeInternetTransportProtocols.Grpc, RuntimeInternetSecurityTypes.Tls),
            new TestGrpcInternetOptions
            {
                ServerHost = "127.0.0.1",
                ServerName = "edge.example.com",
                GrpcServiceName = "/keepalive/test/Tun",
                GrpcIdleTimeoutSeconds = 1,
                GrpcHealthCheckTimeoutSeconds = 1
            },
            transportInitializationData: null,
            lifetimeCts.Token);

        await using var applicationStream = context.ApplicationStream;
        var buffer = new byte[1];
        var exception = await Assert.ThrowsAsync<IOException>(async () =>
            _ = await applicationStream.ReadAsync(buffer, lifetimeCts.Token));

        Assert.Contains("PING acknowledgement timed out", exception.Message, StringComparison.Ordinal);
        await serverTask;
    }

    [Fact]
    public async Task OpenAsync_uses_server_host_as_grpc_authority_for_reality_when_no_explicit_authority()
    {
        using var lifetimeCts = new CancellationTokenSource(TimeSpan.FromSeconds(10));
        using var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();

        var port = ((IPEndPoint)listener.LocalEndpoint).Port;
        var serverTask = CaptureGrpcExchangeAsync(listener, lifetimeCts.Token);
        var realitySecurityFactory = new TestRuntimeInternetProfileFactory.RecordingPassThroughSecurityFactory(
            RuntimeInternetSecurityTypes.Reality,
            negotiatedApplicationProtocol: "h2");
        var profile = TestRuntimeInternetProfileFactory.CreateWithRecordingSecurity(realitySecurityFactory);
        using var client = new TcpClient();
        await client.ConnectAsync(IPAddress.Loopback, port, lifetimeCts.Token);

        var context = await profile.OpenAsync(
            client.GetStream(),
            RuntimeInternetStack.Create(RuntimeInternetTransportProtocols.Grpc, RuntimeInternetSecurityTypes.Reality),
            new TestGrpcInternetOptions
            {
                ServerHost = "127.0.0.1",
                ServerName = "edge.example.com",
                SecurityType = RuntimeInternetSecurityTypes.Reality,
                RealityOptions = new RuntimeRealityOptions
                {
                    PublicKey = EncodeBase64Url(32, 0x11)
                },
                GrpcServiceName = "/reality/service/Tun"
            },
            transportInitializationData: null,
            lifetimeCts.Token);

        await using var applicationStream = context.ApplicationStream;
        await applicationStream.WriteAsync("client-hunk"u8.ToArray(), lifetimeCts.Token);
        await applicationStream.FlushAsync(lifetimeCts.Token);

        var responsePayload = new byte["server-hunk".Length];
        await ReadExactAsync(applicationStream, responsePayload, lifetimeCts.Token);

        var captured = await serverTask;
        Assert.Equal("https", captured.Headers[":scheme"]);
        Assert.Equal("127.0.0.1", captured.Headers[":authority"]);
        Assert.Equal(["h2"], realitySecurityFactory.ObservedApplicationProtocols);
    }

    [Fact]
    public async Task OpenAsync_prefers_explicit_grpc_authority_for_reality_transport()
    {
        using var lifetimeCts = new CancellationTokenSource(TimeSpan.FromSeconds(10));
        using var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();

        var port = ((IPEndPoint)listener.LocalEndpoint).Port;
        var serverTask = CaptureGrpcExchangeAsync(listener, lifetimeCts.Token);
        var realitySecurityFactory = new TestRuntimeInternetProfileFactory.RecordingPassThroughSecurityFactory(
            RuntimeInternetSecurityTypes.Reality,
            negotiatedApplicationProtocol: "h2");
        var profile = TestRuntimeInternetProfileFactory.CreateWithRecordingSecurity(realitySecurityFactory);
        using var client = new TcpClient();
        await client.ConnectAsync(IPAddress.Loopback, port, lifetimeCts.Token);

        var context = await profile.OpenAsync(
            client.GetStream(),
            RuntimeInternetStack.Create(RuntimeInternetTransportProtocols.Grpc, RuntimeInternetSecurityTypes.Reality),
            new TestGrpcInternetOptions
            {
                ServerHost = "127.0.0.1",
                ServerName = "edge.example.com",
                SecurityType = RuntimeInternetSecurityTypes.Reality,
                RealityOptions = new RuntimeRealityOptions
                {
                    PublicKey = EncodeBase64Url(32, 0x11)
                },
                GrpcAuthority = "grpc.example.com",
                GrpcServiceName = "/reality/service/Tun"
            },
            transportInitializationData: null,
            lifetimeCts.Token);

        await using var applicationStream = context.ApplicationStream;
        await applicationStream.WriteAsync("client-hunk"u8.ToArray(), lifetimeCts.Token);
        await applicationStream.FlushAsync(lifetimeCts.Token);

        var responsePayload = new byte["server-hunk".Length];
        await ReadExactAsync(applicationStream, responsePayload, lifetimeCts.Token);

        var captured = await serverTask;
        Assert.Equal("grpc.example.com", captured.Headers[":authority"]);
        Assert.Equal(["h2"], realitySecurityFactory.ObservedApplicationProtocols);
    }

    [Fact]
    public async Task OpenAsync_returns_eof_when_server_completes_with_grpc_status_zero_trailer()
    {
        using var lifetimeCts = new CancellationTokenSource(TimeSpan.FromSeconds(10));
        using var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();

        var port = ((IPEndPoint)listener.LocalEndpoint).Port;
        var serverTask = CompleteGrpcRequestWithStatusTrailerAsync(listener, grpcStatus: 0, lifetimeCts.Token);
        var profile = RuntimeInternetProfile.FromDefault();
        using var client = new TcpClient();
        await client.ConnectAsync(IPAddress.Loopback, port, lifetimeCts.Token);

        var context = await profile.OpenAsync(
            client.GetStream(),
            RuntimeInternetStack.Create(RuntimeInternetTransportProtocols.Grpc, RuntimeInternetSecurityTypes.None),
            new TestGrpcInternetOptions
            {
                ServerHost = "127.0.0.1",
                SecurityType = RuntimeInternetSecurityTypes.None,
                GrpcServiceName = "/trailers/test/Tun"
            },
            transportInitializationData: null,
            lifetimeCts.Token);

        await using var applicationStream = context.ApplicationStream;
        var buffer = new byte[1];
        var read = await applicationStream.ReadAsync(buffer, lifetimeCts.Token);

        Assert.Equal(0, read);
        await serverTask;
    }

    [Fact]
    public async Task OpenAsync_reads_response_when_server_uses_huffman_encoded_status_header()
    {
        using var lifetimeCts = new CancellationTokenSource(TimeSpan.FromSeconds(10));
        using var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();

        var port = ((IPEndPoint)listener.LocalEndpoint).Port;
        var serverTask = CaptureGrpcExchangeAsync(
            listener,
            lifetimeCts.Token,
            useHuffmanStatusHeader: true);
        var profile = RuntimeInternetProfile.FromDefault();
        using var client = new TcpClient();
        await client.ConnectAsync(IPAddress.Loopback, port, lifetimeCts.Token);

        var context = await profile.OpenAsync(
            client.GetStream(),
            RuntimeInternetStack.Create(RuntimeInternetTransportProtocols.Grpc, RuntimeInternetSecurityTypes.None),
            new TestGrpcInternetOptions
            {
                ServerHost = "127.0.0.1",
                ServerPort = port,
                SecurityType = RuntimeInternetSecurityTypes.None,
                GrpcServiceName = "/trailers/test/Tun"
            },
            transportInitializationData: null,
            lifetimeCts.Token);

        await using var applicationStream = context.ApplicationStream;
        await applicationStream.WriteAsync("client-hunk"u8.ToArray(), lifetimeCts.Token);
        await applicationStream.FlushAsync(lifetimeCts.Token);
        var responsePayload = new byte["server-hunk".Length];
        await ReadExactAsync(applicationStream, responsePayload, lifetimeCts.Token);

        Assert.Equal("server-hunk", Encoding.ASCII.GetString(responsePayload));
        await serverTask;
    }

    [Fact]
    public async Task Http2GrpcTunnel_dispose_half_closes_request_stream_without_sending_rst_stream()
    {
        using var lifetimeCts = new CancellationTokenSource(TimeSpan.FromSeconds(10));
        using var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();

        var port = ((IPEndPoint)listener.LocalEndpoint).Port;
        var serverTask = CaptureGrpcClientTerminalFrameAsync(listener, lifetimeCts.Token);
        using var client = new TcpClient();
        await client.ConnectAsync(IPAddress.Loopback, port, lifetimeCts.Token);
        await using var transport = client.GetStream();
        var options = new TestGrpcInternetOptions
        {
            ServerHost = "127.0.0.1",
            ServerPort = port,
            SecurityType = RuntimeInternetSecurityTypes.None,
            GrpcServiceName = "/close/test/Tun"
        };
        var sessionOptions = Http2GrpcTunnel.CreateSessionOptions(options);
        await using var session = await Http2TunnelSession.CreateAsync(
            transport,
            lifetimeCts.Token,
            sessionOptions);

        var stack = RuntimeInternetStack.Create(
            RuntimeInternetTransportProtocols.Grpc,
            RuntimeInternetSecurityTypes.None);
        var grpcStream = await Http2GrpcTunnel.OpenAsync(
            session,
            stack,
            options,
            lifetimeCts.Token,
            disposeSessionOnClose: false);

        await grpcStream.WriteAsync("client-hunk"u8.ToArray(), lifetimeCts.Token);
        await grpcStream.FlushAsync(lifetimeCts.Token);
        await grpcStream.DisposeAsync();

        var terminal = await serverTask;
        Assert.Equal(Http2TestFrameTypes.Data, terminal.Type);
        Assert.Equal(1, terminal.StreamId);
        Assert.True((terminal.Flags & Http2TestFrameFlags.EndStream) == Http2TestFrameFlags.EndStream);
    }

    [Fact]
    public async Task OpenAsync_throws_when_server_completes_with_non_zero_grpc_status_trailer()
    {
        using var lifetimeCts = new CancellationTokenSource(TimeSpan.FromSeconds(10));
        using var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();

        var port = ((IPEndPoint)listener.LocalEndpoint).Port;
        var serverTask = CompleteGrpcRequestWithStatusTrailerAsync(listener, grpcStatus: 13, lifetimeCts.Token);
        var profile = RuntimeInternetProfile.FromDefault();
        using var client = new TcpClient();
        await client.ConnectAsync(IPAddress.Loopback, port, lifetimeCts.Token);

        var context = await profile.OpenAsync(
            client.GetStream(),
            RuntimeInternetStack.Create(RuntimeInternetTransportProtocols.Grpc, RuntimeInternetSecurityTypes.None),
            new TestGrpcInternetOptions
            {
                ServerHost = "127.0.0.1",
                SecurityType = RuntimeInternetSecurityTypes.None,
                GrpcServiceName = "/trailers/test/Tun"
            },
            transportInitializationData: null,
            lifetimeCts.Token);

        await using var applicationStream = context.ApplicationStream;
        var buffer = new byte[1];
        var exception = await Assert.ThrowsAsync<IOException>(async () =>
            _ = await applicationStream.ReadAsync(buffer, lifetimeCts.Token));

        Assert.Contains("non-zero grpc-status: 13", exception.Message, StringComparison.Ordinal);
        await serverTask;
    }

    [Fact]
    public async Task OpenAsync_throws_when_server_completes_with_huffman_encoded_non_zero_grpc_status_trailer()
    {
        using var lifetimeCts = new CancellationTokenSource(TimeSpan.FromSeconds(10));
        using var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();

        var port = ((IPEndPoint)listener.LocalEndpoint).Port;
        var serverTask = CompleteGrpcRequestWithStatusTrailerAsync(
            listener,
            grpcStatus: 13,
            lifetimeCts.Token,
            useHuffmanTrailerValue: true);
        var profile = RuntimeInternetProfile.FromDefault();
        using var client = new TcpClient();
        await client.ConnectAsync(IPAddress.Loopback, port, lifetimeCts.Token);

        var context = await profile.OpenAsync(
            client.GetStream(),
            RuntimeInternetStack.Create(RuntimeInternetTransportProtocols.Grpc, RuntimeInternetSecurityTypes.None),
            new TestGrpcInternetOptions
            {
                ServerHost = "127.0.0.1",
                ServerPort = port,
                SecurityType = RuntimeInternetSecurityTypes.None,
                GrpcServiceName = "/trailers/test/Tun"
            },
            transportInitializationData: null,
            lifetimeCts.Token);

        await using var applicationStream = context.ApplicationStream;
        var buffer = new byte[1];
        var exception = await Assert.ThrowsAsync<IOException>(async () =>
            _ = await applicationStream.ReadAsync(buffer, lifetimeCts.Token));

        Assert.Contains("non-zero grpc-status: 13", exception.Message, StringComparison.Ordinal);
        await serverTask;
    }

    [Fact]
    public async Task RuntimeGrpcClientConnector_reuses_existing_http2_session_for_second_stream()
    {
        using var lifetimeCts = new CancellationTokenSource(TimeSpan.FromSeconds(10));
        using var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();

        var port = ((IPEndPoint)listener.LocalEndpoint).Port;
        var serverTask = CaptureTwoGrpcExchangesOnSingleConnectionAsync(listener, lifetimeCts.Token);
        var profile = RuntimeInternetProfile.FromDefault();
        var stack = RuntimeInternetStack.Create(RuntimeInternetTransportProtocols.Grpc, RuntimeInternetSecurityTypes.None);
        var options = new TestGrpcInternetOptions
        {
            ServerHost = "127.0.0.1",
            ServerPort = port,
            SecurityType = RuntimeInternetSecurityTypes.None,
            GrpcServiceName = "/reuse/service/Tun|TunMulti",
            GrpcUserAgent = "ReuseGrpc/1.0"
        };

        var firstContext = await RuntimeGrpcClientConnector.OpenAsync(
            options,
            stack,
            profile,
            SystemDnsResolver.Instance,
            transportInitializationData: null,
            lifetimeCts.Token);
        await using (firstContext.ApplicationStream)
        {
            await firstContext.ApplicationStream.WriteAsync("first-stream"u8.ToArray(), lifetimeCts.Token);
            await firstContext.ApplicationStream.FlushAsync(lifetimeCts.Token);
            var eof = new byte[1];
            var read = await firstContext.ApplicationStream.ReadAsync(eof, lifetimeCts.Token);
            Assert.Equal(0, read);
        }

        var secondContext = await RuntimeGrpcClientConnector.OpenAsync(
            options,
            stack,
            profile,
            SystemDnsResolver.Instance,
            transportInitializationData: null,
            lifetimeCts.Token);
        await using (secondContext.ApplicationStream)
        {
            await secondContext.ApplicationStream.WriteAsync("second-stream"u8.ToArray(), lifetimeCts.Token);
            await secondContext.ApplicationStream.FlushAsync(lifetimeCts.Token);
            var eof = new byte[1];
            var read = await secondContext.ApplicationStream.ReadAsync(eof, lifetimeCts.Token);
            Assert.Equal(0, read);
        }

        var captured = await serverTask;
        Assert.Equal(2, captured.Count);
        Assert.Equal(1, captured[0].StreamId);
        Assert.Equal(3, captured[1].StreamId);
        Assert.Equal("first-stream", captured[0].RequestPayloadText);
        Assert.Equal("second-stream", captured[1].RequestPayloadText);

        await profile.GrpcTunnelSessionPool.DisposeAsync();
    }

    [Fact]
    public void TryCreateSessionCacheKey_includes_normalized_reality_show_and_master_key_log()
    {
        var createCacheKey = CreateSessionCacheKeyFactory();
        var stack = RuntimeInternetStack.Create(RuntimeInternetTransportProtocols.Grpc, RuntimeInternetSecurityTypes.Reality);
        var baseOptions = new TestGrpcInternetOptions
        {
            ServerHost = "edge.example.com",
            ServerName = "edge.example.com",
            ServerPort = 443,
            SecurityType = RuntimeInternetSecurityTypes.Reality,
            RealityOptions = new RuntimeRealityOptions
            {
                PublicKey = EncodeBase64Url(32, 0x42)
            }
        };

        var defaultKey = createCacheKey(baseOptions, stack, null);
        var showKey = createCacheKey(
            baseOptions with
            {
                RealityOptions = baseOptions.RealityOptions with
                {
                    Show = true
                }
            },
            stack,
            null);
        var trimmedLogKey = createCacheKey(
            baseOptions with
            {
                RealityOptions = baseOptions.RealityOptions with
                {
                    Show = true,
                    MasterKeyLog = " logs/master.keys "
                }
            },
            stack,
            null);
        var normalizedLogKey = createCacheKey(
            baseOptions with
            {
                RealityOptions = baseOptions.RealityOptions with
                {
                    Show = true,
                    MasterKeyLog = "logs/master.keys"
                }
            },
            stack,
            null);
        var differentLogKey = createCacheKey(
            baseOptions with
            {
                RealityOptions = baseOptions.RealityOptions with
                {
                    Show = true,
                    MasterKeyLog = "logs/other.keys"
                }
            },
            stack,
            null);

        Assert.NotEqual(defaultKey, showKey);
        Assert.Equal(trimmedLogKey, normalizedLogKey);
        Assert.NotEqual(normalizedLogKey, differentLogKey);
        Assert.Contains("realityShow=1", normalizedLogKey, StringComparison.Ordinal);
        Assert.Contains("realityMasterKeyLog=logs/master.keys", normalizedLogKey, StringComparison.Ordinal);
    }

    [Fact]
    public void TryCreateSessionCacheKey_treats_none_master_key_log_as_empty()
    {
        var createCacheKey = CreateSessionCacheKeyFactory();
        var stack = RuntimeInternetStack.Create(RuntimeInternetTransportProtocols.Grpc, RuntimeInternetSecurityTypes.Reality);
        var baseOptions = new TestGrpcInternetOptions
        {
            ServerHost = "edge.example.com",
            ServerName = "edge.example.com",
            ServerPort = 443,
            SecurityType = RuntimeInternetSecurityTypes.Reality,
            RealityOptions = new RuntimeRealityOptions
            {
                Show = true,
                PublicKey = EncodeBase64Url(32, 0x42)
            }
        };

        var emptyKey = createCacheKey(baseOptions, stack, null);
        var noneKey = createCacheKey(
            baseOptions with
            {
                RealityOptions = baseOptions.RealityOptions with
                {
                    MasterKeyLog = " none "
                }
            },
            stack,
            null);

        Assert.Equal(emptyKey, noneKey);
        Assert.Contains("realityMasterKeyLog=", emptyKey, StringComparison.Ordinal);
    }

    [Fact]
    public async Task OpenSecuredTransportContextWithRetryAsync_does_not_retry_or_dispose_for_processed_invalid_reality_connection()
    {
        var createdStreams = new List<TrackingStream>();
        var provider = new ThrowingRealityHandshakeProvider(new RuntimeRealityProcessedInvalidConnectionException());
        var options = new TestGrpcInternetOptions
        {
            ServerHost = "edge.example.com",
            ServerName = "edge.example.com",
            SecurityType = RuntimeInternetSecurityTypes.Reality,
            RealityOptions = new RuntimeRealityOptions
            {
                PublicKey = EncodeBase64Url(32, 0x42)
            },
            TransportStreamFactory = _ =>
            {
                var stream = new TrackingStream();
                createdStreams.Add(stream);
                return ValueTask.FromResult<Stream>(stream);
            },
            RealityHandshakeProvider = provider
        };

        var exception = await Assert.ThrowsAsync<RuntimeRealityProcessedInvalidConnectionException>(async () =>
            await RuntimeGrpcClientConnector
                .OpenSecuredTransportContextWithRetryAsync(
                    options,
                    RuntimeInternetStack.Create(RuntimeInternetTransportProtocols.Grpc, RuntimeInternetSecurityTypes.Reality),
                    RuntimeInternetProfile.FromDefault(),
                    SystemDnsResolver.Instance,
                    CancellationToken.None)
                );

        Assert.Equal(RuntimeRealityProcessedInvalidConnectionException.DefaultMessage, exception.Message);
        Assert.Single(createdStreams);
        Assert.False(createdStreams[0].Disposed);
        Assert.Equal(1, provider.CallCount);
    }

    [Fact]
    public async Task RuntimeGrpcClientConnector_shares_single_transport_for_concurrent_dials()
    {
        using var lifetimeCts = new CancellationTokenSource(TimeSpan.FromSeconds(10));
        using var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();

        var port = ((IPEndPoint)listener.LocalEndpoint).Port;
        var serverTask = CaptureConcurrentGrpcExchangesOnSingleConnectionAsync(listener, lifetimeCts.Token);
        var profile = RuntimeInternetProfile.FromDefault();
        var stack = RuntimeInternetStack.Create(RuntimeInternetTransportProtocols.Grpc, RuntimeInternetSecurityTypes.None);
        var options = new TestGrpcInternetOptions
        {
            ServerHost = "127.0.0.1",
            ServerPort = port,
            SecurityType = RuntimeInternetSecurityTypes.None,
            GrpcServiceName = "/concurrent/service/Tun|TunMulti",
            GrpcUserAgent = "ConcurrentGrpc/1.0"
        };

        try
        {
            var openTasks = new[]
            {
                RuntimeGrpcClientConnector.OpenAsync(
                    options,
                    stack,
                    profile,
                    SystemDnsResolver.Instance,
                    transportInitializationData: null,
                    lifetimeCts.Token).AsTask(),
                RuntimeGrpcClientConnector.OpenAsync(
                    options,
                    stack,
                    profile,
                    SystemDnsResolver.Instance,
                    transportInitializationData: null,
                    lifetimeCts.Token).AsTask()
            };

            var contexts = await Task.WhenAll(openTasks);
            await using (contexts[0].ApplicationStream)
            await using (contexts[1].ApplicationStream)
            {
                await contexts[0].ApplicationStream.WriteAsync("first-stream"u8.ToArray(), lifetimeCts.Token);
                await contexts[0].ApplicationStream.FlushAsync(lifetimeCts.Token);
                await contexts[1].ApplicationStream.WriteAsync("second-stream"u8.ToArray(), lifetimeCts.Token);
                await contexts[1].ApplicationStream.FlushAsync(lifetimeCts.Token);

                var eof = new byte[1];
                var firstRead = await contexts[0].ApplicationStream.ReadAsync(eof, lifetimeCts.Token);
                var secondRead = await contexts[1].ApplicationStream.ReadAsync(eof, lifetimeCts.Token);
                Assert.Equal(0, firstRead);
                Assert.Equal(0, secondRead);
            }

            var captured = await serverTask;
            Assert.Equal(2, captured.Count);
            Assert.Equal([1, 3], captured.Select(static item => item.StreamId).OrderBy(static id => id).ToArray());
            Assert.Equal(
                ["first-stream", "second-stream"],
                captured.Select(static item => item.RequestPayloadText).OrderBy(static text => text, StringComparer.Ordinal).ToArray());
        }
        finally
        {
            await profile.GrpcTunnelSessionPool.DisposeAsync();
        }
    }

    [Fact]
    public async Task RuntimeGrpcClientConnector_opens_new_connection_after_goaway()
    {
        using var lifetimeCts = new CancellationTokenSource(TimeSpan.FromSeconds(10));
        using var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();

        var port = ((IPEndPoint)listener.LocalEndpoint).Port;
        var serverTask = CaptureGrpcExchangesAcrossGoAwayAsync(listener, lifetimeCts.Token);
        var profile = RuntimeInternetProfile.FromDefault();
        var stack = RuntimeInternetStack.Create(RuntimeInternetTransportProtocols.Grpc, RuntimeInternetSecurityTypes.None);
        var options = new TestGrpcInternetOptions
        {
            ServerHost = "127.0.0.1",
            ServerPort = port,
            SecurityType = RuntimeInternetSecurityTypes.None,
            GrpcServiceName = "/goaway/service/Tun|TunMulti",
            GrpcUserAgent = "GoAwayGrpc/1.0"
        };

        var firstContext = await RuntimeGrpcClientConnector.OpenAsync(
            options,
            stack,
            profile,
            SystemDnsResolver.Instance,
            transportInitializationData: null,
            lifetimeCts.Token);
        await using (firstContext.ApplicationStream)
        {
            await firstContext.ApplicationStream.WriteAsync("first-stream"u8.ToArray(), lifetimeCts.Token);
            await firstContext.ApplicationStream.FlushAsync(lifetimeCts.Token);
            var eof = new byte[1];
            var read = await firstContext.ApplicationStream.ReadAsync(eof, lifetimeCts.Token);
            Assert.Equal(0, read);
        }

        var secondContext = await RuntimeGrpcClientConnector.OpenAsync(
            options,
            stack,
            profile,
            SystemDnsResolver.Instance,
            transportInitializationData: null,
            lifetimeCts.Token);
        await using (secondContext.ApplicationStream)
        {
            await secondContext.ApplicationStream.WriteAsync("second-stream"u8.ToArray(), lifetimeCts.Token);
            await secondContext.ApplicationStream.FlushAsync(lifetimeCts.Token);
            var eof = new byte[1];
            var read = await secondContext.ApplicationStream.ReadAsync(eof, lifetimeCts.Token);
            Assert.Equal(0, read);
        }

        var captured = await serverTask;
        Assert.Equal(2, captured.Count);
        Assert.Equal(1, captured[0].StreamId);
        Assert.Equal(1, captured[1].StreamId);
        Assert.Equal("first-stream", captured[0].RequestPayloadText);
        Assert.Equal("second-stream", captured[1].RequestPayloadText);

        await profile.GrpcTunnelSessionPool.DisposeAsync();
    }

    [Fact]
    public async Task RuntimeGrpcClientConnector_warms_replacement_connection_in_background_after_goaway()
    {
        using var lifetimeCts = new CancellationTokenSource(TimeSpan.FromSeconds(10));
        using var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();

        var port = ((IPEndPoint)listener.LocalEndpoint).Port;
        var reconnectReadyTcs = new TaskCompletionSource<bool>(TaskCreationOptions.RunContinuationsAsynchronously);
        var serverTask = CaptureGrpcExchangesAcrossBackgroundReconnectAfterGoAwayAsync(
            listener,
            reconnectReadyTcs,
            lifetimeCts.Token);
        var profile = RuntimeInternetProfile.FromDefault();
        var stack = RuntimeInternetStack.Create(RuntimeInternetTransportProtocols.Grpc, RuntimeInternetSecurityTypes.None);
        var options = new TestGrpcInternetOptions
        {
            ServerHost = "127.0.0.1",
            ServerPort = port,
            SecurityType = RuntimeInternetSecurityTypes.None,
            GrpcServiceName = "/warm-goaway/service/Tun|TunMulti",
            GrpcUserAgent = "WarmGoAwayGrpc/1.0"
        };

        var firstContext = await RuntimeGrpcClientConnector.OpenAsync(
            options,
            stack,
            profile,
            SystemDnsResolver.Instance,
            transportInitializationData: null,
            lifetimeCts.Token);
        await using (firstContext.ApplicationStream)
        {
            await firstContext.ApplicationStream.WriteAsync("first-stream"u8.ToArray(), lifetimeCts.Token);
            await firstContext.ApplicationStream.FlushAsync(lifetimeCts.Token);
            var eof = new byte[1];
            var read = await firstContext.ApplicationStream.ReadAsync(eof, lifetimeCts.Token);
            Assert.Equal(0, read);
        }

        await reconnectReadyTcs.Task.WaitAsync(lifetimeCts.Token);

        var secondContext = await RuntimeGrpcClientConnector.OpenAsync(
            options,
            stack,
            profile,
            SystemDnsResolver.Instance,
            transportInitializationData: null,
            lifetimeCts.Token);
        await using (secondContext.ApplicationStream)
        {
            await secondContext.ApplicationStream.WriteAsync("second-stream"u8.ToArray(), lifetimeCts.Token);
            await secondContext.ApplicationStream.FlushAsync(lifetimeCts.Token);
            var eof = new byte[1];
            var read = await secondContext.ApplicationStream.ReadAsync(eof, lifetimeCts.Token);
            Assert.Equal(0, read);
        }

        var captured = await serverTask;
        Assert.Equal(2, captured.Count);
        Assert.Equal(1, captured[0].StreamId);
        Assert.Equal(1, captured[1].StreamId);
        Assert.Equal("first-stream", captured[0].RequestPayloadText);
        Assert.Equal("second-stream", captured[1].RequestPayloadText);

        await profile.GrpcTunnelSessionPool.DisposeAsync();
    }

    [Fact]
    public async Task RuntimeGrpcClientConnector_waits_for_background_reconnect_after_failed_replacement_attempt()
    {
        using var lifetimeCts = new CancellationTokenSource(TimeSpan.FromSeconds(10));
        using var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();

        var port = ((IPEndPoint)listener.LocalEndpoint).Port;
        var failedReconnectAcceptedTcs = new TaskCompletionSource<bool>(TaskCreationOptions.RunContinuationsAsynchronously);
        var serverTask = CaptureGrpcExchangesAcrossFailedBackgroundReconnectAfterGoAwayAsync(
            listener,
            failedReconnectAcceptedTcs,
            lifetimeCts.Token);
        var profile = RuntimeInternetProfile.FromDefault();
        var stack = RuntimeInternetStack.Create(RuntimeInternetTransportProtocols.Grpc, RuntimeInternetSecurityTypes.None);
        var options = new TestGrpcInternetOptions
        {
            ServerHost = "127.0.0.1",
            ServerPort = port,
            SecurityType = RuntimeInternetSecurityTypes.None,
            GrpcServiceName = "/failed-warm-goaway/service/Tun|TunMulti",
            GrpcUserAgent = "FailedWarmGoAwayGrpc/1.0"
        };

        var firstContext = await RuntimeGrpcClientConnector.OpenAsync(
            options,
            stack,
            profile,
            SystemDnsResolver.Instance,
            transportInitializationData: null,
            lifetimeCts.Token);
        await using (firstContext.ApplicationStream)
        {
            await firstContext.ApplicationStream.WriteAsync("first-stream"u8.ToArray(), lifetimeCts.Token);
            await firstContext.ApplicationStream.FlushAsync(lifetimeCts.Token);
            var eof = new byte[1];
            var read = await firstContext.ApplicationStream.ReadAsync(eof, lifetimeCts.Token);
            Assert.Equal(0, read);
        }

        await failedReconnectAcceptedTcs.Task.WaitAsync(lifetimeCts.Token);

        var secondContext = await RuntimeGrpcClientConnector.OpenAsync(
            options,
            stack,
            profile,
            SystemDnsResolver.Instance,
            transportInitializationData: null,
            lifetimeCts.Token);
        await using (secondContext.ApplicationStream)
        {
            await secondContext.ApplicationStream.WriteAsync("second-stream"u8.ToArray(), lifetimeCts.Token);
            await secondContext.ApplicationStream.FlushAsync(lifetimeCts.Token);
            var eof = new byte[1];
            var read = await secondContext.ApplicationStream.ReadAsync(eof, lifetimeCts.Token);
            Assert.Equal(0, read);
        }

        var captured = await serverTask;
        Assert.Equal(2, captured.Count);
        Assert.Equal(1, captured[0].StreamId);
        Assert.Equal(1, captured[1].StreamId);
        Assert.Equal("first-stream", captured[0].RequestPayloadText);
        Assert.Equal("second-stream", captured[1].RequestPayloadText);

        await profile.GrpcTunnelSessionPool.DisposeAsync();
    }

    [Fact]
    public async Task RuntimeGrpcClientConnector_retries_transport_open_failures_before_opening_grpc_stream()
    {
        using var lifetimeCts = new CancellationTokenSource(TimeSpan.FromSeconds(10));
        using var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();

        var port = ((IPEndPoint)listener.LocalEndpoint).Port;
        var serverTask = CompleteGrpcRequestWithStatusTrailerAsync(listener, grpcStatus: 0, lifetimeCts.Token);
        var profile = RuntimeInternetProfile.FromDefault();
        var stack = RuntimeInternetStack.Create(RuntimeInternetTransportProtocols.Grpc, RuntimeInternetSecurityTypes.None);
        var ownedClients = new List<TcpClient>();
        var attempts = 0;

        try
        {
            var context = await RuntimeGrpcClientConnector.OpenAsync(
                new TestGrpcInternetOptions
                {
                    ServerHost = "127.0.0.1",
                    ServerPort = port,
                    SecurityType = RuntimeInternetSecurityTypes.None,
                    GrpcServiceName = "/retry/service/Tun",
                    TransportStreamFactory = async cancellationToken =>
                    {
                        var attempt = Interlocked.Increment(ref attempts);
                        if (attempt < 3)
                        {
                            throw new IOException("Simulated transport open failure.");
                        }

                        var client = new TcpClient();
                        ownedClients.Add(client);
                        await client.ConnectAsync(IPAddress.Loopback, port, cancellationToken);
                        return client.GetStream();
                    }
                },
                stack,
                profile,
                SystemDnsResolver.Instance,
                transportInitializationData: null,
                lifetimeCts.Token);

            await using (context.ApplicationStream)
            {
                var eof = new byte[1];
                var read = await context.ApplicationStream.ReadAsync(eof, lifetimeCts.Token);
                Assert.Equal(0, read);
            }

            Assert.Equal(3, attempts);
            await serverTask;
        }
        finally
        {
            foreach (var client in ownedClients)
            {
                client.Dispose();
            }

            await profile.GrpcTunnelSessionPool.DisposeAsync();
        }
    }

    [Fact]
    public async Task RuntimeGrpcClientConnector_retries_grpc_transport_failures_after_secure_transport_is_open()
    {
        using var lifetimeCts = new CancellationTokenSource(TimeSpan.FromSeconds(10));
        using var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();

        var port = ((IPEndPoint)listener.LocalEndpoint).Port;
        var serverTask = FailFirstGrpcTransportAttemptAfterTcpConnectAsync(listener, lifetimeCts.Token);
        var profile = RuntimeInternetProfile.FromDefault();
        var stack = RuntimeInternetStack.Create(RuntimeInternetTransportProtocols.Grpc, RuntimeInternetSecurityTypes.None);
        var ownedClients = new List<TcpClient>();
        var attempts = 0;

        try
        {
            var context = await RuntimeGrpcClientConnector.OpenAsync(
                new TestGrpcInternetOptions
                {
                    ServerHost = "127.0.0.1",
                    ServerPort = port,
                    SecurityType = RuntimeInternetSecurityTypes.None,
                    GrpcServiceName = "/apply-retry/service/Tun",
                    TransportStreamFactory = async cancellationToken =>
                    {
                        var client = new TcpClient();
                        ownedClients.Add(client);
                        Interlocked.Increment(ref attempts);
                        await client.ConnectAsync(IPAddress.Loopback, port, cancellationToken);
                        return client.GetStream();
                    }
                },
                stack,
                profile,
                SystemDnsResolver.Instance,
                transportInitializationData: null,
                lifetimeCts.Token);

            await using (context.ApplicationStream)
            {
                var eof = new byte[1];
                var read = await context.ApplicationStream.ReadAsync(eof, lifetimeCts.Token);
                Assert.Equal(0, read);
            }

            Assert.Equal(2, attempts);
            await serverTask;
        }
        finally
        {
            foreach (var client in ownedClients)
            {
                client.Dispose();
            }

            await profile.GrpcTunnelSessionPool.DisposeAsync();
        }
    }

    [Fact]
    public async Task RuntimeGrpcClientConnector_delays_ws_transport_open_until_first_write_when_early_data_is_sent_via_subprotocol()
    {
        using var lifetimeCts = new CancellationTokenSource(TimeSpan.FromSeconds(10));
        using var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();

        var port = ((IPEndPoint)listener.LocalEndpoint).Port;
        var serverTask = CaptureWebSocketRequestAsync(listener, lifetimeCts.Token);
        var tlsSecurityFactory = new TestRuntimeInternetProfileFactory.RecordingFakeTlsSecurityFactory();
        var profile = TestRuntimeInternetProfileFactory.CreateWithFakeTls(tlsSecurityFactory);
        var stack = RuntimeInternetStack.Create(RuntimeInternetTransportProtocols.Ws, RuntimeInternetSecurityTypes.Tls);
        var ownedClients = new List<TcpClient>();
        RuntimeInternetConnectionContext? context = null;
        var transportOpenCount = 0;
        var payload = Encoding.ASCII.GetBytes("early-payload");
        var expectedEarlyData = Convert.ToBase64String(payload)
            .TrimEnd('=')
            .Replace('+', '-')
            .Replace('/', '_');

        try
        {
            context = await RuntimeGrpcClientConnector.OpenAsync(
                new TestGrpcInternetOptions
                {
                    ServerHost = "127.0.0.1",
                    ServerPort = port,
                    ServerName = "edge.example.com",
                    TransportProtocol = RuntimeInternetTransportProtocols.Ws,
                    SecurityType = RuntimeInternetSecurityTypes.Tls,
                    WebSocketPath = "/delayed",
                    WebSocketEarlyDataBytes = 4096,
                    TransportStreamFactory = async cancellationToken =>
                    {
                        var client = new TcpClient();
                        ownedClients.Add(client);
                        Interlocked.Increment(ref transportOpenCount);
                        await client.ConnectAsync(IPAddress.Loopback, port, cancellationToken);
                        return client.GetStream();
                    }
                },
                stack,
                profile,
                SystemDnsResolver.Instance,
                transportInitializationData: null,
                lifetimeCts.Token);

            Assert.Equal(0, transportOpenCount);
            Assert.Equal(RuntimeInternetSecurityTypes.Tls, context.SecurityState.SecurityType);
            Assert.Equal(SslProtocols.None, context.NegotiatedSslProtocol);
            Assert.Null(context.SslStream);

            await context.ApplicationStream.WriteAsync(payload, lifetimeCts.Token);

            Assert.Equal(1, transportOpenCount);
            Assert.NotNull(context.SslStream);
            Assert.Equal(SslProtocols.Tls13, context.NegotiatedSslProtocol);
            Assert.Equal("http/1.1", context.NegotiatedApplicationProtocol);
            Assert.Equal(["http/1.1"], tlsSecurityFactory.ObservedApplicationProtocols);

            var captured = await serverTask;
            Assert.Contains("GET /delayed HTTP/1.1", captured.RequestText, StringComparison.Ordinal);
            Assert.Contains("Host: edge.example.com", captured.RequestText, StringComparison.Ordinal);
            Assert.Contains($"Sec-WebSocket-Protocol: {expectedEarlyData}", captured.RequestText, StringComparison.Ordinal);
            Assert.Empty(captured.ExtraBytes);
        }
        finally
        {
            if (context is not null)
            {
                await RuntimeGrpcClientConnector.DisposeTransportContextAsync(context);
            }

            foreach (var client in ownedClients)
            {
                client.Dispose();
            }

            await profile.GrpcTunnelSessionPool.DisposeAsync();
        }
    }

    [Fact]
    public async Task RuntimeGrpcClientConnector_delays_ws_transport_open_until_first_write_when_payload_exceeds_early_data_limit()
    {
        using var lifetimeCts = new CancellationTokenSource(TimeSpan.FromSeconds(10));
        using var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();

        var port = ((IPEndPoint)listener.LocalEndpoint).Port;
        var serverTask = CaptureWebSocketRequestAsync(listener, lifetimeCts.Token);
        var tlsSecurityFactory = new TestRuntimeInternetProfileFactory.RecordingFakeTlsSecurityFactory();
        var profile = TestRuntimeInternetProfileFactory.CreateWithFakeTls(tlsSecurityFactory);
        var stack = RuntimeInternetStack.Create(RuntimeInternetTransportProtocols.Ws, RuntimeInternetSecurityTypes.Tls);
        var ownedClients = new List<TcpClient>();
        RuntimeInternetConnectionContext? context = null;
        var transportOpenCount = 0;
        var payload = Encoding.ASCII.GetBytes("frame-payload");

        try
        {
            context = await RuntimeGrpcClientConnector.OpenAsync(
                new TestGrpcInternetOptions
                {
                    ServerHost = "127.0.0.1",
                    ServerPort = port,
                    ServerName = "edge.example.com",
                    TransportProtocol = RuntimeInternetTransportProtocols.Ws,
                    SecurityType = RuntimeInternetSecurityTypes.Tls,
                    WebSocketPath = "/delayed-frame",
                    WebSocketEarlyDataBytes = 1,
                    TransportStreamFactory = async cancellationToken =>
                    {
                        var client = new TcpClient();
                        ownedClients.Add(client);
                        Interlocked.Increment(ref transportOpenCount);
                        await client.ConnectAsync(IPAddress.Loopback, port, cancellationToken);
                        return client.GetStream();
                    }
                },
                stack,
                profile,
                SystemDnsResolver.Instance,
                transportInitializationData: null,
                lifetimeCts.Token);

            Assert.Equal(0, transportOpenCount);
            Assert.Equal(SslProtocols.None, context.NegotiatedSslProtocol);

            await context.ApplicationStream.WriteAsync(payload, lifetimeCts.Token);

            Assert.Equal(1, transportOpenCount);
            Assert.NotNull(context.SslStream);
            Assert.Equal(SslProtocols.Tls13, context.NegotiatedSslProtocol);
            Assert.Equal(["http/1.1"], tlsSecurityFactory.ObservedApplicationProtocols);

            var captured = await serverTask;
            Assert.Contains("GET /delayed-frame HTTP/1.1", captured.RequestText, StringComparison.Ordinal);
            Assert.DoesNotContain("Sec-WebSocket-Protocol:", captured.RequestText, StringComparison.OrdinalIgnoreCase);
            Assert.Equal(payload, DecodeWebSocketClientBinaryFrame(captured.ExtraBytes));
        }
        finally
        {
            if (context is not null)
            {
                await RuntimeGrpcClientConnector.DisposeTransportContextAsync(context);
            }

            foreach (var client in ownedClients)
            {
                client.Dispose();
            }

            await profile.GrpcTunnelSessionPool.DisposeAsync();
        }
    }

    private static async Task<CapturedGrpcExchange> CaptureGrpcExchangeAsync(
        TcpListener listener,
        CancellationToken cancellationToken,
        bool useHuffmanStatusHeader = false)
    {
        using var client = await listener.AcceptTcpClientAsync(cancellationToken);
        await using var stream = client.GetStream();

        var preface = await ReadExactBytesAsync(stream, 24, cancellationToken);
        Assert.Equal("PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n", Encoding.ASCII.GetString(preface));

        var settingsFrame = await ReadHttp2FrameAsync(stream, cancellationToken);
        Assert.Equal(Http2TestFrameTypes.Settings, settingsFrame.Type);
        Assert.Equal(0, settingsFrame.StreamId);

        await WriteHttp2SettingsAsync(stream, cancellationToken);

        var headers = await ReadHttp2RequestHeadersAsync(stream, expectedStreamId: 1, cancellationToken);
        var requestPayload = await ReadGrpcHunkPayloadAsync(stream, expectedStreamId: 1, cancellationToken);

        await WriteHttp2HeadersStatusAsync(
            stream,
            streamId: 1,
            cancellationToken,
            useHuffmanLiteralValue: useHuffmanStatusHeader);
        await WriteGrpcHunkPayloadAsync(stream, "server-hunk"u8.ToArray(), streamId: 1, cancellationToken);
        await AllowClientToConsumeResponseAsync(cancellationToken);

        return new CapturedGrpcExchange(headers, Encoding.ASCII.GetString(requestPayload));
    }

    private static async Task<IReadOnlyList<CapturedStreamedGrpcExchange>> CaptureTwoGrpcExchangesOnSingleConnectionAsync(
        TcpListener listener,
        CancellationToken cancellationToken)
    {
        using var client = await listener.AcceptTcpClientAsync(cancellationToken);
        await using var stream = client.GetStream();

        var preface = await ReadExactBytesAsync(stream, 24, cancellationToken);
        Assert.Equal("PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n", Encoding.ASCII.GetString(preface));

        var settingsFrame = await ReadHttp2FrameAsync(stream, cancellationToken);
        Assert.Equal(Http2TestFrameTypes.Settings, settingsFrame.Type);
        Assert.Equal(0, settingsFrame.StreamId);

        await WriteHttp2SettingsAsync(stream, cancellationToken);

        var firstHeaders = await ReadHttp2RequestHeadersAsync(stream, expectedStreamId: 1, cancellationToken);
        var firstPayload = await ReadGrpcHunkPayloadAsync(stream, expectedStreamId: 1, cancellationToken);
        await WriteHttp2HeadersStatusAsync(stream, streamId: 1, cancellationToken);
        await WriteHttp2GrpcTrailersAsync(stream, streamId: 1, grpcStatus: 0, cancellationToken);

        var secondHeaders = await ReadHttp2RequestHeadersAsync(stream, expectedStreamId: 3, cancellationToken);
        var secondPayload = await ReadGrpcHunkPayloadAsync(stream, expectedStreamId: 3, cancellationToken);
        await WriteHttp2HeadersStatusAsync(stream, streamId: 3, cancellationToken);
        await WriteHttp2GrpcTrailersAsync(stream, streamId: 3, grpcStatus: 0, cancellationToken);
        await AllowClientToConsumeResponseAsync(cancellationToken);

        return
        [
            new CapturedStreamedGrpcExchange(1, firstHeaders, Encoding.ASCII.GetString(firstPayload)),
            new CapturedStreamedGrpcExchange(3, secondHeaders, Encoding.ASCII.GetString(secondPayload))
        ];
    }

    private static async Task<IReadOnlyList<CapturedStreamedGrpcExchange>> CaptureConcurrentGrpcExchangesOnSingleConnectionAsync(
        TcpListener listener,
        CancellationToken cancellationToken)
    {
        using var client = await listener.AcceptTcpClientAsync(cancellationToken);
        await using var stream = client.GetStream();

        var preface = await ReadExactBytesAsync(stream, 24, cancellationToken);
        Assert.Equal("PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n", Encoding.ASCII.GetString(preface));

        var settingsFrame = await ReadHttp2FrameAsync(stream, cancellationToken);
        Assert.Equal(Http2TestFrameTypes.Settings, settingsFrame.Type);
        Assert.Equal(0, settingsFrame.StreamId);

        await WriteHttp2SettingsAsync(stream, cancellationToken);

        var headersByStream = new Dictionary<int, IReadOnlyDictionary<string, string>>();
        var payloadsByStream = new Dictionary<int, string>();
        var grpcFramesByStream = new Dictionary<int, MemoryStream>();
        var expectedGrpcPayloadLengthByStream = new Dictionary<int, int>();

        while (headersByStream.Count < 2 || payloadsByStream.Count < 2)
        {
            var frame = await ReadHttp2FrameAsync(stream, cancellationToken);
            if (frame.Type == Http2TestFrameTypes.Settings &&
                (frame.Flags & Http2TestFrameFlags.Ack) == Http2TestFrameFlags.Ack)
            {
                continue;
            }

            if (frame.Type == Http2TestFrameTypes.WindowUpdate ||
                frame.Type == Http2TestFrameTypes.RstStream)
            {
                continue;
            }

            if (frame.Type == Http2TestFrameTypes.Headers)
            {
                var headerBlock = await ReadHttp2HeaderBlockAsync(stream, frame, cancellationToken);
                headersByStream[frame.StreamId] = DecodeHttp2RequestHeaders(headerBlock);
                continue;
            }

            if (frame.Type != Http2TestFrameTypes.Data)
            {
                continue;
            }

            if (!grpcFramesByStream.TryGetValue(frame.StreamId, out var grpcBuffer))
            {
                grpcBuffer = new MemoryStream();
                grpcFramesByStream[frame.StreamId] = grpcBuffer;
            }

            if (frame.Payload.Length > 0)
            {
                grpcBuffer.Write(frame.Payload, 0, frame.Payload.Length);
            }

            var raw = grpcBuffer.ToArray();
            if (!expectedGrpcPayloadLengthByStream.TryGetValue(frame.StreamId, out var expectedPayloadLength) &&
                raw.Length >= 5)
            {
                Assert.Equal(0, raw[0]);
                expectedPayloadLength = checked((int)BinaryPrimitives.ReadUInt32BigEndian(raw.AsSpan(1, 4)));
                expectedGrpcPayloadLengthByStream[frame.StreamId] = expectedPayloadLength;
            }

            if (expectedGrpcPayloadLengthByStream.TryGetValue(frame.StreamId, out expectedPayloadLength) &&
                raw.Length >= 5 + expectedPayloadLength)
            {
                payloadsByStream[frame.StreamId] = Encoding.ASCII.GetString(
                    DecodeGrpcHunk(raw.AsSpan(5, expectedPayloadLength)));
            }
        }

        foreach (var streamId in headersByStream.Keys.OrderBy(static id => id))
        {
            await WriteHttp2HeadersStatusAsync(stream, streamId, cancellationToken);
            await WriteHttp2GrpcTrailersAsync(stream, streamId, grpcStatus: 0, cancellationToken);
        }

        await AllowClientToConsumeResponseAsync(cancellationToken);
        await Task.Delay(TimeSpan.FromMilliseconds(100), cancellationToken);
        Assert.False(
            listener.Pending(),
            "Concurrent gRPC dials unexpectedly established more than one TCP connection for the same cache key.");

        return headersByStream.Keys
            .OrderBy(static id => id)
            .Select(streamId => new CapturedStreamedGrpcExchange(
                streamId,
                headersByStream[streamId],
                payloadsByStream[streamId]))
            .ToArray();
    }

    private static async Task<Http2TestFrame> CaptureGrpcClientTerminalFrameAsync(
        TcpListener listener,
        CancellationToken cancellationToken)
    {
        using var client = await listener.AcceptTcpClientAsync(cancellationToken);
        await using var stream = client.GetStream();

        var preface = await ReadExactBytesAsync(stream, 24, cancellationToken);
        Assert.Equal("PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n", Encoding.ASCII.GetString(preface));

        var settingsFrame = await ReadHttp2FrameAsync(stream, cancellationToken);
        Assert.Equal(Http2TestFrameTypes.Settings, settingsFrame.Type);
        Assert.Equal(0, settingsFrame.StreamId);

        await WriteHttp2SettingsAsync(stream, cancellationToken);

        _ = await ReadHttp2RequestHeadersAsync(stream, expectedStreamId: 1, cancellationToken);
        var payload = await ReadGrpcHunkPayloadAsync(stream, expectedStreamId: 1, cancellationToken);
        Assert.Equal("client-hunk", Encoding.ASCII.GetString(payload));

        while (true)
        {
            var frame = await ReadHttp2FrameAsync(stream, cancellationToken);
            if (frame.Type == Http2TestFrameTypes.Settings &&
                (frame.Flags & Http2TestFrameFlags.Ack) == Http2TestFrameFlags.Ack)
            {
                continue;
            }

            if (frame.Type == Http2TestFrameTypes.WindowUpdate)
            {
                continue;
            }

            Assert.NotEqual(Http2TestFrameTypes.RstStream, frame.Type);
            return frame;
        }
    }

    private static async Task CompleteGrpcRequestWithStatusTrailerAsync(
        TcpListener listener,
        int grpcStatus,
        CancellationToken cancellationToken,
        bool useHuffmanStatusHeader = false,
        bool useHuffmanTrailerValue = false)
    {
        using var client = await listener.AcceptTcpClientAsync(cancellationToken);
        await using var stream = client.GetStream();

        var preface = await ReadExactBytesAsync(stream, 24, cancellationToken);
        Assert.Equal("PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n", Encoding.ASCII.GetString(preface));

        var settingsFrame = await ReadHttp2FrameAsync(stream, cancellationToken);
        Assert.Equal(Http2TestFrameTypes.Settings, settingsFrame.Type);
        Assert.Equal(0, settingsFrame.StreamId);

        await WriteHttp2SettingsAsync(stream, cancellationToken);
        _ = await ReadHttp2RequestHeadersAsync(stream, expectedStreamId: 1, cancellationToken);

        await WriteHttp2HeadersStatusAsync(
            stream,
            streamId: 1,
            cancellationToken,
            useHuffmanLiteralValue: useHuffmanStatusHeader);
        await WriteHttp2GrpcTrailersAsync(
            stream,
            streamId: 1,
            grpcStatus,
            cancellationToken,
            useHuffmanValue: useHuffmanTrailerValue);
        await AllowClientToConsumeResponseAsync(cancellationToken);
    }

    private static async Task<IReadOnlyList<CapturedStreamedGrpcExchange>> CaptureGrpcExchangesAcrossGoAwayAsync(
        TcpListener listener,
        CancellationToken cancellationToken)
    {
        using var firstClient = await listener.AcceptTcpClientAsync(cancellationToken);
        await using var firstStream = firstClient.GetStream();

        var firstPreface = await ReadExactBytesAsync(firstStream, 24, cancellationToken);
        Assert.Equal("PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n", Encoding.ASCII.GetString(firstPreface));

        var firstSettingsFrame = await ReadHttp2FrameAsync(firstStream, cancellationToken);
        Assert.Equal(Http2TestFrameTypes.Settings, firstSettingsFrame.Type);
        Assert.Equal(0, firstSettingsFrame.StreamId);

        await WriteHttp2SettingsAsync(firstStream, cancellationToken);

        var firstHeaders = await ReadHttp2RequestHeadersAsync(firstStream, expectedStreamId: 1, cancellationToken);
        var firstPayload = await ReadGrpcHunkPayloadAsync(firstStream, expectedStreamId: 1, cancellationToken);
        await WriteHttp2HeadersStatusAsync(firstStream, streamId: 1, cancellationToken);
        await WriteHttp2GoAwayAsync(firstStream, lastStreamId: 1, errorCode: 0, cancellationToken);
        await WriteHttp2GrpcTrailersAsync(firstStream, streamId: 1, grpcStatus: 0, cancellationToken);
        await WaitForConnectionCloseAsync(firstStream, cancellationToken);

        using var secondClient = await listener.AcceptTcpClientAsync(cancellationToken);
        await using var secondStream = secondClient.GetStream();

        var secondPreface = await ReadExactBytesAsync(secondStream, 24, cancellationToken);
        Assert.Equal("PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n", Encoding.ASCII.GetString(secondPreface));

        var secondSettingsFrame = await ReadHttp2FrameAsync(secondStream, cancellationToken);
        Assert.Equal(Http2TestFrameTypes.Settings, secondSettingsFrame.Type);
        Assert.Equal(0, secondSettingsFrame.StreamId);

        await WriteHttp2SettingsAsync(secondStream, cancellationToken);

        var secondHeaders = await ReadHttp2RequestHeadersAsync(secondStream, expectedStreamId: 1, cancellationToken);
        var secondPayload = await ReadGrpcHunkPayloadAsync(secondStream, expectedStreamId: 1, cancellationToken);
        await WriteHttp2HeadersStatusAsync(secondStream, streamId: 1, cancellationToken);
        await WriteHttp2GrpcTrailersAsync(secondStream, streamId: 1, grpcStatus: 0, cancellationToken);
        await AllowClientToConsumeResponseAsync(cancellationToken);

        return
        [
            new CapturedStreamedGrpcExchange(1, firstHeaders, Encoding.ASCII.GetString(firstPayload)),
            new CapturedStreamedGrpcExchange(1, secondHeaders, Encoding.ASCII.GetString(secondPayload))
        ];
    }

    private static async Task<IReadOnlyList<CapturedStreamedGrpcExchange>> CaptureGrpcExchangesAcrossBackgroundReconnectAfterGoAwayAsync(
        TcpListener listener,
        TaskCompletionSource<bool> reconnectReadyTcs,
        CancellationToken cancellationToken)
    {
        try
        {
            using var firstClient = await listener.AcceptTcpClientAsync(cancellationToken);
            await using var firstStream = firstClient.GetStream();

            var firstPreface = await ReadExactBytesAsync(firstStream, 24, cancellationToken);
            Assert.Equal("PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n", Encoding.ASCII.GetString(firstPreface));

            var firstSettingsFrame = await ReadHttp2FrameAsync(firstStream, cancellationToken);
            Assert.Equal(Http2TestFrameTypes.Settings, firstSettingsFrame.Type);
            Assert.Equal(0, firstSettingsFrame.StreamId);

            await WriteHttp2SettingsAsync(firstStream, cancellationToken);

            var firstHeaders = await ReadHttp2RequestHeadersAsync(firstStream, expectedStreamId: 1, cancellationToken);
            var firstPayload = await ReadGrpcHunkPayloadAsync(firstStream, expectedStreamId: 1, cancellationToken);
            await WriteHttp2HeadersStatusAsync(firstStream, streamId: 1, cancellationToken);
            await WriteHttp2GoAwayAsync(firstStream, lastStreamId: 1, errorCode: 0, cancellationToken);
            await WriteHttp2GrpcTrailersAsync(firstStream, streamId: 1, grpcStatus: 0, cancellationToken);
            await WaitForConnectionCloseAsync(firstStream, cancellationToken);

            using var secondClient = await listener.AcceptTcpClientAsync(cancellationToken);
            await using var secondStream = secondClient.GetStream();

            var secondPreface = await ReadExactBytesAsync(secondStream, 24, cancellationToken);
            Assert.Equal("PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n", Encoding.ASCII.GetString(secondPreface));

            var secondSettingsFrame = await ReadHttp2FrameAsync(secondStream, cancellationToken);
            Assert.Equal(Http2TestFrameTypes.Settings, secondSettingsFrame.Type);
            Assert.Equal(0, secondSettingsFrame.StreamId);

            await WriteHttp2SettingsAsync(secondStream, cancellationToken);
            reconnectReadyTcs.TrySetResult(true);

            var secondHeaders = await ReadHttp2RequestHeadersAsync(secondStream, expectedStreamId: 1, cancellationToken);
            var secondPayload = await ReadGrpcHunkPayloadAsync(secondStream, expectedStreamId: 1, cancellationToken);
            await WriteHttp2HeadersStatusAsync(secondStream, streamId: 1, cancellationToken);
            await WriteHttp2GrpcTrailersAsync(secondStream, streamId: 1, grpcStatus: 0, cancellationToken);
            await AllowClientToConsumeResponseAsync(cancellationToken);

            return
            [
                new CapturedStreamedGrpcExchange(1, firstHeaders, Encoding.ASCII.GetString(firstPayload)),
                new CapturedStreamedGrpcExchange(1, secondHeaders, Encoding.ASCII.GetString(secondPayload))
            ];
        }
        catch (Exception ex)
        {
            reconnectReadyTcs.TrySetException(ex);
            throw;
        }
    }

    private static async Task<IReadOnlyList<CapturedStreamedGrpcExchange>> CaptureGrpcExchangesAcrossFailedBackgroundReconnectAfterGoAwayAsync(
        TcpListener listener,
        TaskCompletionSource<bool> failedReconnectAcceptedTcs,
        CancellationToken cancellationToken)
    {
        try
        {
            using var firstClient = await listener.AcceptTcpClientAsync(cancellationToken);
            await using var firstStream = firstClient.GetStream();

            var firstPreface = await ReadExactBytesAsync(firstStream, 24, cancellationToken);
            Assert.Equal("PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n", Encoding.ASCII.GetString(firstPreface));

            var firstSettingsFrame = await ReadHttp2FrameAsync(firstStream, cancellationToken);
            Assert.Equal(Http2TestFrameTypes.Settings, firstSettingsFrame.Type);
            Assert.Equal(0, firstSettingsFrame.StreamId);

            await WriteHttp2SettingsAsync(firstStream, cancellationToken);

            var firstHeaders = await ReadHttp2RequestHeadersAsync(firstStream, expectedStreamId: 1, cancellationToken);
            var firstPayload = await ReadGrpcHunkPayloadAsync(firstStream, expectedStreamId: 1, cancellationToken);
            await WriteHttp2HeadersStatusAsync(firstStream, streamId: 1, cancellationToken);
            await WriteHttp2GoAwayAsync(firstStream, lastStreamId: 1, errorCode: 0, cancellationToken);
            await WriteHttp2GrpcTrailersAsync(firstStream, streamId: 1, grpcStatus: 0, cancellationToken);
            await WaitForConnectionCloseAsync(firstStream, cancellationToken);

            using (var failedReconnectClient = await listener.AcceptTcpClientAsync(cancellationToken))
            {
                failedReconnectClient.Client.LingerState = new LingerOption(enable: true, seconds: 0);
            }

            failedReconnectAcceptedTcs.TrySetResult(true);

            using var secondClient = await listener.AcceptTcpClientAsync(cancellationToken);
            await using var secondStream = secondClient.GetStream();

            var secondPreface = await ReadExactBytesAsync(secondStream, 24, cancellationToken);
            Assert.Equal("PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n", Encoding.ASCII.GetString(secondPreface));

            var secondSettingsFrame = await ReadHttp2FrameAsync(secondStream, cancellationToken);
            Assert.Equal(Http2TestFrameTypes.Settings, secondSettingsFrame.Type);
            Assert.Equal(0, secondSettingsFrame.StreamId);

            await WriteHttp2SettingsAsync(secondStream, cancellationToken);

            var secondHeaders = await ReadHttp2RequestHeadersAsync(secondStream, expectedStreamId: 1, cancellationToken);
            var secondPayload = await ReadGrpcHunkPayloadAsync(secondStream, expectedStreamId: 1, cancellationToken);
            await WriteHttp2HeadersStatusAsync(secondStream, streamId: 1, cancellationToken);
            await WriteHttp2GrpcTrailersAsync(secondStream, streamId: 1, grpcStatus: 0, cancellationToken);
            await AllowClientToConsumeResponseAsync(cancellationToken);
            await Task.Delay(TimeSpan.FromMilliseconds(800), cancellationToken);
            Assert.False(
                listener.Pending(),
                "Foreground gRPC dial unexpectedly established an extra TCP connection while the background reconnect loop was already responsible for recovery.");

            return
            [
                new CapturedStreamedGrpcExchange(1, firstHeaders, Encoding.ASCII.GetString(firstPayload)),
                new CapturedStreamedGrpcExchange(1, secondHeaders, Encoding.ASCII.GetString(secondPayload))
            ];
        }
        catch (Exception ex)
        {
            failedReconnectAcceptedTcs.TrySetException(ex);
            throw;
        }
    }

    private static async Task FailFirstGrpcTransportAttemptAfterTcpConnectAsync(
        TcpListener listener,
        CancellationToken cancellationToken)
    {
        using (var failedClient = await listener.AcceptTcpClientAsync(cancellationToken))
        {
            failedClient.Client.LingerState = new LingerOption(enable: true, seconds: 0);
        }

        using var succeededClient = await listener.AcceptTcpClientAsync(cancellationToken);
        await using var succeededStream = succeededClient.GetStream();

        var preface = await ReadExactBytesAsync(succeededStream, 24, cancellationToken);
        Assert.Equal("PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n", Encoding.ASCII.GetString(preface));

        var settingsFrame = await ReadHttp2FrameAsync(succeededStream, cancellationToken);
        Assert.Equal(Http2TestFrameTypes.Settings, settingsFrame.Type);
        Assert.Equal(0, settingsFrame.StreamId);

        await WriteHttp2SettingsAsync(succeededStream, cancellationToken);
        _ = await ReadHttp2RequestHeadersAsync(succeededStream, expectedStreamId: 1, cancellationToken);

        await WriteHttp2HeadersStatusAsync(succeededStream, streamId: 1, cancellationToken);
        await WriteHttp2GrpcTrailersAsync(succeededStream, streamId: 1, grpcStatus: 0, cancellationToken);
        await AllowClientToConsumeResponseAsync(cancellationToken);
    }

    private static async Task<int> CaptureInitialWindowSizeAsync(
        TcpListener listener,
        CancellationToken cancellationToken)
    {
        using var client = await listener.AcceptTcpClientAsync(cancellationToken);
        await using var stream = client.GetStream();

        var preface = await ReadExactBytesAsync(stream, 24, cancellationToken);
        Assert.Equal("PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n", Encoding.ASCII.GetString(preface));

        var settingsFrame = await ReadHttp2FrameAsync(stream, cancellationToken);
        Assert.Equal(Http2TestFrameTypes.Settings, settingsFrame.Type);
        Assert.Equal(0, settingsFrame.StreamId);

        var settings = DecodeHttp2Settings(settingsFrame.Payload);
        await WriteHttp2SettingsAsync(stream, cancellationToken);
        _ = await ReadHttp2RequestHeadersAsync(stream, expectedStreamId: 1, cancellationToken);

        Assert.True(settings.TryGetValue(Http2TestSettingsIdentifiers.InitialWindowSize, out var initialWindowSize));
        return checked((int)initialWindowSize);
    }

    private static async Task AcknowledgeKeepAlivePingAndRespondAsync(
        TcpListener listener,
        CancellationToken cancellationToken)
    {
        using var client = await listener.AcceptTcpClientAsync(cancellationToken);
        await using var stream = client.GetStream();

        _ = await ReadExactBytesAsync(stream, 24, cancellationToken);
        _ = await ReadHttp2FrameAsync(stream, cancellationToken);
        await WriteHttp2SettingsAsync(stream, cancellationToken);
        _ = await ReadHttp2RequestHeadersAsync(stream, expectedStreamId: 1, cancellationToken);

        var ping = await ReadKeepAlivePingFrameAsync(stream, cancellationToken);
        await WriteFrameAsync(
            stream,
            Http2TestFrameTypes.Ping,
            Http2TestFrameFlags.Ack,
            streamId: 0,
            ping.Payload,
            cancellationToken);

        await WriteHttp2HeadersStatusAsync(stream, streamId: 1, cancellationToken);
        await WriteGrpcHunkPayloadAsync(stream, "server-after-ping"u8.ToArray(), streamId: 1, cancellationToken);
        await Task.Delay(TimeSpan.FromSeconds(2), cancellationToken);
        await WriteGrpcHunkPayloadAsync(stream, "server-still-alive"u8.ToArray(), streamId: 1, cancellationToken);
        await AllowClientToConsumeResponseAsync(cancellationToken);
    }

    private static async Task HoldKeepAlivePingWithoutAckAsync(
        TcpListener listener,
        CancellationToken cancellationToken)
    {
        using var client = await listener.AcceptTcpClientAsync(cancellationToken);
        await using var stream = client.GetStream();

        _ = await ReadExactBytesAsync(stream, 24, cancellationToken);
        _ = await ReadHttp2FrameAsync(stream, cancellationToken);
        await WriteHttp2SettingsAsync(stream, cancellationToken);
        _ = await ReadHttp2RequestHeadersAsync(stream, expectedStreamId: 1, cancellationToken);
        _ = await ReadKeepAlivePingFrameAsync(stream, cancellationToken);

        await Task.Delay(TimeSpan.FromSeconds(3), cancellationToken);
    }

    private static async Task<IReadOnlyDictionary<string, string>> ReadHttp2RequestHeadersAsync(
        Stream stream,
        int expectedStreamId,
        CancellationToken cancellationToken)
    {
        while (true)
        {
            var frame = await ReadHttp2FrameAsync(stream, cancellationToken);
            if (frame.Type == Http2TestFrameTypes.Settings &&
                (frame.Flags & Http2TestFrameFlags.Ack) == Http2TestFrameFlags.Ack)
            {
                continue;
            }

            if (frame.Type == Http2TestFrameTypes.WindowUpdate ||
                frame.Type == Http2TestFrameTypes.RstStream)
            {
                continue;
            }

            if (frame.Type != Http2TestFrameTypes.Headers)
            {
                continue;
            }

            Assert.Equal(expectedStreamId, frame.StreamId);
            var headerBlock = await ReadHttp2HeaderBlockAsync(stream, frame, cancellationToken);
            return DecodeHttp2RequestHeaders(headerBlock);
        }
    }

    private static async Task<byte[]> ReadGrpcHunkPayloadAsync(
        Stream stream,
        int expectedStreamId,
        CancellationToken cancellationToken)
    {
        using var buffer = new MemoryStream();
        var expectedMessageLength = -1;

        while (true)
        {
            var frame = await ReadHttp2FrameAsync(stream, cancellationToken);
            if (frame.Type == Http2TestFrameTypes.Settings &&
                (frame.Flags & Http2TestFrameFlags.Ack) == Http2TestFrameFlags.Ack)
            {
                continue;
            }

            if (frame.Type == Http2TestFrameTypes.WindowUpdate ||
                frame.Type == Http2TestFrameTypes.RstStream)
            {
                continue;
            }

            if (frame.Type != Http2TestFrameTypes.Data)
            {
                continue;
            }

            Assert.Equal(expectedStreamId, frame.StreamId);
            if (frame.Payload.Length > 0)
            {
                buffer.Write(frame.Payload, 0, frame.Payload.Length);
            }

            var raw = buffer.ToArray();
            if (expectedMessageLength < 0 && raw.Length >= 5)
            {
                Assert.Equal(0, raw[0]);
                expectedMessageLength = checked((int)BinaryPrimitives.ReadUInt32BigEndian(raw.AsSpan(1, 4)));
            }

            if (expectedMessageLength >= 0 && raw.Length >= 5 + expectedMessageLength)
            {
                return DecodeGrpcHunk(raw.AsSpan(5, expectedMessageLength));
            }
        }
    }

    private static async Task<Http2TestFrame> ReadKeepAlivePingFrameAsync(
        Stream stream,
        CancellationToken cancellationToken)
    {
        while (true)
        {
            var frame = await ReadHttp2FrameAsync(stream, cancellationToken);
            if (frame.Type == Http2TestFrameTypes.Settings &&
                (frame.Flags & Http2TestFrameFlags.Ack) == Http2TestFrameFlags.Ack)
            {
                continue;
            }

            if (frame.Type == Http2TestFrameTypes.WindowUpdate ||
                frame.Type == Http2TestFrameTypes.RstStream)
            {
                continue;
            }

            Assert.Equal(Http2TestFrameTypes.Ping, frame.Type);
            Assert.Equal(0, frame.StreamId);
            Assert.Equal(8, frame.Payload.Length);
            Assert.Equal(Http2TestFrameFlags.None, frame.Flags & Http2TestFrameFlags.Ack);
            return frame;
        }
    }

    private static Dictionary<ushort, uint> DecodeHttp2Settings(byte[] payload)
    {
        Assert.True(payload.Length % 6 == 0, "HTTP/2 SETTINGS payload must be a multiple of 6 bytes.");

        var settings = new Dictionary<ushort, uint>();
        for (var offset = 0; offset < payload.Length; offset += 6)
        {
            settings[(ushort)((payload[offset] << 8) | payload[offset + 1])] =
                BinaryPrimitives.ReadUInt32BigEndian(payload.AsSpan(offset + 2, 4));
        }

        return settings;
    }

    private static async Task WriteHttp2SettingsAsync(Stream stream, CancellationToken cancellationToken)
        => await WriteFrameAsync(
            stream,
            Http2TestFrameTypes.Settings,
            Http2TestFrameFlags.None,
            streamId: 0,
            payload: Array.Empty<byte>(),
            cancellationToken);

    private static async Task WriteHttp2HeadersStatusAsync(
        Stream stream,
        int streamId,
        CancellationToken cancellationToken,
        bool useHuffmanLiteralValue = false)
        => await WriteFrameAsync(
            stream,
            Http2TestFrameTypes.Headers,
            Http2TestFrameFlags.EndHeaders,
            streamId,
            payload: useHuffmanLiteralValue ? BuildStatus200HeaderBlock(useHuffmanLiteralValue) : [0x88],
            cancellationToken);

    private static async Task WriteHttp2GrpcTrailersAsync(
        Stream stream,
        int streamId,
        int grpcStatus,
        CancellationToken cancellationToken,
        bool useHuffmanValue = false)
        => await WriteFrameAsync(
            stream,
            Http2TestFrameTypes.Headers,
            Http2TestFrameFlags.EndHeaders | Http2TestFrameFlags.EndStream,
            streamId,
            BuildGrpcStatusHeaderBlock(grpcStatus, useHuffmanValue),
            cancellationToken);

    private static async Task WriteHttp2GoAwayAsync(
        Stream stream,
        int lastStreamId,
        uint errorCode,
        CancellationToken cancellationToken)
    {
        var payload = new byte[8];
        payload[0] = (byte)((lastStreamId >> 24) & 0x7F);
        payload[1] = (byte)((lastStreamId >> 16) & 0xFF);
        payload[2] = (byte)((lastStreamId >> 8) & 0xFF);
        payload[3] = (byte)(lastStreamId & 0xFF);
        BinaryPrimitives.WriteUInt32BigEndian(payload.AsSpan(4, 4), errorCode);

        await WriteFrameAsync(
            stream,
            Http2TestFrameTypes.GoAway,
            Http2TestFrameFlags.None,
            streamId: 0,
            payload,
            cancellationToken);
    }

    private static async Task WriteGrpcHunkPayloadAsync(
        Stream stream,
        byte[] payload,
        int streamId,
        CancellationToken cancellationToken)
    {
        var messagePayload = EncodeGrpcHunk(payload);
        var grpcFrame = new byte[5 + messagePayload.Length];
        grpcFrame[0] = 0;
        BinaryPrimitives.WriteUInt32BigEndian(grpcFrame.AsSpan(1, 4), (uint)messagePayload.Length);
        Buffer.BlockCopy(messagePayload, 0, grpcFrame, 5, messagePayload.Length);

        await WriteFrameAsync(
            stream,
            Http2TestFrameTypes.Data,
            Http2TestFrameFlags.None,
            streamId,
            grpcFrame,
            cancellationToken);
    }

    private static async Task WriteFrameAsync(
        Stream stream,
        byte type,
        Http2TestFrameFlags flags,
        int streamId,
        byte[] payload,
        CancellationToken cancellationToken)
    {
        var header = new byte[9];
        header[0] = (byte)((payload.Length >> 16) & 0xFF);
        header[1] = (byte)((payload.Length >> 8) & 0xFF);
        header[2] = (byte)(payload.Length & 0xFF);
        header[3] = type;
        header[4] = (byte)flags;
        header[5] = (byte)((streamId >> 24) & 0x7F);
        header[6] = (byte)((streamId >> 16) & 0xFF);
        header[7] = (byte)((streamId >> 8) & 0xFF);
        header[8] = (byte)(streamId & 0xFF);

        await stream.WriteAsync(header, cancellationToken);
        if (payload.Length > 0)
        {
            await stream.WriteAsync(payload, cancellationToken);
        }

        await stream.FlushAsync(cancellationToken);
    }

    private static Task AllowClientToConsumeResponseAsync(CancellationToken cancellationToken)
        => Task.Delay(TimeSpan.FromMilliseconds(150), cancellationToken);

    private static async Task<Http2TestFrame> ReadHttp2FrameAsync(
        Stream stream,
        CancellationToken cancellationToken)
    {
        var header = await ReadExactBytesAsync(stream, 9, cancellationToken);
        var length = (header[0] << 16) | (header[1] << 8) | header[2];
        var payload = length == 0
            ? Array.Empty<byte>()
            : await ReadExactBytesAsync(stream, length, cancellationToken);
        return new Http2TestFrame(
            header[3],
            (Http2TestFrameFlags)header[4],
            ((header[5] & 0x7F) << 24) |
            (header[6] << 16) |
            (header[7] << 8) |
            header[8],
            payload);
    }

    private static async Task<byte[]> ReadHttp2HeaderBlockAsync(
        Stream stream,
        Http2TestFrame firstFrame,
        CancellationToken cancellationToken)
    {
        using var buffer = new MemoryStream();
        if (firstFrame.Payload.Length > 0)
        {
            buffer.Write(firstFrame.Payload, 0, firstFrame.Payload.Length);
        }

        if ((firstFrame.Flags & Http2TestFrameFlags.EndHeaders) == Http2TestFrameFlags.EndHeaders)
        {
            return buffer.ToArray();
        }

        while (true)
        {
            var frame = await ReadHttp2FrameAsync(stream, cancellationToken);
            Assert.Equal(Http2TestFrameTypes.Continuation, frame.Type);
            Assert.Equal(firstFrame.StreamId, frame.StreamId);
            if (frame.Payload.Length > 0)
            {
                buffer.Write(frame.Payload, 0, frame.Payload.Length);
            }

            if ((frame.Flags & Http2TestFrameFlags.EndHeaders) == Http2TestFrameFlags.EndHeaders)
            {
                return buffer.ToArray();
            }
        }
    }

    private static Dictionary<string, string> DecodeHttp2RequestHeaders(byte[] headerBlock)
    {
        var headers = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        var offset = 0;

        while (offset < headerBlock.Length)
        {
            var first = headerBlock[offset];
            Assert.False((first & 0x80) != 0, "Unexpected indexed header field in gRPC request.");
            Assert.False((first & 0x20) != 0, "Unexpected dynamic table size update in gRPC request.");

            var nameIndex = ReadHpackInteger(headerBlock, ref offset, (first & 0x40) != 0 ? 6 : 4);
            var name = nameIndex switch
            {
                1 => ":authority",
                2 => ":method",
                4 => ":path",
                6 or 7 => ":scheme",
                58 => "user-agent",
                0 => ReadHpackString(headerBlock, ref offset),
                _ => throw new InvalidDataException($"Unsupported HPACK name index in gRPC test decoder: {nameIndex}.")
            };
            var value = ReadHpackString(headerBlock, ref offset);
            headers[name] = value;
        }

        return headers;
    }

    private static int ReadHpackInteger(byte[] buffer, ref int offset, int prefixBits)
    {
        var maxPrefixValue = (1 << prefixBits) - 1;
        var value = buffer[offset] & maxPrefixValue;
        offset++;

        if (value < maxPrefixValue)
        {
            return value;
        }

        var shift = 0;
        while (true)
        {
            var next = buffer[offset++];
            value += (next & 0x7F) << shift;
            if ((next & 0x80) == 0)
            {
                return value;
            }

            shift += 7;
        }
    }

    private static string ReadHpackString(byte[] buffer, ref int offset)
    {
        var huffmanEncoded = (buffer[offset] & 0x80) != 0;
        Assert.False(huffmanEncoded, "Unexpected Huffman-encoded HPACK string in gRPC test.");

        var length = ReadHpackInteger(buffer, ref offset, 7);
        var value = Encoding.ASCII.GetString(buffer, offset, length);
        offset += length;
        return value;
    }

    private static byte[] EncodeGrpcHunk(byte[] payload)
    {
        using var buffer = new MemoryStream(payload.Length + 8);
        WriteVarint(buffer, 0x0A);
        WriteVarint(buffer, payload.Length);
        if (payload.Length > 0)
        {
            buffer.Write(payload, 0, payload.Length);
        }

        return buffer.ToArray();
    }

    private static byte[] DecodeGrpcHunk(ReadOnlySpan<byte> payload)
    {
        var offset = 0;
        Assert.Equal(0x0Aul, ReadVarint(payload, ref offset));
        var length = checked((int)ReadVarint(payload, ref offset));
        return payload.Slice(offset, length).ToArray();
    }

    private static ulong ReadVarint(ReadOnlySpan<byte> payload, ref int offset)
    {
        ulong value = 0;
        var shift = 0;
        while (offset < payload.Length)
        {
            var next = payload[offset++];
            value |= ((ulong)(next & 0x7F)) << shift;
            if ((next & 0x80) == 0)
            {
                return value;
            }

            shift += 7;
        }

        throw new InvalidDataException("gRPC varint exceeded the available bytes.");
    }

    private static void WriteVarint(Stream stream, int value)
    {
        uint remaining = checked((uint)value);
        while (remaining >= 0x80)
        {
            stream.WriteByte((byte)((remaining & 0x7F) | 0x80));
            remaining >>= 7;
        }

        stream.WriteByte((byte)remaining);
    }

    private static byte[] BuildStatus200HeaderBlock(bool useHuffmanLiteralValue)
    {
        if (!useHuffmanLiteralValue)
        {
            return [0x88];
        }

        using var buffer = new MemoryStream();
        WriteLiteralHeaderFieldWithoutIndexing(
            buffer,
            nameIndex: 8,
            name: null,
            value: "200",
            useHuffmanForValue: true);
        return buffer.ToArray();
    }

    private static byte[] BuildGrpcStatusHeaderBlock(int status, bool useHuffmanValue = false)
    {
        using var buffer = new MemoryStream();
        WriteLiteralHeaderFieldWithoutIndexing(
            buffer,
            nameIndex: 0,
            name: "grpc-status",
            value: status.ToString(),
            useHuffmanForValue: useHuffmanValue);
        return buffer.ToArray();
    }

    private static void WriteLiteralHeaderFieldWithoutIndexing(
        MemoryStream buffer,
        int nameIndex,
        string? name,
        string value,
        bool useHuffmanForValue = false)
    {
        WriteInteger(buffer, nameIndex, prefixBits: 4, prefixMask: 0x00);
        if (nameIndex == 0)
        {
            WriteString(buffer, name ?? string.Empty);
        }

        WriteString(buffer, value, useHuffmanForValue);
    }

    private static void WriteInteger(MemoryStream buffer, int value, int prefixBits, byte prefixMask)
    {
        var maxPrefixValue = (1 << prefixBits) - 1;
        if (value < maxPrefixValue)
        {
            buffer.WriteByte((byte)(prefixMask | value));
            return;
        }

        buffer.WriteByte((byte)(prefixMask | maxPrefixValue));
        var remaining = value - maxPrefixValue;
        while (remaining >= 128)
        {
            buffer.WriteByte((byte)((remaining % 128) + 128));
            remaining /= 128;
        }

        buffer.WriteByte((byte)remaining);
    }

    private static void WriteString(MemoryStream buffer, string value, bool useHuffman = false)
    {
        if (useHuffman)
        {
            var encoded = GetKnownHuffmanEncodedBytes(value);
            WriteInteger(buffer, encoded.Length, prefixBits: 7, prefixMask: 0x80);
            buffer.Write(encoded, 0, encoded.Length);
            return;
        }

        var bytes = Encoding.UTF8.GetBytes(value);
        WriteInteger(buffer, bytes.Length, prefixBits: 7, prefixMask: 0x00);
        buffer.Write(bytes, 0, bytes.Length);
    }

    private static byte[] GetKnownHuffmanEncodedBytes(string value)
        => value switch
        {
            "0" => [0x07],
            "13" => [0x0B, 0x3F],
            "200" => [0x10, 0x01],
            _ => throw new NotSupportedException($"The gRPC test does not have a predefined HPACK Huffman encoding for '{value}'.")
        };

    private static async Task WaitForConnectionCloseAsync(
        Stream stream,
        CancellationToken cancellationToken)
    {
        var buffer = new byte[64];
        while (true)
        {
            var read = await stream.ReadAsync(buffer.AsMemory(), cancellationToken);
            if (read == 0)
            {
                return;
            }
        }
    }

    private static async Task ReadExactAsync(Stream stream, byte[] buffer, CancellationToken cancellationToken)
    {
        var read = 0;
        while (read < buffer.Length)
        {
            var count = await stream.ReadAsync(buffer.AsMemory(read, buffer.Length - read), cancellationToken);
            if (count == 0)
            {
                throw new EndOfStreamException("Unexpected EOF while reading gRPC test payload.");
            }

            read += count;
        }
    }

    private static async Task<byte[]> ReadExactBytesAsync(
        Stream stream,
        int length,
        CancellationToken cancellationToken)
    {
        var buffer = new byte[length];
        await ReadExactAsync(stream, buffer, cancellationToken);
        return buffer;
    }

    private static async Task<CapturedWebSocketRequest> CaptureWebSocketRequestAsync(
        TcpListener listener,
        CancellationToken cancellationToken)
    {
        using var client = await listener.AcceptTcpClientAsync(cancellationToken);
        await using var stream = client.GetStream();

        var requestText = await ReadHttpHeadersAsync(stream, cancellationToken);
        var webSocketKey = GetHeaderValue(requestText, "Sec-WebSocket-Key");
        var response =
            "HTTP/1.1 101 Switching Protocols\r\n" +
            "Upgrade: websocket\r\n" +
            "Connection: Upgrade\r\n" +
            $"Sec-WebSocket-Accept: {ComputeWebSocketAccept(webSocketKey)}\r\n" +
            "\r\n";

        await stream.WriteAsync(Encoding.ASCII.GetBytes(response), cancellationToken);
        await stream.FlushAsync(cancellationToken);

        var extraBytes = await ReadWithTimeoutAsync(stream, TimeSpan.FromMilliseconds(200));
        return new CapturedWebSocketRequest(requestText, extraBytes);
    }

    private static async Task<string> ReadHttpHeadersAsync(Stream stream, CancellationToken cancellationToken)
    {
        using var reader = new StreamReader(stream, Encoding.ASCII, detectEncodingFromByteOrderMarks: false, bufferSize: 1024, leaveOpen: true);
        var lines = new List<string>();

        while (true)
        {
            var line = await reader.ReadLineAsync(cancellationToken);
            if (line is null)
            {
                break;
            }

            lines.Add(line);
            if (line.Length == 0)
            {
                break;
            }
        }

        return string.Join("\r\n", lines);
    }

    private static async Task<byte[]> ReadWithTimeoutAsync(Stream stream, TimeSpan timeout)
    {
        using var timeoutCts = new CancellationTokenSource(timeout);
        var buffer = new byte[256];

        try
        {
            var read = await stream.ReadAsync(buffer.AsMemory(0, buffer.Length), timeoutCts.Token);
            return read == 0 ? Array.Empty<byte>() : buffer.AsSpan(0, read).ToArray();
        }
        catch (OperationCanceledException) when (timeoutCts.IsCancellationRequested)
        {
            return Array.Empty<byte>();
        }
    }

    private static string GetHeaderValue(string requestText, string name)
    {
        var prefix = name + ":";
        foreach (var line in requestText.Split("\r\n", StringSplitOptions.None))
        {
            if (line.StartsWith(prefix, StringComparison.OrdinalIgnoreCase))
            {
                return line[prefix.Length..].Trim();
            }
        }

        throw new InvalidDataException($"Missing header: {name}.");
    }

    private static string ComputeWebSocketAccept(string key)
    {
        const string webSocketGuid = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";
        var input = Encoding.ASCII.GetBytes(key + webSocketGuid);
        return Convert.ToBase64String(System.Security.Cryptography.SHA1.HashData(input));
    }

    private static byte[] DecodeWebSocketClientBinaryFrame(byte[] frame)
    {
        if (frame.Length < 6)
        {
            throw new InvalidDataException("WebSocket frame is incomplete.");
        }

        var opcode = frame[0] & 0x0f;
        if (opcode != 0x02)
        {
            throw new InvalidDataException($"Unexpected WebSocket opcode: 0x{opcode:x2}.");
        }

        var masked = (frame[1] & 0x80) != 0;
        if (!masked)
        {
            throw new InvalidDataException("Client WebSocket frame must be masked.");
        }

        var payloadLength = frame[1] & 0x7f;
        var offset = 2;
        ulong payloadLength64 = (ulong)payloadLength;
        if (payloadLength == 126)
        {
            if (frame.Length < offset + 2)
            {
                throw new InvalidDataException("WebSocket frame length is incomplete.");
            }

            payloadLength64 = ((ulong)frame[offset] << 8) | frame[offset + 1];
            offset += 2;
        }
        else if (payloadLength == 127)
        {
            if (frame.Length < offset + 8)
            {
                throw new InvalidDataException("WebSocket frame length is incomplete.");
            }

            payloadLength64 = 0;
            for (var index = 0; index < 8; index++)
            {
                payloadLength64 = (payloadLength64 << 8) | frame[offset + index];
            }

            offset += 8;
        }

        if (payloadLength64 > int.MaxValue)
        {
            throw new InvalidDataException("WebSocket frame payload is too large for this test helper.");
        }

        if (frame.Length < offset + 4 + (int)payloadLength64)
        {
            throw new InvalidDataException("WebSocket frame payload is incomplete.");
        }

        var maskingKey = frame.AsSpan(offset, 4);
        offset += 4;
        var payload = frame.AsSpan(offset, (int)payloadLength64).ToArray();
        for (var index = 0; index < payload.Length; index++)
        {
            payload[index] ^= maskingKey[index % 4];
        }

        return payload;
    }

    private sealed record CapturedGrpcExchange(
        IReadOnlyDictionary<string, string> Headers,
        string RequestPayloadText);

    private sealed record CapturedWebSocketRequest(
        string RequestText,
        byte[] ExtraBytes);

    private sealed record CapturedStreamedGrpcExchange(
        int StreamId,
        IReadOnlyDictionary<string, string> Headers,
        string RequestPayloadText);

    private sealed record TestGrpcInternetOptions : IRuntimeGrpcClientDialOptions
    {
        public DispatchContext DialContext { get; init; } = new();

        public EndPoint? SourceEndPoint { get; init; }

        public EndPoint? LocalEndPoint { get; init; }

        public string Via { get; init; } = string.Empty;

        public string ViaCidr { get; init; } = string.Empty;

        public string ServerHost { get; init; } = string.Empty;

        public int ServerPort { get; init; } = 443;

        public string ServerName { get; init; } = string.Empty;

        public string Fingerprint { get; init; } = string.Empty;

        public string TransportProtocol { get; init; } = RuntimeInternetTransportProtocols.Grpc;

        public string SecurityType { get; init; } = RuntimeInternetSecurityTypes.Tls;

        public RuntimeRealityOptions RealityOptions { get; init; } = RuntimeRealityOptions.Empty;

        public string WebSocketPath { get; init; } = "/";

        public IReadOnlyDictionary<string, string> WebSocketHeaders { get; init; }
            = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);

        public int WebSocketEarlyDataBytes { get; init; }

        public int WebSocketHeartbeatPeriodSeconds => 0;

        public string SplitHttpHost { get; init; } = string.Empty;

        public string SplitHttpPath { get; init; } = "/";

        public IReadOnlyDictionary<string, string> SplitHttpHeaders { get; init; }
            = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);

        public string SplitHttpMode { get; init; } = string.Empty;

        public bool SplitHttpNoGrpcHeader => false;

        public RuntimeInt32Range SplitHttpXPaddingBytes => RuntimeInt32Range.Empty;

        public bool SplitHttpXPaddingObfsMode => false;

        public string SplitHttpXPaddingKey => string.Empty;

        public string SplitHttpXPaddingHeader => string.Empty;

        public string SplitHttpXPaddingPlacement => string.Empty;

        public string SplitHttpXPaddingMethod => string.Empty;

        public string SplitHttpUplinkHttpMethod => string.Empty;

        public string SplitHttpSessionPlacement => string.Empty;

        public string SplitHttpSessionKey => string.Empty;

        public string SplitHttpSeqPlacement => string.Empty;

        public string SplitHttpSeqKey => string.Empty;

        public string SplitHttpUplinkDataPlacement => string.Empty;

        public string SplitHttpUplinkDataKey => string.Empty;

        public RuntimeInt32Range SplitHttpUplinkChunkSize => RuntimeInt32Range.Empty;

        public RuntimeInt32Range SplitHttpScMaxEachPostBytes => RuntimeInt32Range.Empty;

        public RuntimeInt32Range SplitHttpScMinPostsIntervalMs => RuntimeInt32Range.Empty;

        public int SplitHttpScMaxBufferedPosts => 0;

        public RuntimeSplitHttpXmuxOptions SplitHttpXmux => RuntimeSplitHttpXmuxOptions.Empty;

        public RuntimeSplitHttpDownloadOptions? SplitHttpDownloadSettings => null;

        public IReadOnlyList<string> ApplicationProtocols { get; init; } = Array.Empty<string>();

        public RuntimeQuicOptions QuicOptions => RuntimeQuicOptions.Empty;

        public string GrpcServiceName { get; init; } = string.Empty;

        public string GrpcAuthority { get; init; } = string.Empty;

        public bool GrpcMultiMode { get; init; }

        public string GrpcUserAgent { get; init; } = string.Empty;

        public int GrpcIdleTimeoutSeconds { get; init; }

        public int GrpcHealthCheckTimeoutSeconds { get; init; }

        public bool GrpcPermitWithoutStream { get; init; }

        public int GrpcInitialWindowSize { get; init; }

        public int ConnectTimeoutSeconds { get; init; } = 10;

        public int HandshakeTimeoutSeconds { get; init; } = 10;

        public bool SkipCertificateValidation => true;

        public RemoteCertificateValidationCallback? CertificateValidationCallback => null;

        public SslProtocols EnabledSslProtocols => SslProtocols.Tls12 | SslProtocols.Tls13;

        public IRuntimeRealityHandshakeProvider? RealityHandshakeProvider { get; init; }

        public Func<CancellationToken, ValueTask<Stream>>? TransportStreamFactory { get; init; }

        public Func<CancellationToken, ValueTask<Stream>>? SplitHttpDownloadTransportStreamFactory { get; init; }
    }

    private readonly record struct Http2TestFrame(
        byte Type,
        Http2TestFrameFlags Flags,
        int StreamId,
        byte[] Payload);

    [Flags]
    private enum Http2TestFrameFlags : byte
    {
        None = 0,
        Ack = 0x1,
        EndStream = 0x1,
        EndHeaders = 0x4
    }

    private static class Http2TestFrameTypes
    {
        public const byte Data = 0x0;
        public const byte Headers = 0x1;
        public const byte GoAway = 0x7;
        public const byte Ping = 0x6;
        public const byte RstStream = 0x3;
        public const byte Settings = 0x4;
        public const byte WindowUpdate = 0x8;
        public const byte Continuation = 0x9;
    }

    private static class Http2TestSettingsIdentifiers
    {
        public const ushort InitialWindowSize = 0x4;
    }

    private static string EncodeBase64Url(int length, byte value)
        => Convert.ToBase64String(Enumerable.Repeat(value, length).ToArray())
            .TrimEnd('=')
            .Replace('+', '-')
            .Replace('/', '_');

    private static CreateSessionCacheKeyFunc CreateSessionCacheKeyFactory()
    {
        var method = typeof(RuntimeGrpcClientConnector)
            .GetMethods(BindingFlags.Static | BindingFlags.NonPublic)
            .SingleOrDefault(static candidate => candidate.Name == "TryCreateSessionCacheKey");
        Assert.NotNull(method);
        return method!
            .MakeGenericMethod(typeof(TestGrpcInternetOptions))
            .CreateDelegate<CreateSessionCacheKeyFunc>();
    }

    private delegate string CreateSessionCacheKeyFunc(
        TestGrpcInternetOptions options,
        RuntimeInternetStack internetStack,
        byte[]? transportInitializationData);

    private sealed class ThrowingRealityHandshakeProvider : IRuntimeRealityHandshakeProvider
    {
        private readonly Exception _exception;

        public ThrowingRealityHandshakeProvider(Exception exception)
        {
            _exception = exception;
        }

        public string Identity => "throwing-reality-provider";

        public int CallCount { get; private set; }

        public ValueTask<RuntimeRealityHandshakeResult> SecureAsync(
            RuntimeRealityHandshakeRequest request,
            CancellationToken cancellationToken)
        {
            CallCount++;
            return ValueTask.FromException<RuntimeRealityHandshakeResult>(_exception);
        }
    }

    private sealed class TrackingStream : Stream
    {
        public bool Disposed { get; private set; }

        public override bool CanRead => true;

        public override bool CanSeek => false;

        public override bool CanWrite => true;

        public override long Length => 0;

        public override long Position
        {
            get => 0;
            set => throw new NotSupportedException();
        }

        public override void Flush()
        {
        }

        public override int Read(byte[] buffer, int offset, int count)
            => 0;

        public override long Seek(long offset, SeekOrigin origin)
            => throw new NotSupportedException();

        public override void SetLength(long value)
            => throw new NotSupportedException();

        public override void Write(byte[] buffer, int offset, int count)
        {
        }

        public override ValueTask DisposeAsync()
        {
            Disposed = true;
            return ValueTask.CompletedTask;
        }
    }
}

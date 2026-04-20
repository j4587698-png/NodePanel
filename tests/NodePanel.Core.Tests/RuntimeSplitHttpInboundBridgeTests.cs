using System.Net;
using System.Net.Quic;
using System.Net.Security;
using System.Net.Sockets;
using System.Runtime.Versioning;
using System.Security.Authentication;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using NodePanel.Core.Runtime;

namespace NodePanel.Core.Tests;

[SupportedOSPlatform("windows")]
[SupportedOSPlatform("linux")]
[SupportedOSPlatform("macos")]
public sealed class RuntimeSplitHttpInboundBridgeTests
{
    [Fact]
    public async Task ServeAsync_stream_one_over_http11_exposes_duplex_stream()
    {
        using var lifetimeCts = new CancellationTokenSource(TimeSpan.FromSeconds(10));
        using var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();

        using var client = new TcpClient { NoDelay = true };
        var acceptTask = listener.AcceptTcpClientAsync(lifetimeCts.Token).AsTask();
        await client.ConnectAsync(IPAddress.Loopback, ((IPEndPoint)listener.LocalEndpoint).Port, lifetimeCts.Token);
        using var serverClient = await acceptTask;

        const string clientPayload = "stream-one-client";
        const string serverPayload = "stream-one-server";
        string? observedPayload = null;
        var bridge = new RuntimeSplitHttpInboundBridge(CreateOptions("stream-one"));
        var serverTask = Task.Run(async () =>
        {
            await using var serverStream = serverClient.GetStream();
            await bridge.ServeAsync(
                serverStream,
                async (applicationStream, token) =>
                {
                    observedPayload = await ReadTextToEndAsync(applicationStream, token);
                    await applicationStream.WriteAsync(Encoding.ASCII.GetBytes(serverPayload), token);
                },
                lifetimeCts.Token);
        }, lifetimeCts.Token);

        await using var clientStream = client.GetStream();
        await clientStream.WriteAsync(
            Encoding.ASCII.GetBytes(BuildChunkedRequest(
                "POST",
                "/xhttp/?x_padding=X",
                "edge.example.com",
                clientPayload,
                "Content-Type: application/grpc")),
            lifetimeCts.Token);
        await clientStream.FlushAsync(lifetimeCts.Token);

        var response = await ReadResponseAsync(clientStream, lifetimeCts.Token);
        await serverTask;

        Assert.Equal(clientPayload, observedPayload);
        Assert.Equal(200, response.StatusCode);
        Assert.Equal("text/event-stream", response.Headers["Content-Type"]);
        Assert.Equal("no", response.Headers["X-Accel-Buffering"]);
        Assert.Equal("no-store", response.Headers["Cache-Control"]);
        Assert.Equal("X", response.Headers["X-Padding"]);
        Assert.Equal(serverPayload, response.BodyText);
    }

    [Fact]
    public async Task ServeAsync_stream_up_shares_session_between_get_and_post()
    {
        using var lifetimeCts = new CancellationTokenSource(TimeSpan.FromSeconds(10));
        using var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();

        const string sessionId = "session-1";
        const string clientPayload = "stream-up-client";
        const string serverPayload = "stream-up-server";
        string? observedPayload = null;
        var bridge = new RuntimeSplitHttpInboundBridge(CreateOptions("stream-up"));
        var serverTask = AcceptAndServeAsync(
            listener,
            bridge,
            2,
            async (applicationStream, token) =>
            {
                observedPayload = await ReadExactTextAsync(applicationStream, clientPayload.Length, token);
                await applicationStream.WriteAsync(Encoding.ASCII.GetBytes(serverPayload), token);
            },
            lifetimeCts.Token);

        using var downlinkClient = new TcpClient { NoDelay = true };
        using var uploadClient = new TcpClient { NoDelay = true };
        await downlinkClient.ConnectAsync(IPAddress.Loopback, ((IPEndPoint)listener.LocalEndpoint).Port, lifetimeCts.Token);
        await uploadClient.ConnectAsync(IPAddress.Loopback, ((IPEndPoint)listener.LocalEndpoint).Port, lifetimeCts.Token);

        await using var downlinkStream = downlinkClient.GetStream();
        await using var uploadStream = uploadClient.GetStream();

        await downlinkStream.WriteAsync(
            Encoding.ASCII.GetBytes(BuildGetRequest(
                $"/xhttp/{sessionId}?x_padding=X",
                "edge.example.com")),
            lifetimeCts.Token);
        await downlinkStream.FlushAsync(lifetimeCts.Token);

        await uploadStream.WriteAsync(
            Encoding.ASCII.GetBytes(BuildChunkedRequest(
                "POST",
                $"/xhttp/{sessionId}?x_padding=X",
                "edge.example.com",
                clientPayload,
                "Content-Type: application/grpc")),
            lifetimeCts.Token);
        await uploadStream.FlushAsync(lifetimeCts.Token);

        var uploadResponse = await ReadResponseHeadersOnlyAsync(uploadStream, lifetimeCts.Token);
        var downlinkResponse = await ReadResponseAsync(downlinkStream, lifetimeCts.Token);
        await serverTask;

        Assert.Equal(clientPayload, observedPayload);
        Assert.Equal(200, uploadResponse.StatusCode);
        Assert.Equal(200, downlinkResponse.StatusCode);
        Assert.Equal(serverPayload, downlinkResponse.BodyText);
        Assert.Equal("no", downlinkResponse.Headers["X-Accel-Buffering"]);
        Assert.Equal("no-store", downlinkResponse.Headers["Cache-Control"]);
    }

    [Fact]
    public async Task ServeAsync_packet_up_accepts_header_payloads()
    {
        using var lifetimeCts = new CancellationTokenSource(TimeSpan.FromSeconds(10));
        using var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();

        const string sessionId = "session-2";
        const string clientPayload = "packet-up-client";
        const string serverPayload = "packet-up-server";
        string? observedPayload = null;
        var bridge = new RuntimeSplitHttpInboundBridge(new RuntimeSplitHttpInboundOptions
        {
            Host = "edge.example.com",
            Path = "/xhttp/",
            Mode = "packet-up",
            UplinkDataPlacement = "header",
            UplinkDataKey = "X-Data",
            XPaddingBytes = new RuntimeInt32Range
            {
                From = 1,
                To = 1
            }
        });
        var serverTask = AcceptAndServeAsync(
            listener,
            bridge,
            2,
            async (applicationStream, token) =>
            {
                observedPayload = await ReadExactTextAsync(applicationStream, clientPayload.Length, token);
                await applicationStream.WriteAsync(Encoding.ASCII.GetBytes(serverPayload), token);
            },
            lifetimeCts.Token);

        using var downlinkClient = new TcpClient { NoDelay = true };
        using var uploadClient = new TcpClient { NoDelay = true };
        await downlinkClient.ConnectAsync(IPAddress.Loopback, ((IPEndPoint)listener.LocalEndpoint).Port, lifetimeCts.Token);
        await uploadClient.ConnectAsync(IPAddress.Loopback, ((IPEndPoint)listener.LocalEndpoint).Port, lifetimeCts.Token);

        await using var downlinkStream = downlinkClient.GetStream();
        await using var uploadStream = uploadClient.GetStream();

        await downlinkStream.WriteAsync(
            Encoding.ASCII.GetBytes(BuildGetRequest(
                $"/xhttp/{sessionId}?x_padding=X",
                "edge.example.com")),
            lifetimeCts.Token);
        await downlinkStream.FlushAsync(lifetimeCts.Token);

        await uploadStream.WriteAsync(
            Encoding.ASCII.GetBytes(BuildHeaderPayloadRequest(
                $"/xhttp/{sessionId}/0?x_padding=X",
                "edge.example.com",
                clientPayload)),
            lifetimeCts.Token);
        await uploadStream.FlushAsync(lifetimeCts.Token);

        var uploadResponse = await ReadResponseAsync(uploadStream, lifetimeCts.Token);
        var downlinkResponse = await ReadResponseAsync(downlinkStream, lifetimeCts.Token);
        await serverTask;

        Assert.Equal(clientPayload, observedPayload);
        Assert.Equal(200, uploadResponse.StatusCode);
        Assert.Equal(200, downlinkResponse.StatusCode);
        Assert.Equal(serverPayload, downlinkResponse.BodyText);
    }

    [Fact]
    public async Task ServeAsync_packet_up_accepts_cookie_payloads_and_enables_credentials()
    {
        using var lifetimeCts = new CancellationTokenSource(TimeSpan.FromSeconds(10));
        using var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();

        const string sessionId = "session-3";
        const string clientPayload = "packet-cookie-client";
        const string serverPayload = "packet-cookie-server";
        string? observedPayload = null;
        var bridge = new RuntimeSplitHttpInboundBridge(new RuntimeSplitHttpInboundOptions
        {
            Host = "edge.example.com",
            Path = "/xhttp/",
            Mode = "packet-up",
            UplinkDataPlacement = "cookie",
            UplinkDataKey = "x_data",
            XPaddingBytes = new RuntimeInt32Range
            {
                From = 1,
                To = 1
            }
        });
        var serverTask = AcceptAndServeAsync(
            listener,
            bridge,
            2,
            async (applicationStream, token) =>
            {
                observedPayload = await ReadExactTextAsync(applicationStream, clientPayload.Length, token);
                await applicationStream.WriteAsync(Encoding.ASCII.GetBytes(serverPayload), token);
            },
            lifetimeCts.Token);

        using var downlinkClient = new TcpClient { NoDelay = true };
        using var uploadClient = new TcpClient { NoDelay = true };
        await downlinkClient.ConnectAsync(IPAddress.Loopback, ((IPEndPoint)listener.LocalEndpoint).Port, lifetimeCts.Token);
        await uploadClient.ConnectAsync(IPAddress.Loopback, ((IPEndPoint)listener.LocalEndpoint).Port, lifetimeCts.Token);

        await using var downlinkStream = downlinkClient.GetStream();
        await using var uploadStream = uploadClient.GetStream();

        await downlinkStream.WriteAsync(
            Encoding.ASCII.GetBytes(BuildGetRequest(
                $"/xhttp/{sessionId}?x_padding=X",
                "edge.example.com")),
            lifetimeCts.Token);
        await downlinkStream.FlushAsync(lifetimeCts.Token);

        await uploadStream.WriteAsync(
            Encoding.ASCII.GetBytes(BuildCookiePayloadRequest(
                $"/xhttp/{sessionId}/0?x_padding=X",
                "edge.example.com",
                clientPayload)),
            lifetimeCts.Token);
        await uploadStream.FlushAsync(lifetimeCts.Token);

        var uploadResponse = await ReadResponseAsync(uploadStream, lifetimeCts.Token);
        var downlinkResponse = await ReadResponseAsync(downlinkStream, lifetimeCts.Token);
        await serverTask;

        Assert.Equal(clientPayload, observedPayload);
        Assert.Equal(200, uploadResponse.StatusCode);
        Assert.Equal(200, downlinkResponse.StatusCode);
        Assert.Equal("true", uploadResponse.Headers["Access-Control-Allow-Credentials"]);
        Assert.Equal("true", downlinkResponse.Headers["Access-Control-Allow-Credentials"]);
        Assert.Equal(serverPayload, downlinkResponse.BodyText);
    }

    [Fact]
    public async Task ServeAsync_packet_up_rejects_payloads_exceeding_sc_max_each_post_bytes()
    {
        using var lifetimeCts = new CancellationTokenSource(TimeSpan.FromSeconds(10));
        using var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();

        var bridge = new RuntimeSplitHttpInboundBridge(new RuntimeSplitHttpInboundOptions
        {
            Host = "edge.example.com",
            Path = "/xhttp/",
            Mode = "packet-up",
            XPaddingBytes = new RuntimeInt32Range
            {
                From = 1,
                To = 1
            },
            ScMaxEachPostBytes = new RuntimeInt32Range
            {
                From = 4,
                To = 4
            }
        });
        var serverTask = AcceptAndServeAsync(
            listener,
            bridge,
            1,
            static (_, _) => Task.CompletedTask,
            lifetimeCts.Token);

        using var client = new TcpClient { NoDelay = true };
        await client.ConnectAsync(IPAddress.Loopback, ((IPEndPoint)listener.LocalEndpoint).Port, lifetimeCts.Token);

        await using var stream = client.GetStream();
        await stream.WriteAsync(
            Encoding.ASCII.GetBytes(BuildChunkedRequest(
                "POST",
                "/xhttp/session-4/0?x_padding=X",
                "edge.example.com",
                "12345",
                "Content-Type: application/grpc")),
            lifetimeCts.Token);
        await stream.FlushAsync(lifetimeCts.Token);

        var response = await ReadResponseAsync(stream, lifetimeCts.Token);
        await serverTask;

        Assert.Equal(413, response.StatusCode);
        Assert.Equal(string.Empty, response.BodyText);
    }

    [Fact]
    public async Task ServeAsync_stream_one_omits_sse_header_when_disabled()
    {
        using var lifetimeCts = new CancellationTokenSource(TimeSpan.FromSeconds(10));
        using var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();

        const string clientPayload = "plain-client";
        const string serverPayload = "plain-server";
        var bridge = new RuntimeSplitHttpInboundBridge(new RuntimeSplitHttpInboundOptions
        {
            Host = "edge.example.com",
            Path = "/xhttp/",
            Mode = "stream-one",
            NoSseHeader = true,
            XPaddingBytes = new RuntimeInt32Range
            {
                From = 1,
                To = 1
            }
        });

        using var client = new TcpClient { NoDelay = true };
        var acceptTask = listener.AcceptTcpClientAsync(lifetimeCts.Token).AsTask();
        await client.ConnectAsync(IPAddress.Loopback, ((IPEndPoint)listener.LocalEndpoint).Port, lifetimeCts.Token);
        using var serverClient = await acceptTask;

        var serverTask = Task.Run(async () =>
        {
            await using var serverStream = serverClient.GetStream();
            await bridge.ServeAsync(
                serverStream,
                async (applicationStream, token) =>
                {
                    var observed = await ReadTextToEndAsync(applicationStream, token);
                    Assert.Equal(clientPayload, observed);
                    await applicationStream.WriteAsync(Encoding.ASCII.GetBytes(serverPayload), token);
                },
                lifetimeCts.Token);
        }, lifetimeCts.Token);

        await using var clientStream = client.GetStream();
        await clientStream.WriteAsync(
            Encoding.ASCII.GetBytes(BuildChunkedRequest(
                "POST",
                "/xhttp/?x_padding=X",
                "edge.example.com",
                clientPayload,
                "Content-Type: application/grpc")),
            lifetimeCts.Token);
        await clientStream.FlushAsync(lifetimeCts.Token);

        var response = await ReadResponseAsync(clientStream, lifetimeCts.Token);
        await serverTask;

        Assert.Equal(200, response.StatusCode);
        Assert.False(response.Headers.ContainsKey("Content-Type"));
        Assert.Equal(serverPayload, response.BodyText);
    }

    [Fact]
    public async Task ServeAsync_rejects_request_headers_larger_than_server_limit()
    {
        using var lifetimeCts = new CancellationTokenSource(TimeSpan.FromSeconds(10));
        using var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();

        var bridge = new RuntimeSplitHttpInboundBridge(new RuntimeSplitHttpInboundOptions
        {
            Host = "edge.example.com",
            Path = "/xhttp/",
            Mode = "stream-one",
            XPaddingBytes = new RuntimeInt32Range
            {
                From = 1,
                To = 1
            },
            ServerMaxHeaderBytes = 48
        });
        var serverTask = AcceptAndServeAsync(
            listener,
            bridge,
            1,
            static (_, _) => Task.CompletedTask,
            lifetimeCts.Token);

        using var client = new TcpClient { NoDelay = true };
        await client.ConnectAsync(IPAddress.Loopback, ((IPEndPoint)listener.LocalEndpoint).Port, lifetimeCts.Token);

        await using var stream = client.GetStream();
        var oversizedHeader = new string('a', 64);
        var request = new StringBuilder()
            .Append("GET /xhttp/?x_padding=X HTTP/1.1\r\n")
            .Append("Host: edge.example.com\r\n")
            .Append("X-Overflow: ")
            .Append(oversizedHeader)
            .Append("\r\n\r\n")
            .ToString();

        await stream.WriteAsync(Encoding.ASCII.GetBytes(request), lifetimeCts.Token);
        await stream.FlushAsync(lifetimeCts.Token);

        var response = await ReadResponseAsync(stream, lifetimeCts.Token);
        await serverTask;

        Assert.Equal(431, response.StatusCode);
        Assert.Equal(string.Empty, response.BodyText);
    }

    [Fact]
    public async Task ServeAsync_stream_one_over_http2_exposes_duplex_stream()
    {
        using var lifetimeCts = new CancellationTokenSource(TimeSpan.FromSeconds(10));
        using var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();

        const string clientPayload = "stream-one-h2-client";
        const string serverPayload = "stream-one-h2-server";
        string? observedPayload = null;
        var bridge = new RuntimeSplitHttpInboundBridge(CreateOptions("stream-one"));
        var serverTask = AcceptAndServeAsync(
            listener,
            bridge,
            1,
            async (applicationStream, token) =>
            {
                observedPayload = await ReadExactTextAsync(applicationStream, clientPayload.Length, token);
                await applicationStream.WriteAsync(Encoding.ASCII.GetBytes(serverPayload), token);
            },
            lifetimeCts.Token);

        using var client = new TcpClient { NoDelay = true };
        await client.ConnectAsync(IPAddress.Loopback, ((IPEndPoint)listener.LocalEndpoint).Port, lifetimeCts.Token);
        await using var stream = client.GetStream();

        await stream.WriteAsync(
            Http2InitialPayloadTestBuilder.BuildRequestInitialPayload("POST", "/xhttp/?x_padding=X"),
            lifetimeCts.Token);
        await stream.WriteAsync(
            BuildHttp2Frame(
                Http2FrameTypes.Data,
                Http2FrameFlags.EndStream,
                streamId: 1,
                Encoding.ASCII.GetBytes(clientPayload)),
            lifetimeCts.Token);
        await stream.FlushAsync(lifetimeCts.Token);

        var pendingFrames = new List<Http2TestFrame>();
        var responseHeaders = await ReadHttp2HeadersAsync(stream, pendingFrames, streamId: 1, lifetimeCts.Token);
        var responseBody = await ReadHttp2DataTextAsync(stream, pendingFrames, streamId: 1, lifetimeCts.Token);
        client.Dispose();
        await serverTask;

        Assert.Equal(clientPayload, observedPayload);
        Assert.Equal("200", responseHeaders[":status"]);
        Assert.Equal("text/event-stream", responseHeaders["content-type"]);
        Assert.Equal("no", responseHeaders["x-accel-buffering"]);
        Assert.Equal("no-store", responseHeaders["cache-control"]);
        Assert.Equal("X", responseHeaders["x-padding"]);
        Assert.Equal(serverPayload, responseBody);
    }

    [Fact]
    public async Task ServeAsync_stream_one_over_http2_rejects_request_headers_larger_than_server_limit()
    {
        using var lifetimeCts = new CancellationTokenSource(TimeSpan.FromSeconds(10));
        using var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();

        var handlerInvoked = false;
        var bridge = new RuntimeSplitHttpInboundBridge(new RuntimeSplitHttpInboundOptions
        {
            Host = "edge.example.com",
            Path = "/xhttp/",
            Mode = "stream-one",
            XPaddingBytes = new RuntimeInt32Range
            {
                From = 1,
                To = 1
            },
            ServerMaxHeaderBytes = 128
        });
        var serverTask = AcceptAndServeAsync(
            listener,
            bridge,
            1,
            async (applicationStream, token) =>
            {
                handlerInvoked = true;
                await applicationStream.WriteAsync(Encoding.ASCII.GetBytes("unexpected"), token);
            },
            lifetimeCts.Token);

        using var client = new TcpClient { NoDelay = true };
        await client.ConnectAsync(IPAddress.Loopback, ((IPEndPoint)listener.LocalEndpoint).Port, lifetimeCts.Token);
        await using var stream = client.GetStream();

        await stream.WriteAsync(Http2InitialPayloadTestBuilder.BuildPrefaceOnly(), lifetimeCts.Token);
        await stream.WriteAsync(
            BuildHttp2Frame(Http2FrameTypes.Settings, Http2FrameFlags.None, streamId: 0, Array.Empty<byte>()),
            lifetimeCts.Token);
        await stream.WriteAsync(
            BuildHttp2Frame(
                Http2FrameTypes.Headers,
                Http2FrameFlags.EndHeaders | Http2FrameFlags.EndStream,
                streamId: 1,
                BuildHttp2RequestHeaderBlock(
                    "GET",
                    "/xhttp/?x_padding=X",
                    extraHeaders: new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
                    {
                        ["x-overflow"] = new string('a', 160)
                    })),
            lifetimeCts.Token);
        await stream.FlushAsync(lifetimeCts.Token);

        var pendingFrames = new List<Http2TestFrame>();
        var responseHeaders = await ReadHttp2HeadersAsync(stream, pendingFrames, streamId: 1, lifetimeCts.Token);
        client.Dispose();
        await serverTask;

        Assert.Equal("431", responseHeaders[":status"]);
        Assert.False(handlerInvoked);
    }

    [Fact]
    public async Task ServeHttp3Async_stream_one_exposes_duplex_stream()
    {
        if (!QuicConnection.IsSupported || !QuicListener.IsSupported)
        {
            return;
        }

        using var lifetimeCts = new CancellationTokenSource(TimeSpan.FromSeconds(15));
        using var certificate = TestCertificateFactory.CreateSelfSignedServerCertificate("localhost", ["localhost"]);

        const string clientPayload = "stream-one-h3-client";
        const string serverPayload = "stream-one-h3-server";
        string? observedPayload = null;
        var bridge = new RuntimeSplitHttpInboundBridge(CreateOptions("stream-one"));

        try
        {
            await using var listener = await CreateQuicListenerAsync(certificate, lifetimeCts.Token);
            var serverTask = AcceptAndServeHttp3Async(
                listener,
                bridge,
                async (applicationStream, token) =>
                {
                    observedPayload = await ReadExactTextAsync(applicationStream, clientPayload.Length, token);
                    await applicationStream.WriteAsync(Encoding.ASCII.GetBytes(serverPayload), token);
                },
                lifetimeCts.Token);

            await using var clientSession = await CreateHttp3ClientSessionAsync(listener.LocalEndPoint, lifetimeCts.Token);
            await using var pendingRequest = await clientSession.StartHttpRequestAsync(
                "POST",
                "edge.example.com",
                "https",
                "/xhttp/?x_padding=X",
                new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
                {
                    ["content-type"] = "application/grpc"
                },
                Encoding.ASCII.GetBytes(clientPayload),
                lifetimeCts.Token,
                completeRequestAfterInitialPayload: true);

            await pendingRequest.WaitForSuccessfulStatusAsync(lifetimeCts.Token);
            await using var responseStream = pendingRequest.DetachResponseStream();
            var responseText = await ReadExactTextAsync(responseStream, serverPayload.Length, lifetimeCts.Token);
            Assert.Equal(0, await responseStream.ReadAsync(new byte[1], lifetimeCts.Token));

            await serverTask;

            Assert.Equal(clientPayload, observedPayload);
            Assert.Equal(serverPayload, responseText);
        }
        catch (Exception ex) when (IsKnownLocalQuicCredentialLoadFailure(ex))
        {
            return;
        }
    }

    [Fact]
    public async Task ServeHttp3Async_rejects_request_headers_larger_than_server_limit()
    {
        if (!QuicConnection.IsSupported || !QuicListener.IsSupported)
        {
            return;
        }

        using var lifetimeCts = new CancellationTokenSource(TimeSpan.FromSeconds(15));
        using var certificate = TestCertificateFactory.CreateSelfSignedServerCertificate("localhost", ["localhost"]);

        var handlerInvoked = false;
        var bridge = new RuntimeSplitHttpInboundBridge(new RuntimeSplitHttpInboundOptions
        {
            Host = "edge.example.com",
            Path = "/xhttp/",
            Mode = "stream-one",
            XPaddingBytes = new RuntimeInt32Range
            {
                From = 1,
                To = 1
            },
            ServerMaxHeaderBytes = 128
        });

        try
        {
            await using var listener = await CreateQuicListenerAsync(certificate, lifetimeCts.Token);
            var serverTask = AcceptAndServeHttp3Async(
                listener,
                bridge,
                async (applicationStream, token) =>
                {
                    handlerInvoked = true;
                    await applicationStream.WriteAsync(Encoding.ASCII.GetBytes("unexpected"), token);
                },
                lifetimeCts.Token);

            await using var clientSession = await CreateHttp3ClientSessionAsync(listener.LocalEndPoint, lifetimeCts.Token);
            await using var pendingRequest = await clientSession.StartHttpRequestAsync(
                "GET",
                "edge.example.com",
                "https",
                "/xhttp/?x_padding=X",
                new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
                {
                    ["x-overflow"] = new string('a', 160)
                },
                Array.Empty<byte>(),
                lifetimeCts.Token,
                endRequestOnHeaders: true);

            var exception = await Assert.ThrowsAsync<IOException>(
                () => pendingRequest.WaitForSuccessfulStatusAsync(lifetimeCts.Token).AsTask());
            await clientSession.DisposeAsync();
            var serverException = await Record.ExceptionAsync(() => serverTask);

            Assert.Contains("431", exception.Message, StringComparison.Ordinal);
            Assert.True(
                serverException is null or QuicException,
                serverException?.ToString());
            Assert.False(handlerInvoked);
        }
        catch (Exception ex) when (IsKnownLocalQuicCredentialLoadFailure(ex))
        {
            return;
        }
    }

    [Fact]
    public async Task ServeAsync_packet_up_over_http2_shares_session_between_get_and_post_streams()
    {
        using var lifetimeCts = new CancellationTokenSource(TimeSpan.FromSeconds(10));
        using var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();

        const string sessionId = "session-h2-1";
        const string clientPayload = "packet-h2-client";
        const string serverPayload = "packet-h2-server";
        string? observedPayload = null;
        var bridge = new RuntimeSplitHttpInboundBridge(CreateOptions("packet-up"));
        var serverTask = AcceptAndServeAsync(
            listener,
            bridge,
            1,
            async (applicationStream, token) =>
            {
                observedPayload = await ReadExactTextAsync(applicationStream, clientPayload.Length, token);
                await applicationStream.WriteAsync(Encoding.ASCII.GetBytes(serverPayload), token);
            },
            lifetimeCts.Token);

        using var client = new TcpClient { NoDelay = true };
        await client.ConnectAsync(IPAddress.Loopback, ((IPEndPoint)listener.LocalEndpoint).Port, lifetimeCts.Token);
        await using var stream = client.GetStream();

        await stream.WriteAsync(
            Http2InitialPayloadTestBuilder.BuildRequestInitialPayload("GET", $"/xhttp/{sessionId}?x_padding=X"),
            lifetimeCts.Token);
        await stream.FlushAsync(lifetimeCts.Token);

        var pendingFrames = new List<Http2TestFrame>();
        var downlinkHeaders = await ReadHttp2HeadersAsync(stream, pendingFrames, streamId: 1, lifetimeCts.Token);

        await stream.WriteAsync(
            BuildHttp2Frame(
                Http2FrameTypes.Headers,
                Http2FrameFlags.EndHeaders,
                streamId: 3,
                BuildHttp2RequestHeaderBlock("POST", $"/xhttp/{sessionId}/0?x_padding=X")),
            lifetimeCts.Token);
        await stream.WriteAsync(
            BuildHttp2Frame(
                Http2FrameTypes.Data,
                Http2FrameFlags.EndStream,
                streamId: 3,
                Encoding.ASCII.GetBytes(clientPayload)),
            lifetimeCts.Token);
        await stream.FlushAsync(lifetimeCts.Token);

        var uploadHeaders = await ReadHttp2HeadersAsync(stream, pendingFrames, streamId: 3, lifetimeCts.Token);
        var downlinkBody = await ReadHttp2DataTextAsync(stream, pendingFrames, streamId: 1, lifetimeCts.Token);
        client.Dispose();
        await serverTask;

        Assert.Equal(clientPayload, observedPayload);
        Assert.Equal("200", downlinkHeaders[":status"]);
        Assert.Equal("200", uploadHeaders[":status"]);
        Assert.Equal("no", downlinkHeaders["x-accel-buffering"]);
        Assert.Equal("no-store", downlinkHeaders["cache-control"]);
        Assert.Equal(serverPayload, downlinkBody);
    }

    private static RuntimeSplitHttpInboundOptions CreateOptions(string mode)
        => new()
        {
            Host = "edge.example.com",
            Path = "/xhttp/",
            Mode = mode,
            XPaddingBytes = new RuntimeInt32Range
            {
                From = 1,
                To = 1
            }
        };

    private static async Task AcceptAndServeHttp3Async(
        QuicListener listener,
        RuntimeSplitHttpInboundBridge bridge,
        Func<Stream, CancellationToken, Task> handler,
        CancellationToken cancellationToken)
    {
        var connection = await listener.AcceptConnectionAsync(cancellationToken);
        await bridge.ServeHttp3Async(connection, handler, cancellationToken);
    }

    private static async Task AcceptAndServeAsync(
        TcpListener listener,
        RuntimeSplitHttpInboundBridge bridge,
        int connectionCount,
        Func<Stream, CancellationToken, Task> handler,
        CancellationToken cancellationToken)
    {
        var tasks = new List<Task>(connectionCount);
        for (var index = 0; index < connectionCount; index++)
        {
            var accepted = await listener.AcceptTcpClientAsync(cancellationToken);
            tasks.Add(Task.Run(async () =>
            {
                using var connection = accepted;
                await using var stream = connection.GetStream();
                await bridge.ServeAsync(stream, handler, cancellationToken);
            }, cancellationToken));
        }

        await Task.WhenAll(tasks);
    }

    private static async Task<QuicListener> CreateQuicListenerAsync(
        X509Certificate2 certificate,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(certificate);

        return await QuicListener.ListenAsync(
            new QuicListenerOptions
            {
                ListenEndPoint = new IPEndPoint(IPAddress.Loopback, 0),
                ApplicationProtocols = [SslApplicationProtocol.Http3],
                ConnectionOptionsCallback = (_, _, _) => ValueTask.FromResult(
                    new QuicServerConnectionOptions
                    {
                        DefaultCloseErrorCode = 0,
                        DefaultStreamErrorCode = 0,
                        HandshakeTimeout = TimeSpan.FromSeconds(10),
                        IdleTimeout = TimeSpan.FromSeconds(30),
                        MaxInboundBidirectionalStreams = 64,
                        MaxInboundUnidirectionalStreams = 16,
                        ServerAuthenticationOptions = new SslServerAuthenticationOptions
                        {
                            ApplicationProtocols = [SslApplicationProtocol.Http3],
                            EnabledSslProtocols = SslProtocols.Tls13,
                            ServerCertificate = certificate
                        }
                    })
            },
            cancellationToken);
    }

    private static async Task<RuntimeHttp3ClientSession> CreateHttp3ClientSessionAsync(
        IPEndPoint remoteEndPoint,
        CancellationToken cancellationToken)
    {
        var connection = await QuicConnection.ConnectAsync(
            new QuicClientConnectionOptions
            {
                RemoteEndPoint = remoteEndPoint,
                ClientAuthenticationOptions = new SslClientAuthenticationOptions
                {
                    TargetHost = "localhost",
                    ApplicationProtocols = [SslApplicationProtocol.Http3],
                    EnabledSslProtocols = SslProtocols.Tls13,
                    RemoteCertificateValidationCallback = static (_, _, _, _) => true
                },
                DefaultCloseErrorCode = 0,
                DefaultStreamErrorCode = 0,
                HandshakeTimeout = TimeSpan.FromSeconds(10),
                IdleTimeout = TimeSpan.FromSeconds(30),
                KeepAliveInterval = TimeSpan.FromSeconds(5),
                MaxInboundBidirectionalStreams = 0,
                MaxInboundUnidirectionalStreams = 16
            },
            cancellationToken);

        return await RuntimeHttp3ClientSession.CreateAsync(
            new RuntimeQuicClientConnection(connection),
            cancellationToken);
    }

    private static string BuildGetRequest(string target, string host)
        => $"GET {target} HTTP/1.1\r\nHost: {host}\r\n\r\n";

    private static string BuildChunkedRequest(
        string method,
        string target,
        string host,
        string payload,
        params string[] extraHeaders)
    {
        var builder = new StringBuilder();
        builder.Append(method);
        builder.Append(' ');
        builder.Append(target);
        builder.Append(" HTTP/1.1\r\nHost: ");
        builder.Append(host);
        builder.Append("\r\nTransfer-Encoding: chunked\r\n");
        foreach (var header in extraHeaders)
        {
            builder.Append(header);
            builder.Append("\r\n");
        }

        builder.Append("\r\n");
        builder.Append(payload.Length.ToString("X"));
        builder.Append("\r\n");
        builder.Append(payload);
        builder.Append("\r\n0\r\n\r\n");
        return builder.ToString();
    }

    private static string BuildHeaderPayloadRequest(string target, string host, string payload)
        => $"POST {target} HTTP/1.1\r\nHost: {host}\r\nContent-Length: 0\r\nX-Data-0: {EncodeBase64Url(payload)}\r\n\r\n";

    private static string BuildCookiePayloadRequest(string target, string host, string payload)
        => $"POST {target} HTTP/1.1\r\nHost: {host}\r\nContent-Length: 0\r\nCookie: x_data_0={EncodeBase64Url(payload)}\r\n\r\n";

    private static async Task<string> ReadTextToEndAsync(Stream stream, CancellationToken cancellationToken)
    {
        using var buffer = new MemoryStream();
        var rented = new byte[256];
        while (true)
        {
            var read = await stream.ReadAsync(rented.AsMemory(), cancellationToken);
            if (read == 0)
            {
                break;
            }

            buffer.Write(rented, 0, read);
        }

        return Encoding.ASCII.GetString(buffer.ToArray());
    }

    private static async Task<string> ReadExactTextAsync(Stream stream, int length, CancellationToken cancellationToken)
    {
        var buffer = new byte[length];
        await ReadExactAsync(stream, buffer, cancellationToken);
        return Encoding.ASCII.GetString(buffer);
    }

    private static async Task<(int StatusCode, Dictionary<string, string> Headers, string BodyText)> ReadResponseAsync(
        Stream stream,
        CancellationToken cancellationToken)
    {
        var (statusCode, headers) = await ReadResponseHeadersOnlyAsync(stream, cancellationToken);

        var bodyText = headers.TryGetValue("Transfer-Encoding", out var transferEncoding) &&
                       transferEncoding.Contains("chunked", StringComparison.OrdinalIgnoreCase)
            ? await ReadChunkedBodyTextAsync(stream, cancellationToken)
            : string.Empty;
        return (statusCode, headers, bodyText);
    }

    private static async Task<(int StatusCode, Dictionary<string, string> Headers)> ReadResponseHeadersOnlyAsync(
        Stream stream,
        CancellationToken cancellationToken)
    {
        var statusLine = await RuntimeInternetHttpUtilities
            .ReadHttpLineAsync(stream, "Unexpected EOF while reading SplitHTTP response status line.", cancellationToken);
        var statusCode = int.Parse(statusLine.Split(' ', StringSplitOptions.RemoveEmptyEntries)[1]);

        var headers = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        while (true)
        {
            var line = await RuntimeInternetHttpUtilities
                .ReadHttpLineAsync(stream, "Unexpected EOF while reading SplitHTTP response headers.", cancellationToken);
            if (line.Length == 0)
            {
                break;
            }

            var separator = line.IndexOf(':');
            if (separator <= 0)
            {
                continue;
            }

            headers[line[..separator].Trim()] = line[(separator + 1)..].Trim();
        }

        return (statusCode, headers);
    }

    private static async Task<string> ReadChunkedBodyTextAsync(Stream stream, CancellationToken cancellationToken)
    {
        using var buffer = new MemoryStream();
        while (true)
        {
            var chunkHeader = await RuntimeInternetHttpUtilities
                .ReadHttpLineAsync(stream, "Unexpected EOF while reading SplitHTTP response chunk header.", cancellationToken);
            var sizeText = chunkHeader.Split(';', 2)[0];
            var chunkLength = Convert.ToInt32(sizeText, 16);
            if (chunkLength == 0)
            {
                while (true)
                {
                    var trailerLine = await RuntimeInternetHttpUtilities
                        .ReadHttpLineAsync(stream, "Unexpected EOF while reading SplitHTTP response trailers.", cancellationToken);
                    if (trailerLine.Length == 0)
                    {
                        break;
                    }
                }

                break;
            }

            var payload = new byte[chunkLength];
            await ReadExactAsync(stream, payload, cancellationToken);
            buffer.Write(payload, 0, payload.Length);

            var crlf = new byte[2];
            await ReadExactAsync(stream, crlf, cancellationToken);
        }

        return Encoding.ASCII.GetString(buffer.ToArray());
    }

    private static bool IsKnownLocalQuicCredentialLoadFailure(Exception exception)
    {
        for (var current = exception; current is not null; current = current.InnerException)
        {
            if (current.Message.Contains("QUIC_STATUS_CERT_NO_CERT", StringComparison.OrdinalIgnoreCase))
            {
                return true;
            }
        }

        return false;
    }

    private static byte[] BuildHttp2Frame(byte type, Http2FrameFlags flags, int streamId, byte[] payload)
    {
        using var buffer = new MemoryStream(payload.Length + 9);
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
        buffer.Write(header, 0, header.Length);
        if (payload.Length > 0)
        {
            buffer.Write(payload, 0, payload.Length);
        }

        return buffer.ToArray();
    }

    private static byte[] BuildHttp2RequestHeaderBlock(
        string method,
        string path,
        string authority = "edge.example.com",
        string scheme = "https",
        IReadOnlyDictionary<string, string>? extraHeaders = null)
    {
        using var buffer = new MemoryStream(128);
        WriteLiteralHeaderFieldWithoutIndexing(buffer, nameIndex: 2, name: null, value: method.Trim().ToUpperInvariant());
        WriteLiteralHeaderFieldWithoutIndexing(buffer, nameIndex: 1, name: null, value: authority);
        WriteLiteralHeaderFieldWithoutIndexing(buffer, nameIndex: 6, name: null, value: scheme);
        WriteLiteralHeaderFieldWithoutIndexing(buffer, nameIndex: 4, name: null, value: path);
        if (extraHeaders is not null)
        {
            foreach (var header in extraHeaders)
            {
                WriteLiteralHeaderFieldWithoutIndexing(buffer, nameIndex: 0, name: header.Key, value: header.Value);
            }
        }

        return buffer.ToArray();
    }

    private static async Task<Dictionary<string, string>> ReadHttp2HeadersAsync(
        Stream stream,
        List<Http2TestFrame> pendingFrames,
        int streamId,
        CancellationToken cancellationToken)
    {
        while (true)
        {
            var frame = await ReadNextHttp2FrameForStreamAsync(stream, pendingFrames, streamId, cancellationToken);
            if (frame.Type == Http2FrameTypes.Headers)
            {
                return DecodeHttp2HeaderBlock(frame.Payload);
            }
        }
    }

    private static async Task<string> ReadHttp2DataTextAsync(
        Stream stream,
        List<Http2TestFrame> pendingFrames,
        int streamId,
        CancellationToken cancellationToken)
    {
        using var buffer = new MemoryStream();
        while (true)
        {
            var frame = await ReadNextHttp2FrameForStreamAsync(stream, pendingFrames, streamId, cancellationToken);

            if (frame.Type == Http2FrameTypes.Headers &&
                (frame.Flags & Http2FrameFlags.EndStream) == Http2FrameFlags.EndStream)
            {
                return string.Empty;
            }

            if (frame.Type != Http2FrameTypes.Data)
            {
                continue;
            }

            if (frame.Payload.Length > 0)
            {
                buffer.Write(frame.Payload, 0, frame.Payload.Length);
            }

            if ((frame.Flags & Http2FrameFlags.EndStream) == Http2FrameFlags.EndStream)
            {
                return Encoding.ASCII.GetString(buffer.ToArray());
            }
        }
    }

    private static async Task<Http2TestFrame> ReadNextHttp2FrameForStreamAsync(
        Stream stream,
        List<Http2TestFrame> pendingFrames,
        int streamId,
        CancellationToken cancellationToken)
    {
        while (true)
        {
            for (var index = 0; index < pendingFrames.Count; index++)
            {
                if (pendingFrames[index].StreamId != streamId)
                {
                    continue;
                }

                var frame = pendingFrames[index];
                pendingFrames.RemoveAt(index);
                return frame;
            }

            var nextFrame = await ReadHttp2FrameAsync(stream, cancellationToken);
            if (nextFrame.Type == Http2FrameTypes.Settings &&
                (nextFrame.Flags & Http2FrameFlags.Ack) == 0)
            {
                await stream.WriteAsync(
                    BuildHttp2Frame(Http2FrameTypes.Settings, Http2FrameFlags.Ack, streamId: 0, Array.Empty<byte>()),
                    cancellationToken);
                await stream.FlushAsync(cancellationToken);
                continue;
            }

            if (nextFrame.StreamId == streamId)
            {
                return nextFrame;
            }

            pendingFrames.Add(nextFrame);
        }
    }

    private static async Task<Http2TestFrame> ReadHttp2FrameAsync(Stream stream, CancellationToken cancellationToken)
    {
        var header = new byte[9];
        await ReadExactAsync(stream, header, cancellationToken);

        var length = (header[0] << 16) | (header[1] << 8) | header[2];
        var payload = new byte[length];
        if (length > 0)
        {
            await ReadExactAsync(stream, payload, cancellationToken);
        }

        return new Http2TestFrame(
            header[3],
            (Http2FrameFlags)header[4],
            ((header[5] & 0x7F) << 24) |
            (header[6] << 16) |
            (header[7] << 8) |
            header[8],
            payload);
    }

    private static Dictionary<string, string> DecodeHttp2HeaderBlock(byte[] headerBlock)
    {
        var headers = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        var offset = 0;

        while (offset < headerBlock.Length)
        {
            var first = headerBlock[offset];
            if ((first & 0x80) != 0)
            {
                var index = ReadHpackInteger(headerBlock, ref offset, 7);
                if (TryResolveIndexedHttp2Header(index, out var indexedName, out var indexedValue))
                {
                    headers[indexedName] = indexedValue;
                }

                continue;
            }

            if ((first & 0xE0) == 0x20)
            {
                _ = ReadHpackInteger(headerBlock, ref offset, 5);
                continue;
            }

            var nameIndex = ReadHpackInteger(headerBlock, ref offset, (first & 0x40) != 0 ? 6 : 4);
            var name = nameIndex == 0
                ? ReadHpackString(headerBlock, ref offset)
                : ResolveIndexedHttp2HeaderName(nameIndex);
            var value = ReadHpackString(headerBlock, ref offset);
            if (!string.IsNullOrWhiteSpace(name))
            {
                headers[name] = value;
            }
        }

        return headers;
    }

    private static async Task ReadExactAsync(Stream stream, byte[] buffer, CancellationToken cancellationToken)
    {
        var read = 0;
        while (read < buffer.Length)
        {
            var current = await stream.ReadAsync(buffer.AsMemory(read, buffer.Length - read), cancellationToken);
            if (current == 0)
            {
                throw new EndOfStreamException("Unexpected EOF while reading SplitHTTP test payload.");
            }

            read += current;
        }
    }

    private static bool TryResolveIndexedHttp2Header(
        int index,
        out string name,
        out string value)
    {
        switch (index)
        {
            case 1: name = ":authority"; value = string.Empty; return true;
            case 2: name = ":method"; value = "GET"; return true;
            case 3: name = ":method"; value = "POST"; return true;
            case 4: name = ":path"; value = "/"; return true;
            case 5: name = ":path"; value = "/index.html"; return true;
            case 6: name = ":scheme"; value = "http"; return true;
            case 7: name = ":scheme"; value = "https"; return true;
            case 8: name = ":status"; value = "200"; return true;
            case 9: name = ":status"; value = "204"; return true;
            case 10: name = ":status"; value = "206"; return true;
            case 11: name = ":status"; value = "304"; return true;
            case 12: name = ":status"; value = "400"; return true;
            case 13: name = ":status"; value = "404"; return true;
            case 14: name = ":status"; value = "500"; return true;
            default:
                name = string.Empty;
                value = string.Empty;
                return false;
        }
    }

    private static string ResolveIndexedHttp2HeaderName(int index)
        => index switch
        {
            1 => ":authority",
            2 or 3 => ":method",
            4 or 5 => ":path",
            6 or 7 => ":scheme",
            8 or 9 or 10 or 11 or 12 or 13 or 14 => ":status",
            15 => "accept-charset",
            16 => "accept-encoding",
            17 => "accept-language",
            18 => "accept-ranges",
            19 => "accept",
            20 => "access-control-allow-origin",
            21 => "age",
            22 => "allow",
            23 => "authorization",
            24 => "cache-control",
            25 => "content-disposition",
            26 => "content-encoding",
            27 => "content-language",
            28 => "content-length",
            29 => "content-location",
            30 => "content-range",
            31 => "content-type",
            32 => "cookie",
            33 => "date",
            34 => "etag",
            35 => "expect",
            36 => "expires",
            37 => "from",
            38 => "host",
            39 => "if-match",
            40 => "if-modified-since",
            41 => "if-none-match",
            42 => "if-range",
            43 => "if-unmodified-since",
            44 => "last-modified",
            45 => "link",
            46 => "location",
            47 => "max-forwards",
            48 => "proxy-authenticate",
            49 => "proxy-authorization",
            50 => "range",
            51 => "referer",
            52 => "refresh",
            53 => "retry-after",
            54 => "server",
            55 => "set-cookie",
            56 => "strict-transport-security",
            57 => "transfer-encoding",
            58 => "user-agent",
            59 => "vary",
            60 => "via",
            61 => "www-authenticate",
            _ => string.Empty
        };

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
        var length = ReadHpackInteger(buffer, ref offset, 7);
        var value = huffmanEncoded
            ? RuntimeHpackHuffman.DecodeToUtf8String(buffer.AsSpan(offset, length))
            : Encoding.UTF8.GetString(buffer, offset, length);
        offset += length;
        return value;
    }

    private static void WriteLiteralHeaderFieldWithoutIndexing(
        MemoryStream buffer,
        int nameIndex,
        string? name,
        string value)
    {
        WriteInteger(buffer, nameIndex, prefixBits: 4, prefixMask: 0x00);
        if (nameIndex == 0)
        {
            WriteString(buffer, name ?? string.Empty);
        }

        WriteString(buffer, value);
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

    private static void WriteString(MemoryStream buffer, string value)
    {
        var bytes = Encoding.UTF8.GetBytes(value);
        WriteInteger(buffer, bytes.Length, prefixBits: 7, prefixMask: 0x00);
        buffer.Write(bytes, 0, bytes.Length);
    }

    private static string EncodeBase64Url(string value)
        => Convert
            .ToBase64String(Encoding.ASCII.GetBytes(value))
            .TrimEnd('=')
            .Replace('+', '-')
            .Replace('/', '_');

    [Flags]
    private enum Http2FrameFlags : byte
    {
        None = 0,
        Ack = 0x1,
        EndStream = 0x1,
        EndHeaders = 0x4
    }

    private static class Http2FrameTypes
    {
        public const byte Data = 0x0;
        public const byte Headers = 0x1;
        public const byte Settings = 0x4;
    }

    private readonly record struct Http2TestFrame(
        byte Type,
        Http2FrameFlags Flags,
        int StreamId,
        byte[] Payload);
}

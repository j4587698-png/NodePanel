using System.Collections.Concurrent;
using System.Net;
using System.Net.Quic;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Authentication;
using System.Text;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Server.Kestrel.Core;
using Microsoft.Extensions.Logging;
using NodePanel.Core.Runtime;

namespace NodePanel.Core.Tests;

[CollectionDefinition(RuntimeSplitHttpTransportTestCollection.CollectionName, DisableParallelization = true)]
public sealed class RuntimeSplitHttpTransportTestCollection
{
    public const string CollectionName = nameof(RuntimeSplitHttpTransportTests);
}

[Collection(RuntimeSplitHttpTransportTestCollection.CollectionName)]
public sealed class RuntimeSplitHttpTransportTests
{
    private static readonly TimeSpan Http2TestDrainDelay = TimeSpan.FromMilliseconds(500);
    private static int s_nextReservedTcpPort = 40000 + Random.Shared.Next(10000);

    [Fact]
    public async Task OpenAsync_sends_expected_path_session_requests_and_relays_duplex_payloads()
    {
        using var lifetimeCts = new CancellationTokenSource(TimeSpan.FromSeconds(10));
        using var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();

        const string clientPayload = "client-hunk";
        const string serverPayload = "server-hunk";
        var port = ((IPEndPoint)listener.LocalEndpoint).Port;
        var serverTask = CaptureSplitHttpExchangeAsync(
            listener,
            clientPayload,
            serverPayload,
            downlinkBodyMode: SplitHttpDownlinkBodyMode.Chunked,
            lifetimeCts.Token);
        var tlsSecurityFactory = new TestRuntimeInternetProfileFactory.RecordingFakeTlsSecurityFactory("http/1.1");
        var profile = TestRuntimeInternetProfileFactory.CreateWithFakeTls(tlsSecurityFactory);

        var context = await RuntimeGrpcClientConnector.OpenAsync(
            new TestSplitHttpInternetOptions
            {
                ServerHost = "127.0.0.1",
                ServerPort = port,
                ServerName = "edge.example.com",
                SecurityType = RuntimeInternetSecurityTypes.Tls,
                SplitHttpHost = "cdn.example.com",
                SplitHttpPath = " tunnel?route=1 ",
                SplitHttpHeaders = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
                {
                    ["X-Test"] = "alpha"
                },
                SplitHttpMode = "stream-up",
                SplitHttpNoGrpcHeader = true,
                ApplicationProtocols = ["http/1.1"]
            },
            RuntimeInternetStack.Create(RuntimeInternetTransportProtocols.SplitHttp, RuntimeInternetSecurityTypes.Tls),
            profile,
            SystemDnsResolver.Instance,
            transportInitializationData: null,
            lifetimeCts.Token);

        await using var applicationStream = context.ApplicationStream;
        await applicationStream.WriteAsync(Encoding.ASCII.GetBytes(clientPayload), lifetimeCts.Token);
        await applicationStream.FlushAsync(lifetimeCts.Token);

        var responseBuffer = new byte[serverPayload.Length];
        await ReadExactAsync(applicationStream, responseBuffer, lifetimeCts.Token);
        Assert.Equal(serverPayload, Encoding.ASCII.GetString(responseBuffer));

        var eofBuffer = new byte[1];
        var eofRead = await applicationStream.ReadAsync(eofBuffer, lifetimeCts.Token);
        Assert.Equal(0, eofRead);

        var captured = await serverTask;
        Assert.Equal("GET", captured.DownlinkRequest.Method);
        Assert.Equal("POST", captured.UplinkRequest.Method);
        Assert.Equal("cdn.example.com", captured.DownlinkRequest.Headers["Host"]);
        Assert.Equal("cdn.example.com", captured.UplinkRequest.Headers["Host"]);
        Assert.Equal("alpha", captured.DownlinkRequest.Headers["X-Test"]);
        Assert.Equal("alpha", captured.UplinkRequest.Headers["X-Test"]);
        Assert.Equal("chunked", captured.UplinkRequest.Headers["Transfer-Encoding"]);
        Assert.False(captured.UplinkRequest.Headers.ContainsKey("Content-Type"));
        Assert.Equal(clientPayload, captured.UplinkPayloadText);
        Assert.Equal(["http/1.1"], tlsSecurityFactory.ObservedApplicationProtocols);
        Assert.Equal("http/1.1", tlsSecurityFactory.NegotiatedApplicationProtocol);

        var downlinkTarget = new Uri("http://split.local" + captured.DownlinkRequest.Target);
        var uplinkTarget = new Uri("http://split.local" + captured.UplinkRequest.Target);
        Assert.Equal("route=1", downlinkTarget.Query.TrimStart('?'));
        Assert.Equal("route=1", uplinkTarget.Query.TrimStart('?'));

        var downlinkSegments = downlinkTarget.AbsolutePath.Split('/', StringSplitOptions.RemoveEmptyEntries);
        var uplinkSegments = uplinkTarget.AbsolutePath.Split('/', StringSplitOptions.RemoveEmptyEntries);
        Assert.Equal(["tunnel", Uri.UnescapeDataString(downlinkSegments[1])], downlinkSegments);
        Assert.Equal(["tunnel", Uri.UnescapeDataString(uplinkSegments[1])], uplinkSegments);
        Assert.True(Guid.TryParse(Uri.UnescapeDataString(downlinkSegments[1]), out _));
        Assert.Equal(
            Uri.UnescapeDataString(downlinkSegments[1]),
            Uri.UnescapeDataString(uplinkSegments[1]));
    }

    [Fact]
    public async Task OpenAsync_places_session_in_headers_and_supports_content_length_downlink()
    {
        using var lifetimeCts = new CancellationTokenSource(TimeSpan.FromSeconds(10));
        using var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();

        const string clientPayload = "header-client";
        const string serverPayload = "header-response";
        var port = ((IPEndPoint)listener.LocalEndpoint).Port;
        var serverTask = CaptureSplitHttpExchangeAsync(
            listener,
            clientPayload,
            serverPayload,
            downlinkBodyMode: SplitHttpDownlinkBodyMode.ContentLength,
            lifetimeCts.Token);
        var profile = RuntimeInternetProfile.FromDefault();

        var context = await RuntimeGrpcClientConnector.OpenAsync(
            new TestSplitHttpInternetOptions
            {
                ServerHost = "127.0.0.1",
                ServerPort = port,
                SecurityType = RuntimeInternetSecurityTypes.None,
                SplitHttpPath = " header?x=1 ",
                SplitHttpHeaders = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
                {
                    ["X-Trace"] = "1"
                },
                SplitHttpMode = "stream-up",
                SplitHttpSessionPlacement = "header",
                SplitHttpSessionKey = "X-Custom-Session"
            },
            RuntimeInternetStack.Create(RuntimeInternetTransportProtocols.SplitHttp, RuntimeInternetSecurityTypes.None),
            profile,
            SystemDnsResolver.Instance,
            transportInitializationData: null,
            lifetimeCts.Token);

        await using var applicationStream = context.ApplicationStream;
        await applicationStream.WriteAsync(Encoding.ASCII.GetBytes(clientPayload), lifetimeCts.Token);
        await applicationStream.FlushAsync(lifetimeCts.Token);

        var responseBuffer = new byte[serverPayload.Length];
        await ReadExactAsync(applicationStream, responseBuffer, lifetimeCts.Token);
        Assert.Equal(serverPayload, Encoding.ASCII.GetString(responseBuffer));

        var eofBuffer = new byte[1];
        var eofRead = await applicationStream.ReadAsync(eofBuffer, lifetimeCts.Token);
        Assert.Equal(0, eofRead);

        var captured = await serverTask;
        Assert.Equal("/header/?x=1", captured.DownlinkRequest.Target);
        Assert.Equal("/header/?x=1", captured.UplinkRequest.Target);
        Assert.Equal("127.0.0.1", captured.DownlinkRequest.Headers["Host"]);
        Assert.Equal("127.0.0.1", captured.UplinkRequest.Headers["Host"]);
        Assert.Equal("1", captured.DownlinkRequest.Headers["X-Trace"]);
        Assert.Equal("1", captured.UplinkRequest.Headers["X-Trace"]);
        Assert.Equal("application/grpc", captured.UplinkRequest.Headers["Content-Type"]);
        Assert.Equal(clientPayload, captured.UplinkPayloadText);

        var sessionId = captured.DownlinkRequest.Headers["X-Custom-Session"];
        Assert.True(Guid.TryParse(sessionId, out _));
        Assert.Equal(sessionId, captured.UplinkRequest.Headers["X-Custom-Session"]);
    }

    [Fact]
    public async Task OpenAsync_stream_up_over_http11_accepts_custom_uplink_method()
    {
        using var lifetimeCts = new CancellationTokenSource(TimeSpan.FromSeconds(10));
        using var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();

        const string clientPayload = "custom-method-client";
        const string serverPayload = "custom-method-server";
        var port = ((IPEndPoint)listener.LocalEndpoint).Port;
        var serverTask = CaptureSplitHttpExchangeAsync(
            listener,
            clientPayload,
            serverPayload,
            downlinkBodyMode: SplitHttpDownlinkBodyMode.Chunked,
            lifetimeCts.Token);
        var profile = RuntimeInternetProfile.FromDefault();

        var context = await RuntimeGrpcClientConnector.OpenAsync(
            new TestSplitHttpInternetOptions
            {
                ServerHost = "127.0.0.1",
                ServerPort = port,
                SecurityType = RuntimeInternetSecurityTypes.None,
                SplitHttpPath = " custom-method?route=1 ",
                SplitHttpMode = "stream-up",
                SplitHttpUplinkHttpMethod = " put "
            },
            RuntimeInternetStack.Create(RuntimeInternetTransportProtocols.SplitHttp, RuntimeInternetSecurityTypes.None),
            profile,
            SystemDnsResolver.Instance,
            transportInitializationData: null,
            lifetimeCts.Token);

        await using var applicationStream = context.ApplicationStream;
        await applicationStream.WriteAsync(Encoding.ASCII.GetBytes(clientPayload), lifetimeCts.Token);
        await applicationStream.FlushAsync(lifetimeCts.Token);

        var responseBuffer = new byte[serverPayload.Length];
        await ReadExactAsync(applicationStream, responseBuffer, lifetimeCts.Token);
        Assert.Equal(serverPayload, Encoding.ASCII.GetString(responseBuffer));

        var eofBuffer = new byte[1];
        var eofRead = await applicationStream.ReadAsync(eofBuffer, lifetimeCts.Token);
        Assert.Equal(0, eofRead);

        var captured = await serverTask;
        Assert.Equal("GET", captured.DownlinkRequest.Method);
        Assert.Equal("PUT", captured.UplinkRequest.Method);
        Assert.Equal("chunked", captured.UplinkRequest.Headers["Transfer-Encoding"]);
        Assert.Equal("application/grpc", captured.UplinkRequest.Headers["Content-Type"]);
        Assert.Equal(clientPayload, captured.UplinkPayloadText);
    }

    [Fact]
    public async Task OpenAsync_packet_up_uses_browser_dialer_for_downlink_and_upload()
    {
        using var lifetimeCts = new CancellationTokenSource(TimeSpan.FromSeconds(10));

        const string clientPayload = "browser-packet-client";
        const string serverPayload = "browser-packet-server";
        var browserDialer = new RecordingBrowserDialer(
            static (_, _) => ValueTask.FromResult<Stream>(
                new MemoryStream(Encoding.ASCII.GetBytes(serverPayload), writable: false)));
        var profile = RuntimeInternetProfile.FromDefault(browserDialer: browserDialer);

        var context = await RuntimeGrpcClientConnector.OpenAsync(
            new TestSplitHttpInternetOptions
            {
                ServerHost = "edge.example.com",
                ServerPort = 443,
                ServerName = "edge.example.com",
                SecurityType = RuntimeInternetSecurityTypes.Tls,
                SplitHttpHost = "cdn.example.com",
                SplitHttpPath = " browser?route=1 ",
                SplitHttpHeaders = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
                {
                    ["X-Test"] = "alpha"
                },
                SplitHttpMode = "packet-up",
                SplitHttpSessionPlacement = "header",
                SplitHttpSessionKey = "X-Session",
                SplitHttpSeqPlacement = "header",
                SplitHttpSeqKey = "X-Seq"
            },
            RuntimeInternetStack.Create(RuntimeInternetTransportProtocols.SplitHttp, RuntimeInternetSecurityTypes.Tls),
            profile,
            SystemDnsResolver.Instance,
            transportInitializationData: null,
            lifetimeCts.Token);

        Assert.Equal(RuntimeInternetSecurityTypes.Tls, context.SecurityState.SecurityType);

        await using var applicationStream = context.ApplicationStream;
        await applicationStream.WriteAsync(Encoding.ASCII.GetBytes(clientPayload), lifetimeCts.Token);
        await applicationStream.FlushAsync(lifetimeCts.Token);

        var responseBuffer = new byte[serverPayload.Length];
        await ReadExactAsync(applicationStream, responseBuffer, lifetimeCts.Token);
        Assert.Equal(serverPayload, Encoding.ASCII.GetString(responseBuffer));

        var eofBuffer = new byte[1];
        var eofRead = await applicationStream.ReadAsync(eofBuffer, lifetimeCts.Token);
        Assert.Equal(0, eofRead);

        var downlinkRequest = Assert.Single(browserDialer.StreamRequests);
        var uploadRequest = Assert.Single(browserDialer.PacketRequests);
        Assert.Equal("POST", uploadRequest.Method);
        Assert.Equal("alpha", downlinkRequest.Headers["X-Test"]);
        Assert.Equal("alpha", uploadRequest.Headers["X-Test"]);
        Assert.Equal(RuntimeInternetHttpUtilities.DefaultChromeUserAgent, downlinkRequest.Headers["User-Agent"]);
        Assert.Equal(RuntimeInternetHttpUtilities.DefaultChromeUserAgent, uploadRequest.Headers["User-Agent"]);
        Assert.Equal("identity", downlinkRequest.Headers["Accept-Encoding"]);
        Assert.Equal("identity", uploadRequest.Headers["Accept-Encoding"]);
        Assert.False(downlinkRequest.Headers.ContainsKey("Content-Type"));
        Assert.False(uploadRequest.Headers.ContainsKey("Content-Type"));
        Assert.Equal(clientPayload, Encoding.ASCII.GetString(uploadRequest.Payload));

        var downlinkUri = new Uri(downlinkRequest.Url);
        var uploadUri = new Uri(uploadRequest.Url);
        Assert.Equal("https", downlinkUri.Scheme);
        Assert.Equal("https", uploadUri.Scheme);
        Assert.Equal("cdn.example.com", downlinkUri.Host);
        Assert.Equal("cdn.example.com", uploadUri.Host);
        Assert.Equal("/browser/?route=1", downlinkUri.PathAndQuery);
        Assert.Equal("/browser/?route=1", uploadUri.PathAndQuery);

        var sessionId = downlinkRequest.Headers["X-Session"];
        Assert.True(Guid.TryParse(sessionId, out _));
        Assert.Equal(sessionId, uploadRequest.Headers["X-Session"]);
        Assert.Equal("0", uploadRequest.Headers["X-Seq"]);
    }

    [Fact]
    public async Task OpenAsync_stream_one_with_browser_dialer_throws_not_supported()
    {
        using var lifetimeCts = new CancellationTokenSource(TimeSpan.FromSeconds(10));
        var browserDialer = new RecordingBrowserDialer();
        var profile = RuntimeInternetProfile.FromDefault(browserDialer: browserDialer);

        var exception = await Record.ExceptionAsync(() => RuntimeGrpcClientConnector.OpenAsync(
            new TestSplitHttpInternetOptions
            {
                ServerHost = "edge.example.com",
                ServerPort = 443,
                SecurityType = RuntimeInternetSecurityTypes.None,
                SplitHttpPath = " stream-one ",
                SplitHttpMode = "stream-one"
            },
            RuntimeInternetStack.Create(RuntimeInternetTransportProtocols.SplitHttp, RuntimeInternetSecurityTypes.None),
            profile,
            SystemDnsResolver.Instance,
            transportInitializationData: null,
            lifetimeCts.Token).AsTask());

        var notSupported = Assert.IsType<NotSupportedException>(exception);
        Assert.Contains("bidirectional streaming", notSupported.Message, StringComparison.OrdinalIgnoreCase);
        Assert.Empty(browserDialer.StreamRequests);
        Assert.Empty(browserDialer.PacketRequests);
    }

    [Fact]
    public async Task OpenAsync_stream_up_with_browser_dialer_throws_not_supported()
    {
        using var lifetimeCts = new CancellationTokenSource(TimeSpan.FromSeconds(10));
        var browserDialer = new RecordingBrowserDialer();
        var profile = RuntimeInternetProfile.FromDefault(browserDialer: browserDialer);

        var exception = await Record.ExceptionAsync(() => RuntimeGrpcClientConnector.OpenAsync(
            new TestSplitHttpInternetOptions
            {
                ServerHost = "edge.example.com",
                ServerPort = 443,
                SecurityType = RuntimeInternetSecurityTypes.None,
                SplitHttpPath = " stream-up ",
                SplitHttpMode = "stream-up"
            },
            RuntimeInternetStack.Create(RuntimeInternetTransportProtocols.SplitHttp, RuntimeInternetSecurityTypes.None),
            profile,
            SystemDnsResolver.Instance,
            transportInitializationData: null,
            lifetimeCts.Token).AsTask());

        var notSupported = Assert.IsType<NotSupportedException>(exception);
        Assert.Contains("bidirectional streaming", notSupported.Message, StringComparison.OrdinalIgnoreCase);
        Assert.Empty(browserDialer.StreamRequests);
        Assert.Empty(browserDialer.PacketRequests);
    }

    [Fact]
    public async Task OpenAsync_reality_auto_mode_ignores_browser_dialer()
    {
        using var lifetimeCts = new CancellationTokenSource(TimeSpan.FromSeconds(10));
        using var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();

        const string clientPayload = "browser-ignore-client";
        const string serverPayload = "browser-ignore-server";
        var port = ((IPEndPoint)listener.LocalEndpoint).Port;
        var serverTask = CaptureSplitHttpHttp2StreamOneExchangeAsync(
            listener,
            clientPayload,
            serverPayload,
            lifetimeCts.Token);
        var realitySecurityFactory = new TestRuntimeInternetProfileFactory.RecordingPassThroughSecurityFactory(
            RuntimeInternetSecurityTypes.Reality,
            negotiatedApplicationProtocol: "h2");
        var browserDialer = new RecordingBrowserDialer();
        var profile = RuntimeInternetProfile.FromDefault(
            securityFactories:
            [
                realitySecurityFactory
            ],
            replaceExistingSecurityFactories: true,
            browserDialer: browserDialer);

        var context = await RuntimeGrpcClientConnector.OpenAsync(
            new TestSplitHttpInternetOptions
            {
                ServerHost = "127.0.0.1",
                ServerPort = port,
                ServerName = "edge.example.com",
                SecurityType = RuntimeInternetSecurityTypes.Reality,
                RealityOptions = new RuntimeRealityOptions
                {
                    PublicKey = EncodeBase64Url(32, 0x41)
                },
                SplitHttpMode = "auto",
                SplitHttpPath = "stream-one?route=1"
            },
            RuntimeInternetStack.Create(RuntimeInternetTransportProtocols.SplitHttp, RuntimeInternetSecurityTypes.Reality),
            profile,
            SystemDnsResolver.Instance,
            transportInitializationData: null,
            lifetimeCts.Token);

        await using var applicationStream = context.ApplicationStream;
        await applicationStream.WriteAsync(Encoding.ASCII.GetBytes(clientPayload), lifetimeCts.Token);
        await applicationStream.FlushAsync(lifetimeCts.Token);

        var responseBuffer = new byte[serverPayload.Length];
        await ReadExactAsync(applicationStream, responseBuffer, lifetimeCts.Token);
        Assert.Equal(serverPayload, Encoding.ASCII.GetString(responseBuffer));

        var eofBuffer = new byte[1];
        var eofRead = await applicationStream.ReadAsync(eofBuffer, lifetimeCts.Token);
        Assert.Equal(0, eofRead);

        var captured = await serverTask;
        Assert.Equal("POST", captured.Request.Method);
        Assert.Equal("/stream-one/?route=1", captured.Request.Target);
        Assert.Equal("edge.example.com", captured.Request.Headers[":authority"]);
        Assert.Equal("https", captured.Request.Headers[":scheme"]);
        Assert.Equal(clientPayload, captured.PayloadText);
        Assert.Equal(["h2", "http/1.1"], realitySecurityFactory.ObservedApplicationProtocols);
        Assert.Equal("h2", realitySecurityFactory.NegotiatedApplicationProtocol);
        Assert.Empty(browserDialer.StreamRequests);
        Assert.Empty(browserDialer.PacketRequests);
    }

    [Fact]
    public async Task OpenAsync_explicit_h3_stream_one_relays_duplex_payloads()
    {
        if (!QuicConnection.IsSupported || !QuicListener.IsSupported)
        {
            return;
        }

        using var lifetimeCts = new CancellationTokenSource(TimeSpan.FromSeconds(30));
        using var certificate = TestCertificateFactory.CreateSelfSignedServerCertificate("localhost", ["localhost"]);

        const string clientPayload = "h3-stream-one-client";
        const string serverPayload = "h3-stream-one-server";
        var port = ReserveTcpPort();
        var requestTcs = new TaskCompletionSource<CapturedHttp3ServerRequest>(
            TaskCreationOptions.RunContinuationsAsynchronously);

        var builder = WebApplication.CreateBuilder();
        builder.Logging.ClearProviders();
        builder.WebHost.ConfigureKestrel(options =>
        {
            options.Listen(IPAddress.Loopback, port, listenOptions =>
            {
                listenOptions.Protocols = HttpProtocols.Http3;
                listenOptions.UseHttps(certificate);
            });
        });

        var app = builder.Build();
        app.Run(async context =>
        {
            var requestBodyBuffer = new byte[Encoding.ASCII.GetByteCount(clientPayload)];
            await ReadExactAsync(context.Request.Body, requestBodyBuffer, lifetimeCts.Token);
            requestTcs.TrySetResult(new CapturedHttp3ServerRequest(
                context.Request.Protocol,
                new SplitHttpRequest(
                    context.Request.Method,
                    $"{context.Request.Path}{context.Request.QueryString}",
                    context.Request.Headers.ToDictionary(
                        static pair => pair.Key,
                        static pair => pair.Value.ToString(),
                        StringComparer.OrdinalIgnoreCase)),
                Encoding.ASCII.GetString(requestBodyBuffer)));

            await context.Response.Body.WriteAsync(Encoding.ASCII.GetBytes(serverPayload), lifetimeCts.Token);
        });

        await app.StartAsync(lifetimeCts.Token);

        try
        {
            RuntimeInternetConnectionContext context;
            try
            {
                context = await RuntimeGrpcClientConnector.OpenAsync(
                    new TestSplitHttpInternetOptions
                    {
                        ServerHost = "127.0.0.1",
                        ServerPort = port,
                        ServerName = "localhost",
                        SecurityType = RuntimeInternetSecurityTypes.Tls,
                        ApplicationProtocols = ["h3"],
                        SplitHttpHost = "cdn.example.com",
                        SplitHttpPath = "stream-one?route=1",
                        SplitHttpMode = "stream-one"
                    },
                    RuntimeInternetStack.Create(RuntimeInternetTransportProtocols.SplitHttp, RuntimeInternetSecurityTypes.Tls),
                    RuntimeInternetProfile.FromDefault(),
                    SystemDnsResolver.Instance,
                    transportInitializationData: null,
                    lifetimeCts.Token);
            }
            catch (Exception ex) when (IsKnownLocalQuicCredentialLoadFailure(ex))
            {
                return;
            }

            await using var applicationStream = context.ApplicationStream;
            await applicationStream.WriteAsync(Encoding.ASCII.GetBytes(clientPayload), lifetimeCts.Token);
            await applicationStream.FlushAsync(lifetimeCts.Token);

            var responseBuffer = new byte[serverPayload.Length];
            await ReadExactAsync(applicationStream, responseBuffer, lifetimeCts.Token);
            Assert.Equal(serverPayload, Encoding.ASCII.GetString(responseBuffer));

            var eofBuffer = new byte[1];
            var eofRead = await applicationStream.ReadAsync(eofBuffer, lifetimeCts.Token);
            Assert.Equal(0, eofRead);

            var captured = await requestTcs.Task.WaitAsync(lifetimeCts.Token);
            Assert.Equal("HTTP/3", captured.Protocol);
            Assert.Equal("POST", captured.Request.Method);
            Assert.Equal("/stream-one/?route=1", captured.Request.Target);
            Assert.Equal("cdn.example.com", captured.Request.Headers["Host"]);
            Assert.Equal("application/grpc", captured.Request.Headers["Content-Type"]);
            Assert.Equal("identity", captured.Request.Headers["Accept-Encoding"]);
            Assert.False(string.IsNullOrWhiteSpace(captured.Request.Headers["User-Agent"]));
            Assert.Equal(clientPayload, captured.RequestBodyText);
        }
        finally
        {
            await app.StopAsync(lifetimeCts.Token);
            await app.DisposeAsync();
        }
    }

    [Fact]
    public async Task OpenAsync_explicit_h3_stream_one_reuses_connection_across_sessions()
    {
        if (!QuicConnection.IsSupported || !QuicListener.IsSupported)
        {
            return;
        }

        using var lifetimeCts = new CancellationTokenSource(TimeSpan.FromSeconds(30));
        using var certificate = TestCertificateFactory.CreateSelfSignedServerCertificate("localhost", ["localhost"]);

        var clientPayloads = new[] { "h3-stream-one-first", "h3-stream-one-second" };
        var serverPayloads = new[] { "h3-stream-one-response-1", "h3-stream-one-response-2" };
        var port = ReserveTcpPort();
        var capturedRequests = new ConcurrentQueue<CapturedHttp3ServerRequest>();
        var requestCount = 0;

        var builder = WebApplication.CreateBuilder();
        builder.Logging.ClearProviders();
        builder.WebHost.ConfigureKestrel(options =>
        {
            options.Listen(IPAddress.Loopback, port, listenOptions =>
            {
                listenOptions.Protocols = HttpProtocols.Http3;
                listenOptions.UseHttps(certificate);
            });
        });

        var app = builder.Build();
        app.Run(async context =>
        {
            var index = Interlocked.Increment(ref requestCount) - 1;
            var expectedClientPayload = clientPayloads[index];
            var requestBodyBuffer = new byte[Encoding.ASCII.GetByteCount(expectedClientPayload)];
            await ReadExactAsync(context.Request.Body, requestBodyBuffer, lifetimeCts.Token);
            capturedRequests.Enqueue(new CapturedHttp3ServerRequest(
                context.Request.Protocol,
                CaptureAspNetRequest(context.Request),
                Encoding.ASCII.GetString(requestBodyBuffer),
                context.Connection.Id));

            await context.Response.Body.WriteAsync(Encoding.ASCII.GetBytes(serverPayloads[index]), lifetimeCts.Token);
        });

        await app.StartAsync(lifetimeCts.Token);

        try
        {
            var profile = RuntimeInternetProfile.FromDefault();
            foreach (var index in Enumerable.Range(0, clientPayloads.Length))
            {
                RuntimeInternetConnectionContext context;
                try
                {
                    context = await RuntimeGrpcClientConnector.OpenAsync(
                        new TestSplitHttpInternetOptions
                        {
                            ServerHost = "127.0.0.1",
                            ServerPort = port,
                            ServerName = "localhost",
                            SecurityType = RuntimeInternetSecurityTypes.Tls,
                            ApplicationProtocols = ["h3"],
                            SplitHttpHost = "reuse.example.com",
                            SplitHttpPath = "stream-one-reuse?route=1",
                            SplitHttpMode = "stream-one"
                        },
                        RuntimeInternetStack.Create(RuntimeInternetTransportProtocols.SplitHttp, RuntimeInternetSecurityTypes.Tls),
                        profile,
                        SystemDnsResolver.Instance,
                        transportInitializationData: null,
                        lifetimeCts.Token);
                }
                catch (Exception ex) when (IsKnownLocalQuicCredentialLoadFailure(ex))
                {
                    return;
                }

                await using var applicationStream = context.ApplicationStream;
                await applicationStream.WriteAsync(Encoding.ASCII.GetBytes(clientPayloads[index]), lifetimeCts.Token);
                await applicationStream.FlushAsync(lifetimeCts.Token);

                var responseBuffer = new byte[serverPayloads[index].Length];
                await ReadExactAsync(applicationStream, responseBuffer, lifetimeCts.Token);
                Assert.Equal(serverPayloads[index], Encoding.ASCII.GetString(responseBuffer));

                var eofBuffer = new byte[1];
                var eofException = await Record.ExceptionAsync(async () =>
                {
                    var eofRead = await applicationStream.ReadAsync(eofBuffer, lifetimeCts.Token);
                    Assert.Equal(0, eofRead);
                });
                Assert.True(eofException is null or EndOfStreamException, eofException?.ToString());
            }

            await WaitUntilAsync(() => capturedRequests.Count == clientPayloads.Length, lifetimeCts.Token);
            var captured = capturedRequests.ToArray();
            Assert.Equal(2, captured.Length);
            Assert.Single(captured.Select(static request => request.ConnectionId).Distinct(StringComparer.Ordinal));

            foreach (var (capturedRequest, index) in captured.Select(static (request, index) => (request, index)))
            {
                Assert.Equal("HTTP/3", capturedRequest.Protocol);
                Assert.Equal("POST", capturedRequest.Request.Method);
                Assert.Equal("/stream-one-reuse/?route=1", capturedRequest.Request.Target);
                Assert.Equal("reuse.example.com", capturedRequest.Request.Headers["Host"]);
                Assert.Equal("application/grpc", capturedRequest.Request.Headers["Content-Type"]);
                Assert.Equal("identity", capturedRequest.Request.Headers["Accept-Encoding"]);
                Assert.Equal(clientPayloads[index], capturedRequest.RequestBodyText);
            }
        }
        finally
        {
            await app.StopAsync(lifetimeCts.Token);
            await app.DisposeAsync();
        }
    }

    [Fact]
    public async Task OpenAsync_explicit_h3_stream_up_relays_duplex_payloads()
    {
        if (!QuicConnection.IsSupported || !QuicListener.IsSupported)
        {
            return;
        }

        using var lifetimeCts = new CancellationTokenSource(TimeSpan.FromSeconds(30));
        using var certificate = TestCertificateFactory.CreateSelfSignedServerCertificate("localhost", ["localhost"]);

        const string clientPayload = "h3-stream-up-client";
        const string serverPayload = "h3-stream-up-server";
        var port = ReserveTcpPort();
        var session = new Http3StreamUpServerSession(0);

        var builder = WebApplication.CreateBuilder();
        builder.Logging.ClearProviders();
        builder.WebHost.ConfigureKestrel(options =>
        {
            options.Listen(IPAddress.Loopback, port, listenOptions =>
            {
                listenOptions.Protocols = HttpProtocols.Http3;
                listenOptions.UseHttps(certificate);
            });
        });

        var app = builder.Build();
        app.Run(async context =>
        {
            if (string.Equals(context.Request.Method, "GET", StringComparison.Ordinal))
            {
                session.DownlinkRequest = CaptureAspNetRequest(context.Request);
                session.DownlinkConnectionId = context.Connection.Id;
                session.TryCompleteExchange();
                var responsePayload = await session.ResponseReady.Task.WaitAsync(lifetimeCts.Token);
                await context.Response.Body.WriteAsync(Encoding.ASCII.GetBytes(responsePayload), lifetimeCts.Token);
                return;
            }

            if (string.Equals(context.Request.Method, "POST", StringComparison.Ordinal))
            {
                var requestBodyBuffer = new byte[Encoding.ASCII.GetByteCount(clientPayload)];
                await ReadExactAsync(context.Request.Body, requestBodyBuffer, lifetimeCts.Token);
                session.UplinkRequest = CaptureAspNetRequest(context.Request);
                session.UplinkConnectionId = context.Connection.Id;
                session.UplinkPayloadText = Encoding.ASCII.GetString(requestBodyBuffer);
                session.ResponseReady.TrySetResult(serverPayload);
                session.TryCompleteExchange();
                return;
            }

            context.Response.StatusCode = 405;
        });

        await app.StartAsync(lifetimeCts.Token);

        try
        {
            RuntimeInternetConnectionContext context;
            try
            {
                context = await RuntimeGrpcClientConnector.OpenAsync(
                    new TestSplitHttpInternetOptions
                    {
                        ServerHost = "127.0.0.1",
                        ServerPort = port,
                        ServerName = "localhost",
                        SecurityType = RuntimeInternetSecurityTypes.Tls,
                        ApplicationProtocols = ["h3"],
                        SplitHttpHost = "stream-up.example.com",
                        SplitHttpPath = "stream-up-single?route=1",
                        SplitHttpMode = "stream-up",
                        SplitHttpSessionPlacement = "path"
                    },
                    RuntimeInternetStack.Create(RuntimeInternetTransportProtocols.SplitHttp, RuntimeInternetSecurityTypes.Tls),
                    RuntimeInternetProfile.FromDefault(),
                    SystemDnsResolver.Instance,
                    transportInitializationData: null,
                    lifetimeCts.Token);
            }
            catch (Exception ex) when (IsKnownLocalQuicCredentialLoadFailure(ex))
            {
                return;
            }

            await using var applicationStream = context.ApplicationStream;
            await applicationStream.WriteAsync(Encoding.ASCII.GetBytes(clientPayload), lifetimeCts.Token);
            await applicationStream.FlushAsync(lifetimeCts.Token);

            var responseBuffer = new byte[serverPayload.Length];
            await ReadExactAsync(applicationStream, responseBuffer, lifetimeCts.Token);
            Assert.Equal(serverPayload, Encoding.ASCII.GetString(responseBuffer));

            var eofBuffer = new byte[1];
            var eofRead = await applicationStream.ReadAsync(eofBuffer, lifetimeCts.Token);
            Assert.Equal(0, eofRead);

            var exchange = await session.Exchange.Task.WaitAsync(lifetimeCts.Token);
            Assert.Equal("GET", exchange.DownlinkRequest.Method);
            Assert.Equal("POST", exchange.UplinkRequest.Method);
            Assert.Equal("stream-up.example.com", exchange.DownlinkRequest.Headers["Host"]);
            Assert.Equal("stream-up.example.com", exchange.UplinkRequest.Headers["Host"]);
            Assert.Equal("identity", exchange.DownlinkRequest.Headers["Accept-Encoding"]);
            Assert.Equal("identity", exchange.UplinkRequest.Headers["Accept-Encoding"]);
            Assert.Equal("application/grpc", exchange.UplinkRequest.Headers["Content-Type"]);
            Assert.Equal(clientPayload, exchange.UplinkPayloadText);

            var downlinkTarget = new Uri("https://split.local" + exchange.DownlinkRequest.Target);
            var uplinkTarget = new Uri("https://split.local" + exchange.UplinkRequest.Target);
            Assert.Equal("route=1", downlinkTarget.Query.TrimStart('?'));
            Assert.Equal("route=1", uplinkTarget.Query.TrimStart('?'));

            var downlinkSegments = downlinkTarget.AbsolutePath.Split('/', StringSplitOptions.RemoveEmptyEntries);
            var uplinkSegments = uplinkTarget.AbsolutePath.Split('/', StringSplitOptions.RemoveEmptyEntries);
            Assert.Equal("stream-up-single", downlinkSegments[0]);
            Assert.Equal("stream-up-single", uplinkSegments[0]);
            Assert.True(Guid.TryParse(Uri.UnescapeDataString(downlinkSegments[1]), out _));
            Assert.Equal(Uri.UnescapeDataString(downlinkSegments[1]), Uri.UnescapeDataString(uplinkSegments[1]));
        }
        finally
        {
            await app.StopAsync(lifetimeCts.Token);
            await app.DisposeAsync();
        }
    }

    [Fact]
    public async Task OpenAsync_explicit_h3_stream_up_reuses_connection_across_sessions()
    {
        if (!QuicConnection.IsSupported || !QuicListener.IsSupported)
        {
            return;
        }

        using var lifetimeCts = new CancellationTokenSource(TimeSpan.FromSeconds(30));
        using var certificate = TestCertificateFactory.CreateSelfSignedServerCertificate("localhost", ["localhost"]);

        var clientPayloads = new[] { "h3-stream-up-first", "h3-stream-up-second" };
        var serverPayloads = new[] { "h3-stream-up-response-1", "h3-stream-up-response-2" };
        var port = ReserveTcpPort();
        var sessions = new ConcurrentDictionary<string, Http3StreamUpServerSession>(StringComparer.Ordinal);
        var sessionsLock = new object();
        var nextSessionIndex = 0;

        var builder = WebApplication.CreateBuilder();
        builder.Logging.ClearProviders();
        builder.WebHost.ConfigureKestrel(options =>
        {
            options.Listen(IPAddress.Loopback, port, listenOptions =>
            {
                listenOptions.Protocols = HttpProtocols.Http3;
                listenOptions.UseHttps(certificate);
            });
        });

        var app = builder.Build();
        app.Run(async context =>
        {
            var sessionId = ExtractSplitHttpPathSessionId(context.Request.Path.Value);
            var session = GetOrAddHttp3StreamUpSession(sessions, sessionsLock, sessionId, ref nextSessionIndex);

            if (string.Equals(context.Request.Method, "GET", StringComparison.Ordinal))
            {
                session.DownlinkRequest = CaptureAspNetRequest(context.Request);
                session.DownlinkConnectionId = context.Connection.Id;
                session.TryCompleteExchange();
                var responsePayload = await session.ResponseReady.Task.WaitAsync(lifetimeCts.Token);
                await context.Response.Body.WriteAsync(Encoding.ASCII.GetBytes(responsePayload), lifetimeCts.Token);
                return;
            }

            if (string.Equals(context.Request.Method, "POST", StringComparison.Ordinal))
            {
                var expectedClientPayload = clientPayloads[session.Index];
                var requestBodyBuffer = new byte[Encoding.ASCII.GetByteCount(expectedClientPayload)];
                await ReadExactAsync(context.Request.Body, requestBodyBuffer, lifetimeCts.Token);
                session.UplinkRequest = CaptureAspNetRequest(context.Request);
                session.UplinkConnectionId = context.Connection.Id;
                session.UplinkPayloadText = Encoding.ASCII.GetString(requestBodyBuffer);
                session.ResponseReady.TrySetResult(serverPayloads[session.Index]);
                session.TryCompleteExchange();
                return;
            }

            context.Response.StatusCode = 405;
        });

        await app.StartAsync(lifetimeCts.Token);

        try
        {
            var profile = RuntimeInternetProfile.FromDefault();
            foreach (var index in Enumerable.Range(0, clientPayloads.Length))
            {
                RuntimeInternetConnectionContext context;
                try
                {
                    context = await RuntimeGrpcClientConnector.OpenAsync(
                        new TestSplitHttpInternetOptions
                        {
                            ServerHost = "127.0.0.1",
                            ServerPort = port,
                            ServerName = "localhost",
                            SecurityType = RuntimeInternetSecurityTypes.Tls,
                            ApplicationProtocols = ["h3"],
                            SplitHttpHost = "reuse.example.com",
                            SplitHttpPath = "stream-up-reuse?route=1",
                            SplitHttpMode = "stream-up"
                        },
                        RuntimeInternetStack.Create(RuntimeInternetTransportProtocols.SplitHttp, RuntimeInternetSecurityTypes.Tls),
                        profile,
                        SystemDnsResolver.Instance,
                        transportInitializationData: null,
                        lifetimeCts.Token);
                }
                catch (Exception ex) when (IsKnownLocalQuicCredentialLoadFailure(ex))
                {
                    return;
                }

                await using var applicationStream = context.ApplicationStream;
                await applicationStream.WriteAsync(Encoding.ASCII.GetBytes(clientPayloads[index]), lifetimeCts.Token);
                await applicationStream.FlushAsync(lifetimeCts.Token);

                var responseBuffer = new byte[serverPayloads[index].Length];
                await ReadExactAsync(applicationStream, responseBuffer, lifetimeCts.Token);
                Assert.Equal(serverPayloads[index], Encoding.ASCII.GetString(responseBuffer));

                var eofBuffer = new byte[1];
                var eofException = await Record.ExceptionAsync(async () =>
                {
                    var eofRead = await applicationStream.ReadAsync(eofBuffer, lifetimeCts.Token);
                    Assert.Equal(0, eofRead);
                });
                Assert.True(eofException is null or EndOfStreamException, eofException?.ToString());
            }

            await WaitUntilAsync(
                () => sessions.Count == clientPayloads.Length &&
                      sessions.Values.All(static session => session.Exchange.Task.IsCompleted),
                lifetimeCts.Token);

            var captured = sessions.Values
                .OrderBy(static session => session.Index)
                .Select(static session => session.Exchange.Task.Result)
                .ToArray();
            Assert.Equal(2, captured.Length);
            Assert.Single(captured.Select(static exchange => exchange.DownlinkConnectionId).Distinct(StringComparer.Ordinal));
            Assert.Single(captured.Select(static exchange => exchange.UplinkConnectionId).Distinct(StringComparer.Ordinal));
            Assert.Single(captured.SelectMany(static exchange => new[] { exchange.DownlinkConnectionId, exchange.UplinkConnectionId }).Distinct(StringComparer.Ordinal));

            foreach (var (exchange, index) in captured.Select(static (exchange, index) => (exchange, index)))
            {
                Assert.Equal("GET", exchange.DownlinkRequest.Method);
                Assert.Equal("POST", exchange.UplinkRequest.Method);
                Assert.StartsWith("/stream-up-reuse/", exchange.DownlinkRequest.Target.Split('?', 2)[0], StringComparison.Ordinal);
                Assert.StartsWith("/stream-up-reuse/", exchange.UplinkRequest.Target.Split('?', 2)[0], StringComparison.Ordinal);
                Assert.Equal("reuse.example.com", exchange.DownlinkRequest.Headers["Host"]);
                Assert.Equal("reuse.example.com", exchange.UplinkRequest.Headers["Host"]);
                Assert.Equal("application/grpc", exchange.UplinkRequest.Headers["Content-Type"]);
                Assert.Equal("identity", exchange.DownlinkRequest.Headers["Accept-Encoding"]);
                Assert.Equal("identity", exchange.UplinkRequest.Headers["Accept-Encoding"]);
                Assert.Equal(clientPayloads[index], exchange.UplinkPayloadText);

                var downlinkTarget = new Uri("https://split.local" + exchange.DownlinkRequest.Target);
                var uplinkTarget = new Uri("https://split.local" + exchange.UplinkRequest.Target);
                Assert.Equal("route=1", downlinkTarget.Query.TrimStart('?'));
                Assert.Equal("route=1", uplinkTarget.Query.TrimStart('?'));

                var downlinkSegments = downlinkTarget.AbsolutePath.Split('/', StringSplitOptions.RemoveEmptyEntries);
                var uplinkSegments = uplinkTarget.AbsolutePath.Split('/', StringSplitOptions.RemoveEmptyEntries);
                Assert.Equal("stream-up-reuse", downlinkSegments[0]);
                Assert.Equal("stream-up-reuse", uplinkSegments[0]);
                Assert.True(Guid.TryParse(Uri.UnescapeDataString(downlinkSegments[1]), out _));
                Assert.Equal(Uri.UnescapeDataString(downlinkSegments[1]), Uri.UnescapeDataString(uplinkSegments[1]));
            }
        }
        finally
        {
            await app.StopAsync(lifetimeCts.Token);
            await app.DisposeAsync();
        }
    }

    [Fact]
    public async Task OpenAsync_explicit_h3_stream_up_with_download_settings_reuses_connections_across_sessions()
    {
        if (!QuicConnection.IsSupported || !QuicListener.IsSupported)
        {
            return;
        }

        using var lifetimeCts = new CancellationTokenSource(TimeSpan.FromSeconds(30));
        using var certificate = TestCertificateFactory.CreateSelfSignedServerCertificate("localhost", ["localhost"]);

        var clientPayloads = new[] { "h3-dedicated-first", "h3-dedicated-second" };
        var serverPayloads = new[] { "h3-dedicated-response-1", "h3-dedicated-response-2" };
        var downlinkPort = ReserveTcpPort();
        var uploadPort = ReserveTcpPort();
        var sessions = new ConcurrentDictionary<string, Http3StreamUpServerSession>(StringComparer.Ordinal);
        var sessionsLock = new object();
        var nextSessionIndex = 0;

        var downlinkBuilder = WebApplication.CreateBuilder();
        downlinkBuilder.Logging.ClearProviders();
        downlinkBuilder.WebHost.ConfigureKestrel(options =>
        {
            options.Listen(IPAddress.Loopback, downlinkPort, listenOptions =>
            {
                listenOptions.Protocols = HttpProtocols.Http3;
                listenOptions.UseHttps(certificate);
            });
        });

        var downlinkApp = downlinkBuilder.Build();
        downlinkApp.Run(async context =>
        {
            var sessionId = ExtractSplitHttpPathSessionId(context.Request.Path.Value);
            var session = GetOrAddHttp3StreamUpSession(sessions, sessionsLock, sessionId, ref nextSessionIndex);

            Assert.Equal("GET", context.Request.Method);
            session.DownlinkRequest = CaptureAspNetRequest(context.Request);
            session.DownlinkConnectionId = context.Connection.Id;
            session.TryCompleteExchange();
            var responsePayload = await session.ResponseReady.Task.WaitAsync(lifetimeCts.Token);
            await context.Response.Body.WriteAsync(Encoding.ASCII.GetBytes(responsePayload), lifetimeCts.Token);
        });

        var uploadBuilder = WebApplication.CreateBuilder();
        uploadBuilder.Logging.ClearProviders();
        uploadBuilder.WebHost.ConfigureKestrel(options =>
        {
            options.Listen(IPAddress.Loopback, uploadPort, listenOptions =>
            {
                listenOptions.Protocols = HttpProtocols.Http3;
                listenOptions.UseHttps(certificate);
            });
        });

        var uploadApp = uploadBuilder.Build();
        uploadApp.Run(async context =>
        {
            var sessionId = ExtractSplitHttpPathSessionId(context.Request.Path.Value);
            var session = GetOrAddHttp3StreamUpSession(sessions, sessionsLock, sessionId, ref nextSessionIndex);

            Assert.Equal("POST", context.Request.Method);
            var expectedClientPayload = clientPayloads[session.Index];
            var requestBodyBuffer = new byte[Encoding.ASCII.GetByteCount(expectedClientPayload)];
            await ReadExactAsync(context.Request.Body, requestBodyBuffer, lifetimeCts.Token);
            session.UplinkRequest = CaptureAspNetRequest(context.Request);
            session.UplinkConnectionId = context.Connection.Id;
            session.UplinkPayloadText = Encoding.ASCII.GetString(requestBodyBuffer);
            session.ResponseReady.TrySetResult(serverPayloads[session.Index]);
            session.TryCompleteExchange();
        });

        await downlinkApp.StartAsync(lifetimeCts.Token);
        await uploadApp.StartAsync(lifetimeCts.Token);

        try
        {
            var profile = RuntimeInternetProfile.FromDefault();
            foreach (var index in Enumerable.Range(0, clientPayloads.Length))
            {
                RuntimeInternetConnectionContext context;
                try
                {
                    context = await RuntimeGrpcClientConnector.OpenAsync(
                        new TestSplitHttpInternetOptions
                        {
                            ServerHost = "127.0.0.1",
                            ServerPort = uploadPort,
                            ServerName = "localhost",
                            SecurityType = RuntimeInternetSecurityTypes.Tls,
                            ApplicationProtocols = ["h3"],
                            SplitHttpHost = "upload.example.com",
                            SplitHttpPath = "upload-h3-reuse?u=1",
                            SplitHttpMode = "stream-up",
                            SplitHttpDownloadSettings = new RuntimeSplitHttpDownloadOptions
                            {
                                ServerHost = "127.0.0.1",
                                ServerPort = downlinkPort,
                                ServerName = "localhost",
                                TransportSecurity = RuntimeInternetSecurityTypes.Tls,
                                Host = "down.example.com",
                                Path = "down-h3-reuse?d=1"
                            }
                        },
                        RuntimeInternetStack.Create(RuntimeInternetTransportProtocols.SplitHttp, RuntimeInternetSecurityTypes.Tls),
                        profile,
                        SystemDnsResolver.Instance,
                        transportInitializationData: null,
                        lifetimeCts.Token);
                }
                catch (Exception ex) when (IsKnownLocalQuicCredentialLoadFailure(ex))
                {
                    return;
                }

                await using var applicationStream = context.ApplicationStream;
                await applicationStream.WriteAsync(Encoding.ASCII.GetBytes(clientPayloads[index]), lifetimeCts.Token);
                await applicationStream.FlushAsync(lifetimeCts.Token);

                var responseBuffer = new byte[serverPayloads[index].Length];
                await ReadExactAsync(applicationStream, responseBuffer, lifetimeCts.Token);
                Assert.Equal(serverPayloads[index], Encoding.ASCII.GetString(responseBuffer));

                var eofBuffer = new byte[1];
                var eofRead = await applicationStream.ReadAsync(eofBuffer, lifetimeCts.Token);
                Assert.Equal(0, eofRead);
            }

            await WaitUntilAsync(
                () => sessions.Count == clientPayloads.Length &&
                      sessions.Values.All(static session => session.Exchange.Task.IsCompleted),
                lifetimeCts.Token);

            var captured = sessions.Values
                .OrderBy(static session => session.Index)
                .Select(static session => session.Exchange.Task.Result)
                .ToArray();
            Assert.Equal(2, captured.Length);
            Assert.Single(captured.Select(static exchange => exchange.DownlinkConnectionId).Distinct(StringComparer.Ordinal));
            Assert.Single(captured.Select(static exchange => exchange.UplinkConnectionId).Distinct(StringComparer.Ordinal));

            foreach (var (exchange, index) in captured.Select(static (exchange, index) => (exchange, index)))
            {
                Assert.Equal("GET", exchange.DownlinkRequest.Method);
                Assert.Equal("POST", exchange.UplinkRequest.Method);
                Assert.Equal("down.example.com", exchange.DownlinkRequest.Headers["Host"]);
                Assert.Equal("upload.example.com", exchange.UplinkRequest.Headers["Host"]);
                Assert.Equal("identity", exchange.DownlinkRequest.Headers["Accept-Encoding"]);
                Assert.Equal("identity", exchange.UplinkRequest.Headers["Accept-Encoding"]);
                Assert.Equal("application/grpc", exchange.UplinkRequest.Headers["Content-Type"]);
                Assert.Equal(clientPayloads[index], exchange.UplinkPayloadText);

                var downlinkTarget = new Uri("https://split.local" + exchange.DownlinkRequest.Target);
                var uplinkTarget = new Uri("https://split.local" + exchange.UplinkRequest.Target);
                Assert.Equal("d=1", downlinkTarget.Query.TrimStart('?'));
                Assert.Equal("u=1", uplinkTarget.Query.TrimStart('?'));

                var downlinkSegments = downlinkTarget.AbsolutePath.Split('/', StringSplitOptions.RemoveEmptyEntries);
                var uplinkSegments = uplinkTarget.AbsolutePath.Split('/', StringSplitOptions.RemoveEmptyEntries);
                Assert.Equal("down-h3-reuse", downlinkSegments[0]);
                Assert.Equal("upload-h3-reuse", uplinkSegments[0]);
                Assert.True(Guid.TryParse(Uri.UnescapeDataString(downlinkSegments[1]), out _));
                Assert.Equal(Uri.UnescapeDataString(downlinkSegments[1]), Uri.UnescapeDataString(uplinkSegments[1]));
            }
        }
        finally
        {
            await uploadApp.StopAsync(lifetimeCts.Token);
            await uploadApp.DisposeAsync();
            await downlinkApp.StopAsync(lifetimeCts.Token);
            await downlinkApp.DisposeAsync();
        }
    }

    [Fact]
    public async Task OpenAsync_explicit_h3_packet_up_routes_into_h3_packet_up_path()
    {
        using var lifetimeCts = new CancellationTokenSource(TimeSpan.FromSeconds(5));
        var profile = RuntimeInternetProfile.FromDefault();

        var exception = await Record.ExceptionAsync(() => RuntimeGrpcClientConnector.OpenAsync(
                new TestSplitHttpInternetOptions
                {
                    ServerHost = "127.0.0.1",
                    ServerPort = 443,
                    SecurityType = RuntimeInternetSecurityTypes.Tls,
                    ApplicationProtocols = ["h3"],
                    SplitHttpMode = "packet-up",
                    TransportStreamFactory = static cancellationToken => ValueTask.FromResult<Stream>(Stream.Null)
                },
                RuntimeInternetStack.Create(RuntimeInternetTransportProtocols.SplitHttp, RuntimeInternetSecurityTypes.Tls),
                profile,
                SystemDnsResolver.Instance,
                transportInitializationData: null,
                lifetimeCts.Token).AsTask());

        Assert.NotNull(exception);
        if (!QuicConnection.IsSupported)
        {
            Assert.IsType<PlatformNotSupportedException>(exception);
            Assert.Contains("QUIC", exception.Message, StringComparison.OrdinalIgnoreCase);
            return;
        }

        Assert.IsType<NotSupportedException>(exception);
        Assert.Contains("TransportStreamFactory", exception.Message, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task OpenAsync_explicit_h3_stream_one_accepts_custom_uplink_method()
    {
        using var lifetimeCts = new CancellationTokenSource(TimeSpan.FromSeconds(5));
        var profile = RuntimeInternetProfile.FromDefault();

        var exception = await Record.ExceptionAsync(() => RuntimeGrpcClientConnector.OpenAsync(
                new TestSplitHttpInternetOptions
                {
                    ServerHost = "127.0.0.1",
                    ServerPort = 443,
                    SecurityType = RuntimeInternetSecurityTypes.Tls,
                    ApplicationProtocols = ["h3"],
                    SplitHttpMode = "stream-one",
                    SplitHttpUplinkHttpMethod = "PUT",
                    TransportStreamFactory = static cancellationToken => ValueTask.FromResult<Stream>(Stream.Null)
                },
                RuntimeInternetStack.Create(RuntimeInternetTransportProtocols.SplitHttp, RuntimeInternetSecurityTypes.Tls),
                profile,
                SystemDnsResolver.Instance,
                transportInitializationData: null,
                lifetimeCts.Token).AsTask());

        Assert.NotNull(exception);
        if (!QuicConnection.IsSupported)
        {
            Assert.IsType<PlatformNotSupportedException>(exception);
            Assert.Contains("QUIC", exception.Message, StringComparison.OrdinalIgnoreCase);
            return;
        }

        Assert.IsType<NotSupportedException>(exception);
        Assert.Contains("TransportStreamFactory", exception.Message, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task OpenAsync_explicit_h3_stream_up_accepts_custom_uplink_method()
    {
        using var lifetimeCts = new CancellationTokenSource(TimeSpan.FromSeconds(5));
        var profile = RuntimeInternetProfile.FromDefault();

        var exception = await Record.ExceptionAsync(() => RuntimeGrpcClientConnector.OpenAsync(
                new TestSplitHttpInternetOptions
                {
                    ServerHost = "127.0.0.1",
                    ServerPort = 443,
                    SecurityType = RuntimeInternetSecurityTypes.Tls,
                    ApplicationProtocols = ["h3"],
                    SplitHttpMode = "stream-up",
                    SplitHttpUplinkHttpMethod = "PUT",
                    TransportStreamFactory = static cancellationToken => ValueTask.FromResult<Stream>(Stream.Null)
                },
                RuntimeInternetStack.Create(RuntimeInternetTransportProtocols.SplitHttp, RuntimeInternetSecurityTypes.Tls),
                profile,
                SystemDnsResolver.Instance,
                transportInitializationData: null,
                lifetimeCts.Token).AsTask());

        Assert.NotNull(exception);
        if (!QuicConnection.IsSupported)
        {
            Assert.IsType<PlatformNotSupportedException>(exception);
            Assert.Contains("QUIC", exception.Message, StringComparison.OrdinalIgnoreCase);
            return;
        }

        Assert.IsType<NotSupportedException>(exception);
        Assert.Contains("TransportStreamFactory", exception.Message, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task OpenAsync_stream_up_default_xpadding_uses_referer_and_ignores_obfs_fields()
    {
        using var lifetimeCts = new CancellationTokenSource(TimeSpan.FromSeconds(10));
        using var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();

        const string clientPayload = "referer-client";
        const string serverPayload = "referer-server";
        var port = ((IPEndPoint)listener.LocalEndpoint).Port;
        var serverTask = CaptureSplitHttpExchangeAsync(
            listener,
            clientPayload,
            serverPayload,
            downlinkBodyMode: SplitHttpDownlinkBodyMode.Chunked,
            lifetimeCts.Token);
        var profile = RuntimeInternetProfile.FromDefault();

        var context = await RuntimeGrpcClientConnector.OpenAsync(
            new TestSplitHttpInternetOptions
            {
                ServerHost = "127.0.0.1",
                ServerPort = port,
                SecurityType = RuntimeInternetSecurityTypes.None,
                SplitHttpHost = "cdn.example.com",
                SplitHttpPath = " referer?route=1 ",
                SplitHttpMode = "stream-up",
                SplitHttpNoGrpcHeader = true,
                SplitHttpXPaddingKey = "ignored-key",
                SplitHttpXPaddingHeader = "X-Ignored",
                SplitHttpXPaddingPlacement = "header",
                SplitHttpXPaddingMethod = "tokenish"
            },
            RuntimeInternetStack.Create(RuntimeInternetTransportProtocols.SplitHttp, RuntimeInternetSecurityTypes.None),
            profile,
            SystemDnsResolver.Instance,
            transportInitializationData: null,
            lifetimeCts.Token);

        await using var applicationStream = context.ApplicationStream;
        await applicationStream.WriteAsync(Encoding.ASCII.GetBytes(clientPayload), lifetimeCts.Token);
        await applicationStream.FlushAsync(lifetimeCts.Token);

        var responseBuffer = new byte[serverPayload.Length];
        await ReadExactAsync(applicationStream, responseBuffer, lifetimeCts.Token);
        Assert.Equal(serverPayload, Encoding.ASCII.GetString(responseBuffer));

        var captured = await serverTask;
        Assert.False(captured.DownlinkRequest.Headers.ContainsKey("X-Ignored"));
        Assert.False(captured.UplinkRequest.Headers.ContainsKey("X-Ignored"));

        var downlinkReferer = new Uri(captured.DownlinkRequest.Headers["Referer"]);
        var uplinkReferer = new Uri(captured.UplinkRequest.Headers["Referer"]);
        Assert.Equal("http", downlinkReferer.Scheme);
        Assert.Equal("http", uplinkReferer.Scheme);
        Assert.Equal("cdn.example.com", downlinkReferer.Host);
        Assert.Equal("cdn.example.com", uplinkReferer.Host);
        Assert.Equal("/referer/", downlinkReferer.AbsolutePath);
        Assert.Equal("/referer/", uplinkReferer.AbsolutePath);
        Assert.DoesNotContain("route=1", downlinkReferer.Query, StringComparison.Ordinal);
        Assert.DoesNotContain("route=1", uplinkReferer.Query, StringComparison.Ordinal);

        var downlinkPadding = Assert.Single(ParseQuery(downlinkReferer.Query));
        var uplinkPadding = Assert.Single(ParseQuery(uplinkReferer.Query));
        Assert.Equal("x_padding", downlinkPadding.Key);
        Assert.Equal("x_padding", uplinkPadding.Key);
        Assert.InRange(downlinkPadding.Value.Length, 100, 1000);
        Assert.InRange(uplinkPadding.Value.Length, 100, 1000);
        Assert.All(downlinkPadding.Value, static ch => Assert.Equal('X', ch));
        Assert.All(uplinkPadding.Value, static ch => Assert.Equal('X', ch));

        var downlinkTarget = new Uri("http://split.local" + captured.DownlinkRequest.Target);
        var uplinkTarget = new Uri("http://split.local" + captured.UplinkRequest.Target);
        Assert.Equal("route=1", downlinkTarget.Query.TrimStart('?'));
        Assert.Equal("route=1", uplinkTarget.Query.TrimStart('?'));
    }

    [Fact]
    public async Task OpenAsync_stream_up_xpadding_header_obfs_sets_custom_header()
    {
        using var lifetimeCts = new CancellationTokenSource(TimeSpan.FromSeconds(10));
        using var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();

        const string clientPayload = "header-pad-client";
        const string serverPayload = "header-pad-server";
        var port = ((IPEndPoint)listener.LocalEndpoint).Port;
        var serverTask = CaptureSplitHttpExchangeAsync(
            listener,
            clientPayload,
            serverPayload,
            downlinkBodyMode: SplitHttpDownlinkBodyMode.Chunked,
            lifetimeCts.Token);
        var profile = RuntimeInternetProfile.FromDefault();

        var context = await RuntimeGrpcClientConnector.OpenAsync(
            new TestSplitHttpInternetOptions
            {
                ServerHost = "127.0.0.1",
                ServerPort = port,
                SecurityType = RuntimeInternetSecurityTypes.None,
                SplitHttpHost = "pad.example.com",
                SplitHttpPath = " header-pad?route=1 ",
                SplitHttpMode = "stream-up",
                SplitHttpNoGrpcHeader = true,
                SplitHttpXPaddingBytes = new RuntimeInt32Range
                {
                    From = 4,
                    To = 4
                },
                SplitHttpXPaddingObfsMode = true,
                SplitHttpXPaddingHeader = "X-Pad-Test",
                SplitHttpXPaddingPlacement = "header",
                SplitHttpXPaddingMethod = "repeat-x"
            },
            RuntimeInternetStack.Create(RuntimeInternetTransportProtocols.SplitHttp, RuntimeInternetSecurityTypes.None),
            profile,
            SystemDnsResolver.Instance,
            transportInitializationData: null,
            lifetimeCts.Token);

        await using var applicationStream = context.ApplicationStream;
        await applicationStream.WriteAsync(Encoding.ASCII.GetBytes(clientPayload), lifetimeCts.Token);
        await applicationStream.FlushAsync(lifetimeCts.Token);

        var responseBuffer = new byte[serverPayload.Length];
        await ReadExactAsync(applicationStream, responseBuffer, lifetimeCts.Token);
        Assert.Equal(serverPayload, Encoding.ASCII.GetString(responseBuffer));

        var captured = await serverTask;
        Assert.Equal("XXXX", captured.DownlinkRequest.Headers["X-Pad-Test"]);
        Assert.Equal("XXXX", captured.UplinkRequest.Headers["X-Pad-Test"]);
        Assert.False(captured.DownlinkRequest.Headers.ContainsKey("Referer"));
        Assert.False(captured.UplinkRequest.Headers.ContainsKey("Referer"));
    }

    [Fact]
    public async Task OpenAsync_stream_up_xpadding_header_tokenish_uses_base62_and_hpack_tolerance()
    {
        using var lifetimeCts = new CancellationTokenSource(TimeSpan.FromSeconds(10));
        using var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();

        const string clientPayload = "header-tokenish-client";
        const string serverPayload = "header-tokenish-server";
        var port = ((IPEndPoint)listener.LocalEndpoint).Port;
        var serverTask = CaptureSplitHttpExchangeAsync(
            listener,
            clientPayload,
            serverPayload,
            downlinkBodyMode: SplitHttpDownlinkBodyMode.Chunked,
            lifetimeCts.Token);
        var profile = RuntimeInternetProfile.FromDefault();

        var context = await RuntimeGrpcClientConnector.OpenAsync(
            new TestSplitHttpInternetOptions
            {
                ServerHost = "127.0.0.1",
                ServerPort = port,
                SecurityType = RuntimeInternetSecurityTypes.None,
                SplitHttpHost = "pad.example.com",
                SplitHttpPath = " header-tokenish?route=1 ",
                SplitHttpMode = "stream-up",
                SplitHttpNoGrpcHeader = true,
                SplitHttpXPaddingBytes = new RuntimeInt32Range
                {
                    From = 20,
                    To = 20
                },
                SplitHttpXPaddingObfsMode = true,
                SplitHttpXPaddingHeader = "X-Pad-Test",
                SplitHttpXPaddingPlacement = "header",
                SplitHttpXPaddingMethod = "tokenish"
            },
            RuntimeInternetStack.Create(RuntimeInternetTransportProtocols.SplitHttp, RuntimeInternetSecurityTypes.None),
            profile,
            SystemDnsResolver.Instance,
            transportInitializationData: null,
            lifetimeCts.Token);

        await using var applicationStream = context.ApplicationStream;
        await applicationStream.WriteAsync(Encoding.ASCII.GetBytes(clientPayload), lifetimeCts.Token);
        await applicationStream.FlushAsync(lifetimeCts.Token);

        var responseBuffer = new byte[serverPayload.Length];
        await ReadExactAsync(applicationStream, responseBuffer, lifetimeCts.Token);
        Assert.Equal(serverPayload, Encoding.ASCII.GetString(responseBuffer));

        var captured = await serverTask;
        var downlinkPadding = captured.DownlinkRequest.Headers["X-Pad-Test"];
        var uplinkPadding = captured.UplinkRequest.Headers["X-Pad-Test"];

        Assert.All(downlinkPadding, static ch => Assert.True(char.IsAsciiLetterOrDigit(ch)));
        Assert.All(uplinkPadding, static ch => Assert.True(char.IsAsciiLetterOrDigit(ch)));
        Assert.Contains(downlinkPadding, static ch => ch is not ('X' or 'Z'));
        Assert.Contains(uplinkPadding, static ch => ch is not ('X' or 'Z'));
        Assert.InRange(RuntimeHpackHuffman.GetBase62EncodedLength(downlinkPadding), 18, 22);
        Assert.InRange(RuntimeHpackHuffman.GetBase62EncodedLength(uplinkPadding), 18, 22);
        Assert.False(captured.DownlinkRequest.Headers.ContainsKey("Referer"));
        Assert.False(captured.UplinkRequest.Headers.ContainsKey("Referer"));
    }

    [Fact]
    public async Task OpenAsync_packet_up_xpadding_query_obfs_appends_padding_before_seq()
    {
        using var lifetimeCts = new CancellationTokenSource(TimeSpan.FromSeconds(10));
        using var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();

        const string clientPayload = "query-pad";
        var port = ((IPEndPoint)listener.LocalEndpoint).Port;
        var serverTask = CaptureSplitHttpPacketExchangeAsync(
            listener,
            serverPayload: "packet-down",
            expectedUploadPayloads: [clientPayload],
            lifetimeCts.Token);
        var profile = RuntimeInternetProfile.FromDefault();

        var context = await RuntimeGrpcClientConnector.OpenAsync(
            new TestSplitHttpInternetOptions
            {
                ServerHost = "127.0.0.1",
                ServerPort = port,
                SecurityType = RuntimeInternetSecurityTypes.None,
                SplitHttpPath = " query-pad?route=1 ",
                SplitHttpMode = "packet-up",
                SplitHttpSessionPlacement = "header",
                SplitHttpSeqPlacement = "query",
                SplitHttpXPaddingBytes = new RuntimeInt32Range
                {
                    From = 4,
                    To = 4
                },
                SplitHttpXPaddingObfsMode = true,
                SplitHttpXPaddingKey = "pad",
                SplitHttpXPaddingPlacement = "query"
            },
            RuntimeInternetStack.Create(RuntimeInternetTransportProtocols.SplitHttp, RuntimeInternetSecurityTypes.None),
            profile,
            SystemDnsResolver.Instance,
            transportInitializationData: null,
            lifetimeCts.Token);

        await using var applicationStream = context.ApplicationStream;
        await applicationStream.WriteAsync(Encoding.ASCII.GetBytes(clientPayload), lifetimeCts.Token);
        await applicationStream.FlushAsync(lifetimeCts.Token);

        var responseBuffer = new byte["packet-down".Length];
        await ReadExactAsync(applicationStream, responseBuffer, lifetimeCts.Token);
        Assert.Equal("packet-down", Encoding.ASCII.GetString(responseBuffer));

        var captured = await serverTask;
        Assert.Equal("/query-pad/?route=1&pad=XXXX", captured.DownlinkRequest.Target);
        var upload = Assert.Single(captured.UploadRequests);
        Assert.Equal("/query-pad/?route=1&pad=XXXX&x_seq=0", upload.Request.Target);
        Assert.Equal(clientPayload, upload.PayloadText);
    }

    [Fact]
    public async Task OpenAsync_packet_up_xpadding_cookie_obfs_appends_padding_before_session_and_seq()
    {
        using var lifetimeCts = new CancellationTokenSource(TimeSpan.FromSeconds(10));
        using var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();

        const string clientPayload = "cookie-pad";
        var port = ((IPEndPoint)listener.LocalEndpoint).Port;
        var serverTask = CaptureSplitHttpPacketExchangeAsync(
            listener,
            serverPayload: "packet-down",
            expectedUploadPayloads: [clientPayload],
            lifetimeCts.Token);
        var profile = RuntimeInternetProfile.FromDefault();

        var context = await RuntimeGrpcClientConnector.OpenAsync(
            new TestSplitHttpInternetOptions
            {
                ServerHost = "127.0.0.1",
                ServerPort = port,
                SecurityType = RuntimeInternetSecurityTypes.None,
                SplitHttpPath = " cookie-pad ",
                SplitHttpMode = "packet-up",
                SplitHttpSessionPlacement = "cookie",
                SplitHttpSeqPlacement = "cookie",
                SplitHttpXPaddingBytes = new RuntimeInt32Range
                {
                    From = 4,
                    To = 4
                },
                SplitHttpXPaddingObfsMode = true,
                SplitHttpXPaddingPlacement = "cookie",
                SplitHttpXPaddingMethod = "repeat-x"
            },
            RuntimeInternetStack.Create(RuntimeInternetTransportProtocols.SplitHttp, RuntimeInternetSecurityTypes.None),
            profile,
            SystemDnsResolver.Instance,
            transportInitializationData: null,
            lifetimeCts.Token);

        await using var applicationStream = context.ApplicationStream;
        await applicationStream.WriteAsync(Encoding.ASCII.GetBytes(clientPayload), lifetimeCts.Token);
        await applicationStream.FlushAsync(lifetimeCts.Token);

        var responseBuffer = new byte["packet-down".Length];
        await ReadExactAsync(applicationStream, responseBuffer, lifetimeCts.Token);
        Assert.Equal("packet-down", Encoding.ASCII.GetString(responseBuffer));

        var captured = await serverTask;
        var upload = Assert.Single(captured.UploadRequests);
        Assert.StartsWith("x_padding=XXXX; x_session=", captured.DownlinkRequest.Headers["Cookie"]);
        Assert.StartsWith("x_padding=XXXX; x_session=", upload.Request.Headers["Cookie"]);
        Assert.Contains("; x_seq=0", upload.Request.Headers["Cookie"], StringComparison.Ordinal);

        var downlinkCookies = ParseCookies(captured.DownlinkRequest.Headers["Cookie"]);
        var uploadCookies = ParseCookies(upload.Request.Headers["Cookie"]);
        Assert.Equal("XXXX", downlinkCookies["x_padding"]);
        Assert.Equal("XXXX", uploadCookies["x_padding"]);
        Assert.True(Guid.TryParse(downlinkCookies["x_session"], out _));
        Assert.Equal(downlinkCookies["x_session"], uploadCookies["x_session"]);
        Assert.Equal("0", uploadCookies["x_seq"]);
    }

    [Fact]
    public async Task OpenAsync_stream_up_xpadding_query_in_header_obfs_sets_absolute_url_header()
    {
        using var lifetimeCts = new CancellationTokenSource(TimeSpan.FromSeconds(10));
        using var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();

        const string clientPayload = "url-pad-client";
        const string serverPayload = "url-pad-server";
        var port = ((IPEndPoint)listener.LocalEndpoint).Port;
        var serverTask = CaptureSplitHttpExchangeAsync(
            listener,
            clientPayload,
            serverPayload,
            downlinkBodyMode: SplitHttpDownlinkBodyMode.Chunked,
            lifetimeCts.Token);
        var profile = RuntimeInternetProfile.FromDefault();

        var context = await RuntimeGrpcClientConnector.OpenAsync(
            new TestSplitHttpInternetOptions
            {
                ServerHost = "127.0.0.1",
                ServerPort = port,
                SecurityType = RuntimeInternetSecurityTypes.None,
                SplitHttpHost = "pad.example.com",
                SplitHttpPath = " url-pad?route=1 ",
                SplitHttpMode = "stream-up",
                SplitHttpNoGrpcHeader = true,
                SplitHttpXPaddingBytes = new RuntimeInt32Range
                {
                    From = 6,
                    To = 6
                },
                SplitHttpXPaddingObfsMode = true,
                SplitHttpXPaddingKey = "pad",
                SplitHttpXPaddingHeader = "X-Pad-Url",
                SplitHttpXPaddingPlacement = "queryInHeader"
            },
            RuntimeInternetStack.Create(RuntimeInternetTransportProtocols.SplitHttp, RuntimeInternetSecurityTypes.None),
            profile,
            SystemDnsResolver.Instance,
            transportInitializationData: null,
            lifetimeCts.Token);

        await using var applicationStream = context.ApplicationStream;
        await applicationStream.WriteAsync(Encoding.ASCII.GetBytes(clientPayload), lifetimeCts.Token);
        await applicationStream.FlushAsync(lifetimeCts.Token);

        var responseBuffer = new byte[serverPayload.Length];
        await ReadExactAsync(applicationStream, responseBuffer, lifetimeCts.Token);
        Assert.Equal(serverPayload, Encoding.ASCII.GetString(responseBuffer));

        var captured = await serverTask;
        Assert.Equal("http://pad.example.com/url-pad/?pad=XXXXXX", captured.DownlinkRequest.Headers["X-Pad-Url"]);
        Assert.Equal("http://pad.example.com/url-pad/?pad=XXXXXX", captured.UplinkRequest.Headers["X-Pad-Url"]);
        Assert.Equal("route=1", new Uri("http://split.local" + captured.DownlinkRequest.Target).Query.TrimStart('?'));
        Assert.Equal("route=1", new Uri("http://split.local" + captured.UplinkRequest.Target).Query.TrimStart('?'));
    }

    [Fact]
    public async Task OpenAsync_auto_mode_uses_packet_up_and_sends_sequenced_upload_requests()
    {
        using var lifetimeCts = new CancellationTokenSource(TimeSpan.FromSeconds(10));
        using var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();

        var port = ((IPEndPoint)listener.LocalEndpoint).Port;
        var serverTask = CaptureSplitHttpPacketExchangeAsync(
            listener,
            serverPayload: "packet-down",
            expectedUploadPayloads: ["first-packet", "second-packet"],
            lifetimeCts.Token);
        var profile = RuntimeInternetProfile.FromDefault();

        var context = await RuntimeGrpcClientConnector.OpenAsync(
            new TestSplitHttpInternetOptions
            {
                ServerHost = "127.0.0.1",
                ServerPort = port,
                SecurityType = RuntimeInternetSecurityTypes.None,
                SplitHttpPath = " packet?route=1 ",
                SplitHttpHeaders = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
                {
                    ["X-Trace"] = "packet"
                },
                SplitHttpMode = "auto",
                SplitHttpSessionPlacement = "header",
                SplitHttpSessionKey = "X-Session-Custom",
                SplitHttpSeqPlacement = "query",
                SplitHttpScMaxEachPostBytes = new RuntimeInt32Range
                {
                    From = 13,
                    To = 13
                }
            },
            RuntimeInternetStack.Create(RuntimeInternetTransportProtocols.SplitHttp, RuntimeInternetSecurityTypes.None),
            profile,
            SystemDnsResolver.Instance,
            transportInitializationData: null,
            lifetimeCts.Token);

        await using var applicationStream = context.ApplicationStream;
        await applicationStream.WriteAsync(Encoding.ASCII.GetBytes("first-packet"), lifetimeCts.Token);
        await applicationStream.FlushAsync(lifetimeCts.Token);
        await applicationStream.WriteAsync(Encoding.ASCII.GetBytes("second-packet"), lifetimeCts.Token);
        await applicationStream.FlushAsync(lifetimeCts.Token);

        var responseBuffer = new byte["packet-down".Length];
        await ReadExactAsync(applicationStream, responseBuffer, lifetimeCts.Token);
        Assert.Equal("packet-down", Encoding.ASCII.GetString(responseBuffer));

        var eofBuffer = new byte[1];
        var eofRead = await applicationStream.ReadAsync(eofBuffer, lifetimeCts.Token);
        Assert.Equal(0, eofRead);

        var captured = await serverTask;
        Assert.Equal("GET", captured.DownlinkRequest.Method);
        Assert.Equal("/packet/?route=1", captured.DownlinkRequest.Target);
        Assert.Equal("packet", captured.DownlinkRequest.Headers["X-Trace"]);

        var sessionId = captured.DownlinkRequest.Headers["X-Session-Custom"];
        Assert.True(Guid.TryParse(sessionId, out _));
        Assert.Equal(2, captured.UploadRequests.Count);

        Assert.Equal("POST", captured.UploadRequests[0].Request.Method);
        Assert.Equal("POST", captured.UploadRequests[1].Request.Method);
        Assert.Equal("packet", captured.UploadRequests[0].Request.Headers["X-Trace"]);
        Assert.Equal("packet", captured.UploadRequests[1].Request.Headers["X-Trace"]);
        Assert.Equal(sessionId, captured.UploadRequests[0].Request.Headers["X-Session-Custom"]);
        Assert.Equal(sessionId, captured.UploadRequests[1].Request.Headers["X-Session-Custom"]);
        Assert.False(captured.UploadRequests[0].Request.Headers.ContainsKey("Content-Type"));
        Assert.False(captured.UploadRequests[1].Request.Headers.ContainsKey("Content-Type"));
        Assert.Equal("first-packet", captured.UploadRequests[0].PayloadText);
        Assert.Equal("second-packet", captured.UploadRequests[1].PayloadText);

        var firstTarget = new Uri("http://split.local" + captured.UploadRequests[0].Request.Target);
        var secondTarget = new Uri("http://split.local" + captured.UploadRequests[1].Request.Target);
        Assert.Equal("route=1&x_seq=0", firstTarget.Query.TrimStart('?'));
        Assert.Equal("route=1&x_seq=1", secondTarget.Query.TrimStart('?'));
    }

    [Fact]
    public async Task OpenAsync_packet_up_batches_multiple_writes_when_post_capacity_allows()
    {
        using var lifetimeCts = new CancellationTokenSource(TimeSpan.FromSeconds(10));
        using var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();

        var port = ((IPEndPoint)listener.LocalEndpoint).Port;
        var serverTask = CaptureSplitHttpPacketExchangeAsync(
            listener,
            serverPayload: "packet-down",
            expectedUploadPayloads: ["first-packetsecond-packet"],
            lifetimeCts.Token);
        var profile = RuntimeInternetProfile.FromDefault();

        var context = await RuntimeGrpcClientConnector.OpenAsync(
            new TestSplitHttpInternetOptions
            {
                ServerHost = "127.0.0.1",
                ServerPort = port,
                SecurityType = RuntimeInternetSecurityTypes.None,
                SplitHttpPath = " batch?route=1 ",
                SplitHttpMode = "packet-up",
                SplitHttpSessionPlacement = "header",
                SplitHttpScMaxEachPostBytes = new RuntimeInt32Range
                {
                    From = 64,
                    To = 64
                }
            },
            RuntimeInternetStack.Create(RuntimeInternetTransportProtocols.SplitHttp, RuntimeInternetSecurityTypes.None),
            profile,
            SystemDnsResolver.Instance,
            transportInitializationData: null,
            lifetimeCts.Token);

        await using var applicationStream = context.ApplicationStream;
        await applicationStream.WriteAsync(Encoding.ASCII.GetBytes("first-packet"), lifetimeCts.Token);
        await applicationStream.WriteAsync(Encoding.ASCII.GetBytes("second-packet"), lifetimeCts.Token);

        var responseBuffer = new byte["packet-down".Length];
        await ReadExactAsync(applicationStream, responseBuffer, lifetimeCts.Token);
        Assert.Equal("packet-down", Encoding.ASCII.GetString(responseBuffer));

        var captured = await serverTask;
        var upload = Assert.Single(captured.UploadRequests);
        Assert.Equal("first-packetsecond-packet", upload.PayloadText);
        Assert.Equal("POST", upload.Request.Method);
        var uploadTarget = new Uri("http://split.local" + upload.Request.Target);
        Assert.Equal("route=1", uploadTarget.Query.TrimStart('?'));
    }

    [Fact]
    public async Task OpenAsync_packet_up_splits_large_write_by_sc_max_each_post_bytes()
    {
        using var lifetimeCts = new CancellationTokenSource(TimeSpan.FromSeconds(10));
        using var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();

        const string clientPayload = "abcdefghijkl";
        var port = ((IPEndPoint)listener.LocalEndpoint).Port;
        var serverTask = CaptureSplitHttpPacketExchangeAsync(
            listener,
            serverPayload: "packet-down",
            expectedUploadPayloads: ["abcdef", "ghijkl"],
            lifetimeCts.Token);
        var profile = RuntimeInternetProfile.FromDefault();

        var context = await RuntimeGrpcClientConnector.OpenAsync(
            new TestSplitHttpInternetOptions
            {
                ServerHost = "127.0.0.1",
                ServerPort = port,
                SecurityType = RuntimeInternetSecurityTypes.None,
                SplitHttpPath = " split?route=1 ",
                SplitHttpMode = "packet-up",
                SplitHttpSeqPlacement = "query",
                SplitHttpScMaxEachPostBytes = new RuntimeInt32Range
                {
                    From = 6,
                    To = 6
                }
            },
            RuntimeInternetStack.Create(RuntimeInternetTransportProtocols.SplitHttp, RuntimeInternetSecurityTypes.None),
            profile,
            SystemDnsResolver.Instance,
            transportInitializationData: null,
            lifetimeCts.Token);

        await using var applicationStream = context.ApplicationStream;
        await applicationStream.WriteAsync(Encoding.ASCII.GetBytes(clientPayload), lifetimeCts.Token);

        var responseBuffer = new byte["packet-down".Length];
        await ReadExactAsync(applicationStream, responseBuffer, lifetimeCts.Token);
        Assert.Equal("packet-down", Encoding.ASCII.GetString(responseBuffer));

        var captured = await serverTask;
        Assert.Equal(2, captured.UploadRequests.Count);
        Assert.Equal("abcdef", captured.UploadRequests[0].PayloadText);
        Assert.Equal("ghijkl", captured.UploadRequests[1].PayloadText);

        var firstTarget = new Uri("http://split.local" + captured.UploadRequests[0].Request.Target);
        var secondTarget = new Uri("http://split.local" + captured.UploadRequests[1].Request.Target);
        Assert.Equal("route=1&x_seq=0", firstTarget.Query.TrimStart('?'));
        Assert.Equal("route=1&x_seq=1", secondTarget.Query.TrimStart('?'));
    }

    [Fact]
    public async Task OpenAsync_packet_up_honors_min_post_interval_between_split_uploads()
    {
        using var lifetimeCts = new CancellationTokenSource(TimeSpan.FromSeconds(10));
        using var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();

        const string clientPayload = "abcdefghijkl";
        var port = ((IPEndPoint)listener.LocalEndpoint).Port;
        var serverTask = CaptureSplitHttpPacketExchangeAsync(
            listener,
            serverPayload: "packet-down",
            expectedUploadPayloads: ["abcdef", "ghijkl"],
            lifetimeCts.Token);
        var profile = RuntimeInternetProfile.FromDefault();

        var context = await RuntimeGrpcClientConnector.OpenAsync(
            new TestSplitHttpInternetOptions
            {
                ServerHost = "127.0.0.1",
                ServerPort = port,
                SecurityType = RuntimeInternetSecurityTypes.None,
                SplitHttpPath = " interval?route=1 ",
                SplitHttpMode = "packet-up",
                SplitHttpScMaxEachPostBytes = new RuntimeInt32Range
                {
                    From = 6,
                    To = 6
                },
                SplitHttpScMinPostsIntervalMs = new RuntimeInt32Range
                {
                    From = 150,
                    To = 150
                }
            },
            RuntimeInternetStack.Create(RuntimeInternetTransportProtocols.SplitHttp, RuntimeInternetSecurityTypes.None),
            profile,
            SystemDnsResolver.Instance,
            transportInitializationData: null,
            lifetimeCts.Token);

        await using var applicationStream = context.ApplicationStream;
        await applicationStream.WriteAsync(Encoding.ASCII.GetBytes(clientPayload), lifetimeCts.Token);

        var responseBuffer = new byte["packet-down".Length];
        await ReadExactAsync(applicationStream, responseBuffer, lifetimeCts.Token);
        Assert.Equal("packet-down", Encoding.ASCII.GetString(responseBuffer));

        var captured = await serverTask;
        Assert.Equal(2, captured.UploadRequests.Count);
        var observedInterval = captured.UploadRequests[1].ReceivedAtUtc - captured.UploadRequests[0].ReceivedAtUtc;
        Assert.True(
            observedInterval >= TimeSpan.FromMilliseconds(100),
            $"Expected at least 100ms between uploads, but observed {observedInterval.TotalMilliseconds:F0}ms.");
    }

    [Fact]
    public async Task OpenAsync_packet_up_reuses_h1_upload_connection_when_server_keeps_it_alive()
    {
        using var lifetimeCts = new CancellationTokenSource(TimeSpan.FromSeconds(10));
        using var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();

        const string clientPayload = "abcdefghijkl";
        var port = ((IPEndPoint)listener.LocalEndpoint).Port;
        var serverTask = CaptureSplitHttpPersistentPacketExchangeAsync(
            listener,
            serverPayload: "packet-down",
            expectedUploadPayloads: ["abcdef", "ghijkl"],
            lifetimeCts.Token);
        var profile = RuntimeInternetProfile.FromDefault();

        var context = await RuntimeGrpcClientConnector.OpenAsync(
            new TestSplitHttpInternetOptions
            {
                ServerHost = "127.0.0.1",
                ServerPort = port,
                SecurityType = RuntimeInternetSecurityTypes.None,
                SplitHttpPath = " reuse?route=1 ",
                SplitHttpMode = "packet-up",
                SplitHttpSeqPlacement = "query",
                SplitHttpScMaxEachPostBytes = new RuntimeInt32Range
                {
                    From = 6,
                    To = 6
                }
            },
            RuntimeInternetStack.Create(RuntimeInternetTransportProtocols.SplitHttp, RuntimeInternetSecurityTypes.None),
            profile,
            SystemDnsResolver.Instance,
            transportInitializationData: null,
            lifetimeCts.Token);

        await using var applicationStream = context.ApplicationStream;
        await applicationStream.WriteAsync(Encoding.ASCII.GetBytes(clientPayload), lifetimeCts.Token);

        var responseBuffer = new byte["packet-down".Length];
        await ReadExactAsync(applicationStream, responseBuffer, lifetimeCts.Token);
        Assert.Equal("packet-down", Encoding.ASCII.GetString(responseBuffer));

        var captured = await serverTask;
        Assert.Equal(1, captured.UploadConnectionCount);
        Assert.Equal(2, captured.UploadRequests.Count);
        Assert.Equal("abcdef", captured.UploadRequests[0].PayloadText);
        Assert.Equal("ghijkl", captured.UploadRequests[1].PayloadText);
    }

    [Fact]
    public async Task OpenAsync_packet_up_over_h1_sends_second_upload_before_first_upload_response_completes()
    {
        using var lifetimeCts = new CancellationTokenSource(TimeSpan.FromSeconds(10));
        using var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();

        const string clientPayload = "abcdefghijkl";
        var port = ((IPEndPoint)listener.LocalEndpoint).Port;
        var serverTask = CaptureSplitHttpPersistentPacketExchangeWithDelayedFirstUploadResponseAsync(
            listener,
            serverPayload: "packet-down",
            expectedUploadPayloads: ["abcdef", "ghijkl"],
            lifetimeCts.Token);
        var profile = RuntimeInternetProfile.FromDefault();

        var context = await RuntimeGrpcClientConnector.OpenAsync(
            new TestSplitHttpInternetOptions
            {
                ServerHost = "127.0.0.1",
                ServerPort = port,
                SecurityType = RuntimeInternetSecurityTypes.None,
                SplitHttpPath = " reuse-delayed?route=1 ",
                SplitHttpMode = "packet-up",
                SplitHttpSeqPlacement = "query",
                SplitHttpScMaxEachPostBytes = new RuntimeInt32Range
                {
                    From = 6,
                    To = 6
                }
            },
            RuntimeInternetStack.Create(RuntimeInternetTransportProtocols.SplitHttp, RuntimeInternetSecurityTypes.None),
            profile,
            SystemDnsResolver.Instance,
            transportInitializationData: null,
            lifetimeCts.Token);

        await using var applicationStream = context.ApplicationStream;
        await applicationStream.WriteAsync(Encoding.ASCII.GetBytes(clientPayload), lifetimeCts.Token);
        await applicationStream.FlushAsync(lifetimeCts.Token);

        var responseBuffer = new byte["packet-down".Length];
        await ReadExactAsync(applicationStream, responseBuffer, lifetimeCts.Token);
        Assert.Equal("packet-down", Encoding.ASCII.GetString(responseBuffer));

        var captured = await serverTask;
        Assert.Equal(1, captured.UploadConnectionCount);
        Assert.Equal(2, captured.UploadRequests.Count);
        Assert.Equal("abcdef", captured.UploadRequests[0].PayloadText);
        Assert.Equal("ghijkl", captured.UploadRequests[1].PayloadText);
    }

    [Fact]
    public async Task OpenAsync_packet_up_reuses_h1_upload_connection_across_sessions_when_server_keeps_it_alive()
    {
        using var lifetimeCts = new CancellationTokenSource(TimeSpan.FromSeconds(10));
        using var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();

        var port = ((IPEndPoint)listener.LocalEndpoint).Port;
        var serverTask = CaptureSplitHttpPersistentPacketExchangeAcrossSessionsAsync(
            listener,
            serverPayloads: ["packet-down-1", "packet-down-2"],
            expectedUploadPayloads: ["first-packet", "second-packet"],
            lifetimeCts.Token);
        var profile = RuntimeInternetProfile.FromDefault();
        var options = new TestSplitHttpInternetOptions
        {
            ServerHost = "127.0.0.1",
            ServerPort = port,
            SecurityType = RuntimeInternetSecurityTypes.None,
            SplitHttpPath = " reuse-global?route=1 ",
            SplitHttpMode = "packet-up",
            SplitHttpSeqPlacement = "query",
            SplitHttpScMaxEachPostBytes = new RuntimeInt32Range
            {
                From = 64,
                To = 64
            }
        };
        var stack = RuntimeInternetStack.Create(
            RuntimeInternetTransportProtocols.SplitHttp,
            RuntimeInternetSecurityTypes.None);

        var context1 = await RuntimeGrpcClientConnector.OpenAsync(
            options,
            stack,
            profile,
            SystemDnsResolver.Instance,
            transportInitializationData: null,
            lifetimeCts.Token);
        await using (var applicationStream1 = context1.ApplicationStream)
        {
            await applicationStream1.WriteAsync(Encoding.ASCII.GetBytes("first-packet"), lifetimeCts.Token);
            await applicationStream1.FlushAsync(lifetimeCts.Token);

            var responseBuffer = new byte["packet-down-1".Length];
            await ReadExactAsync(applicationStream1, responseBuffer, lifetimeCts.Token);
            Assert.Equal("packet-down-1", Encoding.ASCII.GetString(responseBuffer));

            var eofBuffer = new byte[1];
            var eofRead = await applicationStream1.ReadAsync(eofBuffer, lifetimeCts.Token);
            Assert.Equal(0, eofRead);
        }

        var context2 = await RuntimeGrpcClientConnector.OpenAsync(
            options,
            stack,
            profile,
            SystemDnsResolver.Instance,
            transportInitializationData: null,
            lifetimeCts.Token);
        await using (var applicationStream2 = context2.ApplicationStream)
        {
            await applicationStream2.WriteAsync(Encoding.ASCII.GetBytes("second-packet"), lifetimeCts.Token);
            await applicationStream2.FlushAsync(lifetimeCts.Token);

            var responseBuffer = new byte["packet-down-2".Length];
            await ReadExactAsync(applicationStream2, responseBuffer, lifetimeCts.Token);
            Assert.Equal("packet-down-2", Encoding.ASCII.GetString(responseBuffer));

            var eofBuffer = new byte[1];
            var eofRead = await applicationStream2.ReadAsync(eofBuffer, lifetimeCts.Token);
            Assert.Equal(0, eofRead);
        }

        var captured = await serverTask;
        Assert.Equal(1, captured.UploadConnectionCount);
        Assert.Equal(2, captured.DownlinkRequests.Count);
        Assert.Equal(2, captured.UploadRequests.Count);
        Assert.StartsWith("/reuse-global/", captured.DownlinkRequests[0].Target, StringComparison.Ordinal);
        Assert.StartsWith("/reuse-global/", captured.DownlinkRequests[1].Target, StringComparison.Ordinal);
        Assert.Equal("first-packet", captured.UploadRequests[0].PayloadText);
        Assert.Equal("second-packet", captured.UploadRequests[1].PayloadText);
    }

    [Fact]
    public async Task OpenAsync_packet_up_xmux_max_connections_prefers_distinct_upload_connections_across_sessions()
    {
        using var lifetimeCts = new CancellationTokenSource(TimeSpan.FromSeconds(10));
        using var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();

        var port = ((IPEndPoint)listener.LocalEndpoint).Port;
        var serverTask = CaptureSplitHttpPacketExchangeAcrossSessionsAsync(
            listener,
            serverPayloads: ["packet-down-1", "packet-down-2"],
            expectedUploadPayloads: ["first-packet", "second-packet"],
            uploadConnectionPattern: [0, 1],
            lifetimeCts.Token);
        var profile = RuntimeInternetProfile.FromDefault();
        var options = new TestSplitHttpInternetOptions
        {
            ServerHost = "127.0.0.1",
            ServerPort = port,
            SecurityType = RuntimeInternetSecurityTypes.None,
            SplitHttpPath = " xmux-max-connections?route=1 ",
            SplitHttpMode = "packet-up",
            SplitHttpSeqPlacement = "query",
            SplitHttpScMaxEachPostBytes = new RuntimeInt32Range
            {
                From = 64,
                To = 64
            },
            SplitHttpXmux = new RuntimeSplitHttpXmuxOptions
            {
                MaxConnections = new RuntimeInt32Range
                {
                    From = 2,
                    To = 2
                }
            }
        };
        var stack = RuntimeInternetStack.Create(
            RuntimeInternetTransportProtocols.SplitHttp,
            RuntimeInternetSecurityTypes.None);

        var context1 = await RuntimeGrpcClientConnector.OpenAsync(
            options,
            stack,
            profile,
            SystemDnsResolver.Instance,
            transportInitializationData: null,
            lifetimeCts.Token);
        await using (var applicationStream1 = context1.ApplicationStream)
        {
            await applicationStream1.WriteAsync(Encoding.ASCII.GetBytes("first-packet"), lifetimeCts.Token);
            await applicationStream1.FlushAsync(lifetimeCts.Token);

            var responseBuffer = new byte["packet-down-1".Length];
            await ReadExactAsync(applicationStream1, responseBuffer, lifetimeCts.Token);
            Assert.Equal("packet-down-1", Encoding.ASCII.GetString(responseBuffer));

            var eofBuffer = new byte[1];
            var eofRead = await applicationStream1.ReadAsync(eofBuffer, lifetimeCts.Token);
            Assert.Equal(0, eofRead);
        }

        var context2 = await RuntimeGrpcClientConnector.OpenAsync(
            options,
            stack,
            profile,
            SystemDnsResolver.Instance,
            transportInitializationData: null,
            lifetimeCts.Token);
        await using (var applicationStream2 = context2.ApplicationStream)
        {
            await applicationStream2.WriteAsync(Encoding.ASCII.GetBytes("second-packet"), lifetimeCts.Token);
            await applicationStream2.FlushAsync(lifetimeCts.Token);

            var responseBuffer = new byte["packet-down-2".Length];
            await ReadExactAsync(applicationStream2, responseBuffer, lifetimeCts.Token);
            Assert.Equal("packet-down-2", Encoding.ASCII.GetString(responseBuffer));

            var eofBuffer = new byte[1];
            var eofRead = await applicationStream2.ReadAsync(eofBuffer, lifetimeCts.Token);
            Assert.Equal(0, eofRead);
        }

        var captured = await serverTask;
        Assert.Equal(2, captured.UploadConnectionCount);
        Assert.Equal(2, captured.UploadRequests.Count);
    }

    [Fact]
    public async Task OpenAsync_packet_up_xmux_cmax_reuse_times_rotates_upload_pool_after_reuse_budget()
    {
        using var lifetimeCts = new CancellationTokenSource(TimeSpan.FromSeconds(10));
        using var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();

        var port = ((IPEndPoint)listener.LocalEndpoint).Port;
        var serverTask = CaptureSplitHttpPacketExchangeAcrossSessionsAsync(
            listener,
            serverPayloads: ["packet-down-1", "packet-down-2", "packet-down-3"],
            expectedUploadPayloads: ["first-packet", "second-packet", "third-packet"],
            uploadConnectionPattern: [0, 0, 1],
            lifetimeCts.Token);
        var profile = RuntimeInternetProfile.FromDefault();
        var options = new TestSplitHttpInternetOptions
        {
            ServerHost = "127.0.0.1",
            ServerPort = port,
            SecurityType = RuntimeInternetSecurityTypes.None,
            SplitHttpPath = " xmux-cmax-reuse?route=1 ",
            SplitHttpMode = "packet-up",
            SplitHttpSeqPlacement = "query",
            SplitHttpScMaxEachPostBytes = new RuntimeInt32Range
            {
                From = 64,
                To = 64
            },
            SplitHttpXmux = new RuntimeSplitHttpXmuxOptions
            {
                CMaxReuseTimes = new RuntimeInt32Range
                {
                    From = 2,
                    To = 2
                }
            }
        };
        var stack = RuntimeInternetStack.Create(
            RuntimeInternetTransportProtocols.SplitHttp,
            RuntimeInternetSecurityTypes.None);

        foreach (var (payload, responseText) in new[]
                 {
                     ("first-packet", "packet-down-1"),
                     ("second-packet", "packet-down-2"),
                     ("third-packet", "packet-down-3")
                 })
        {
            var context = await RuntimeGrpcClientConnector.OpenAsync(
                options,
                stack,
                profile,
                SystemDnsResolver.Instance,
                transportInitializationData: null,
                lifetimeCts.Token);
            await using var applicationStream = context.ApplicationStream;
            await applicationStream.WriteAsync(Encoding.ASCII.GetBytes(payload), lifetimeCts.Token);
            await applicationStream.FlushAsync(lifetimeCts.Token);

            var responseBuffer = new byte[responseText.Length];
            await ReadExactAsync(applicationStream, responseBuffer, lifetimeCts.Token);
            Assert.Equal(responseText, Encoding.ASCII.GetString(responseBuffer));

            var eofBuffer = new byte[1];
            var eofRead = await applicationStream.ReadAsync(eofBuffer, lifetimeCts.Token);
            Assert.Equal(0, eofRead);
        }

        var captured = await serverTask;
        Assert.Equal(2, captured.UploadConnectionCount);
        Assert.Equal(3, captured.UploadRequests.Count);
        Assert.Equal("first-packet", captured.UploadRequests[0].PayloadText);
        Assert.Equal("second-packet", captured.UploadRequests[1].PayloadText);
        Assert.Equal("third-packet", captured.UploadRequests[2].PayloadText);
    }

    [Fact]
    public async Task OpenAsync_packet_up_xmux_hmax_request_times_rotates_upload_connection_within_session()
    {
        using var lifetimeCts = new CancellationTokenSource(TimeSpan.FromSeconds(10));
        using var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();

        const string clientPayload = "abcdefghijkl";
        var port = ((IPEndPoint)listener.LocalEndpoint).Port;
        var serverTask = CaptureSplitHttpPacketExchangeAsync(
            listener,
            serverPayload: "packet-down",
            expectedUploadPayloads: ["abcdef", "ghijkl"],
            uploadConnectionPattern: [0, 1],
            lifetimeCts.Token);
        var profile = RuntimeInternetProfile.FromDefault();

        var context = await RuntimeGrpcClientConnector.OpenAsync(
            new TestSplitHttpInternetOptions
            {
                ServerHost = "127.0.0.1",
                ServerPort = port,
                SecurityType = RuntimeInternetSecurityTypes.None,
                SplitHttpPath = " xmux-hmax-requests?route=1 ",
                SplitHttpMode = "packet-up",
                SplitHttpSeqPlacement = "query",
                SplitHttpScMaxEachPostBytes = new RuntimeInt32Range
                {
                    From = 6,
                    To = 6
                },
                SplitHttpXmux = new RuntimeSplitHttpXmuxOptions
                {
                    HMaxRequestTimes = new RuntimeInt32Range
                    {
                        From = 1,
                        To = 1
                    }
                }
            },
            RuntimeInternetStack.Create(RuntimeInternetTransportProtocols.SplitHttp, RuntimeInternetSecurityTypes.None),
            profile,
            SystemDnsResolver.Instance,
            transportInitializationData: null,
            lifetimeCts.Token);

        await using var applicationStream = context.ApplicationStream;
        await applicationStream.WriteAsync(Encoding.ASCII.GetBytes(clientPayload), lifetimeCts.Token);

        var responseBuffer = new byte["packet-down".Length];
        await ReadExactAsync(applicationStream, responseBuffer, lifetimeCts.Token);
        Assert.Equal("packet-down", Encoding.ASCII.GetString(responseBuffer));

        var captured = await serverTask;
        Assert.Equal(2, captured.UploadConnectionCount);
        Assert.Equal(2, captured.UploadRequests.Count);
        Assert.Equal("abcdef", captured.UploadRequests[0].PayloadText);
        Assert.Equal("ghijkl", captured.UploadRequests[1].PayloadText);
    }

    [Fact]
    public async Task OpenAsync_packet_up_over_default_tls_reuses_single_upload_connection_with_multiple_streams()
    {
        using var lifetimeCts = new CancellationTokenSource(TimeSpan.FromSeconds(10));
        using var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();

        const string clientPayload = "abcdefghijkl";
        var port = ((IPEndPoint)listener.LocalEndpoint).Port;
        var serverTask = CaptureSplitHttpHttp2PacketExchangeAsync(
            listener,
            serverPayload: "packet-down",
            expectedUploadPayloads: ["abcdef", "ghijkl"],
            cancellationToken: lifetimeCts.Token);
        var tlsSecurityFactory = new TestRuntimeInternetProfileFactory.RecordingFakeTlsSecurityFactory("h2");
        var profile = TestRuntimeInternetProfileFactory.CreateWithFakeTls(tlsSecurityFactory);

        var context = await RuntimeGrpcClientConnector.OpenAsync(
            new TestSplitHttpInternetOptions
            {
                ServerHost = "127.0.0.1",
                ServerPort = port,
                ServerName = "edge.example.com",
                SecurityType = RuntimeInternetSecurityTypes.Tls,
                SplitHttpPath = " packet-default-h2?route=1 ",
                SplitHttpMode = "packet-up",
                SplitHttpSeqPlacement = "query",
                SplitHttpScMaxEachPostBytes = new RuntimeInt32Range
                {
                    From = 6,
                    To = 6
                }
            },
            RuntimeInternetStack.Create(RuntimeInternetTransportProtocols.SplitHttp, RuntimeInternetSecurityTypes.Tls),
            profile,
            SystemDnsResolver.Instance,
            transportInitializationData: null,
            lifetimeCts.Token);

        await using var applicationStream = context.ApplicationStream;
        await applicationStream.WriteAsync(Encoding.ASCII.GetBytes(clientPayload), lifetimeCts.Token);
        await applicationStream.FlushAsync(lifetimeCts.Token);

        var responseBuffer = new byte["packet-down".Length];
        await ReadExactAsync(applicationStream, responseBuffer, lifetimeCts.Token);
        Assert.Equal("packet-down", Encoding.ASCII.GetString(responseBuffer));

        var eofBuffer = new byte[1];
        var eofRead = await applicationStream.ReadAsync(eofBuffer, lifetimeCts.Token);
        Assert.Equal(0, eofRead);

        var captured = await serverTask;
        Assert.Equal("GET", captured.DownlinkRequest.Method);
        Assert.Equal("edge.example.com", captured.DownlinkRequest.Headers[":authority"]);
        Assert.Equal("https", captured.DownlinkRequest.Headers[":scheme"]);
        Assert.Equal(1, captured.UploadConnectionCount);
        Assert.Equal(2, captured.UploadRequests.Count);
        Assert.Equal("POST", captured.UploadRequests[0].Request.Method);
        Assert.Equal("POST", captured.UploadRequests[1].Request.Method);
        Assert.Equal("abcdef", captured.UploadRequests[0].PayloadText);
        Assert.Equal("ghijkl", captured.UploadRequests[1].PayloadText);
        Assert.Equal(["h2", "http/1.1"], tlsSecurityFactory.ObservedApplicationProtocols);
        Assert.Equal("h2", tlsSecurityFactory.NegotiatedApplicationProtocol);

        var downlinkTarget = new Uri("http://split.local" + captured.DownlinkRequest.Target);
        Assert.Equal("route=1", downlinkTarget.Query.TrimStart('?'));

        var downlinkSegments = downlinkTarget.AbsolutePath.Split('/', StringSplitOptions.RemoveEmptyEntries);
        Assert.Equal("packet-default-h2", downlinkSegments[0]);
        Assert.True(Guid.TryParse(Uri.UnescapeDataString(downlinkSegments[1]), out _));
        var sessionId = Uri.UnescapeDataString(downlinkSegments[1]);

        var firstUploadTarget = new Uri("http://split.local" + captured.UploadRequests[0].Request.Target);
        var secondUploadTarget = new Uri("http://split.local" + captured.UploadRequests[1].Request.Target);
        Assert.Equal("route=1&x_seq=0", firstUploadTarget.Query.TrimStart('?'));
        Assert.Equal("route=1&x_seq=1", secondUploadTarget.Query.TrimStart('?'));

        var firstUploadSegments = firstUploadTarget.AbsolutePath.Split('/', StringSplitOptions.RemoveEmptyEntries);
        var secondUploadSegments = secondUploadTarget.AbsolutePath.Split('/', StringSplitOptions.RemoveEmptyEntries);
        Assert.Equal("packet-default-h2", firstUploadSegments[0]);
        Assert.Equal("packet-default-h2", secondUploadSegments[0]);
        Assert.Equal(sessionId, Uri.UnescapeDataString(firstUploadSegments[1]));
        Assert.Equal(sessionId, Uri.UnescapeDataString(secondUploadSegments[1]));
    }

    [Fact]
    public async Task OpenAsync_packet_up_over_explicit_h2_reuses_single_upload_connection_with_multiple_streams()
    {
        using var lifetimeCts = new CancellationTokenSource(TimeSpan.FromSeconds(10));
        using var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();

        const string clientPayload = "abcdefghijkl";
        var port = ((IPEndPoint)listener.LocalEndpoint).Port;
        var serverTask = CaptureSplitHttpHttp2PacketExchangeAsync(
            listener,
            serverPayload: "packet-down",
            expectedUploadPayloads: ["abcdef", "ghijkl"],
            cancellationToken: lifetimeCts.Token);
        var tlsSecurityFactory = new TestRuntimeInternetProfileFactory.RecordingFakeTlsSecurityFactory("h2");
        var profile = TestRuntimeInternetProfileFactory.CreateWithFakeTls(tlsSecurityFactory);

        var context = await RuntimeGrpcClientConnector.OpenAsync(
            new TestSplitHttpInternetOptions
            {
                ServerHost = "127.0.0.1",
                ServerPort = port,
                ServerName = "edge.example.com",
                SecurityType = RuntimeInternetSecurityTypes.Tls,
                SplitHttpPath = " packet-h2?route=1 ",
                SplitHttpMode = "packet-up",
                SplitHttpSeqPlacement = "query",
                SplitHttpScMaxEachPostBytes = new RuntimeInt32Range
                {
                    From = 6,
                    To = 6
                },
                ApplicationProtocols = ["h2"]
            },
            RuntimeInternetStack.Create(RuntimeInternetTransportProtocols.SplitHttp, RuntimeInternetSecurityTypes.Tls),
            profile,
            SystemDnsResolver.Instance,
            transportInitializationData: null,
            lifetimeCts.Token);

        await using var applicationStream = context.ApplicationStream;
        await applicationStream.WriteAsync(Encoding.ASCII.GetBytes(clientPayload), lifetimeCts.Token);
        await applicationStream.FlushAsync(lifetimeCts.Token);

        var responseBuffer = new byte["packet-down".Length];
        await ReadExactAsync(applicationStream, responseBuffer, lifetimeCts.Token);
        Assert.Equal("packet-down", Encoding.ASCII.GetString(responseBuffer));

        var eofBuffer = new byte[1];
        var eofRead = await applicationStream.ReadAsync(eofBuffer, lifetimeCts.Token);
        Assert.Equal(0, eofRead);

        var captured = await serverTask;
        Assert.Equal("GET", captured.DownlinkRequest.Method);
        Assert.Equal("edge.example.com", captured.DownlinkRequest.Headers[":authority"]);
        Assert.Equal("https", captured.DownlinkRequest.Headers[":scheme"]);
        Assert.Equal(1, captured.UploadConnectionCount);
        Assert.Equal(2, captured.UploadRequests.Count);
        Assert.Equal("POST", captured.UploadRequests[0].Request.Method);
        Assert.Equal("POST", captured.UploadRequests[1].Request.Method);
        Assert.Equal("abcdef", captured.UploadRequests[0].PayloadText);
        Assert.Equal("ghijkl", captured.UploadRequests[1].PayloadText);
        Assert.Equal(["h2"], tlsSecurityFactory.ObservedApplicationProtocols);
        Assert.Equal("h2", tlsSecurityFactory.NegotiatedApplicationProtocol);

        var downlinkTarget = new Uri("http://split.local" + captured.DownlinkRequest.Target);
        Assert.Equal("route=1", downlinkTarget.Query.TrimStart('?'));

        var downlinkSegments = downlinkTarget.AbsolutePath.Split('/', StringSplitOptions.RemoveEmptyEntries);
        Assert.Equal("packet-h2", downlinkSegments[0]);
        Assert.True(Guid.TryParse(Uri.UnescapeDataString(downlinkSegments[1]), out _));
        var sessionId = Uri.UnescapeDataString(downlinkSegments[1]);

        var firstTarget = new Uri("http://split.local" + captured.UploadRequests[0].Request.Target);
        var secondTarget = new Uri("http://split.local" + captured.UploadRequests[1].Request.Target);
        Assert.Equal("route=1&x_seq=0", firstTarget.Query.TrimStart('?'));
        Assert.Equal("route=1&x_seq=1", secondTarget.Query.TrimStart('?'));

        var firstSegments = firstTarget.AbsolutePath.Split('/', StringSplitOptions.RemoveEmptyEntries);
        var secondSegments = secondTarget.AbsolutePath.Split('/', StringSplitOptions.RemoveEmptyEntries);
        Assert.Equal(["packet-h2", sessionId], firstSegments);
        Assert.Equal(["packet-h2", sessionId], secondSegments);
    }

    [Fact]
    public async Task OpenAsync_packet_up_over_explicit_h2_sends_second_upload_before_first_upload_response_completes()
    {
        using var lifetimeCts = new CancellationTokenSource(TimeSpan.FromSeconds(10));
        using var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();

        const string clientPayload = "abcdefghijkl";
        var port = ((IPEndPoint)listener.LocalEndpoint).Port;
        var serverTask = CaptureSplitHttpHttp2PacketExchangeWithDelayedFirstUploadResponseAsync(
            listener,
            serverPayload: "packet-down",
            expectedUploadPayloads: ["abcdef", "ghijkl"],
            cancellationToken: lifetimeCts.Token);
        var tlsSecurityFactory = new TestRuntimeInternetProfileFactory.RecordingFakeTlsSecurityFactory("h2");
        var profile = TestRuntimeInternetProfileFactory.CreateWithFakeTls(tlsSecurityFactory);

        var context = await RuntimeGrpcClientConnector.OpenAsync(
            new TestSplitHttpInternetOptions
            {
                ServerHost = "127.0.0.1",
                ServerPort = port,
                ServerName = "edge.example.com",
                SecurityType = RuntimeInternetSecurityTypes.Tls,
                SplitHttpPath = " packet-h2-delayed?route=1 ",
                SplitHttpMode = "packet-up",
                SplitHttpSeqPlacement = "query",
                SplitHttpScMaxEachPostBytes = new RuntimeInt32Range
                {
                    From = 6,
                    To = 6
                },
                ApplicationProtocols = ["h2"]
            },
            RuntimeInternetStack.Create(RuntimeInternetTransportProtocols.SplitHttp, RuntimeInternetSecurityTypes.Tls),
            profile,
            SystemDnsResolver.Instance,
            transportInitializationData: null,
            lifetimeCts.Token);

        await using var applicationStream = context.ApplicationStream;
        await applicationStream.WriteAsync(Encoding.ASCII.GetBytes(clientPayload), lifetimeCts.Token);
        await applicationStream.FlushAsync(lifetimeCts.Token);

        var responseBuffer = new byte["packet-down".Length];
        await ReadExactAsync(applicationStream, responseBuffer, lifetimeCts.Token);
        Assert.Equal("packet-down", Encoding.ASCII.GetString(responseBuffer));

        var captured = await serverTask;
        Assert.Equal(1, captured.UploadConnectionCount);
        Assert.Equal(2, captured.UploadRequests.Count);
        Assert.Equal("abcdef", captured.UploadRequests[0].PayloadText);
        Assert.Equal("ghijkl", captured.UploadRequests[1].PayloadText);
        Assert.Equal(["h2"], tlsSecurityFactory.ObservedApplicationProtocols);
    }

    [Fact]
    public async Task OpenAsync_packet_up_over_explicit_h2_without_shared_pool_sends_second_upload_before_first_upload_response_completes()
    {
        using var lifetimeCts = new CancellationTokenSource(TimeSpan.FromSeconds(10));
        using var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();

        const string clientPayload = "abcdefghijkl";
        var port = ((IPEndPoint)listener.LocalEndpoint).Port;
        var serverTask = CaptureSplitHttpHttp2PacketExchangeWithDelayedFirstUploadResponseAsync(
            listener,
            serverPayload: "packet-down",
            expectedUploadPayloads: ["abcdef", "ghijkl"],
            cancellationToken: lifetimeCts.Token);
        var tlsSecurityFactory = new TestRuntimeInternetProfileFactory.RecordingFakeTlsSecurityFactory("h2");
        var profile = TestRuntimeInternetProfileFactory.CreateWithFakeTls(tlsSecurityFactory);
        var ownedClients = new List<TcpClient>();

        CapturedSplitHttpPacketExchange? captured = null;
        try
        {
            var context = await RuntimeGrpcClientConnector.OpenAsync(
                new TestSplitHttpInternetOptions
                {
                    ServerHost = "127.0.0.1",
                    ServerPort = port,
                    ServerName = "edge.example.com",
                    SecurityType = RuntimeInternetSecurityTypes.Tls,
                    SplitHttpPath = " packet-h2-local-delayed?route=1 ",
                    SplitHttpMode = "packet-up",
                    SplitHttpSeqPlacement = "query",
                    SplitHttpScMaxEachPostBytes = new RuntimeInt32Range
                    {
                        From = 6,
                        To = 6
                    },
                    ApplicationProtocols = ["h2"],
                    TransportStreamFactory = async cancellationToken =>
                    {
                        var client = new TcpClient();
                        ownedClients.Add(client);
                        await client.ConnectAsync(IPAddress.Loopback, port, cancellationToken);
                        return client.GetStream();
                    }
                },
                RuntimeInternetStack.Create(RuntimeInternetTransportProtocols.SplitHttp, RuntimeInternetSecurityTypes.Tls),
                profile,
                SystemDnsResolver.Instance,
                transportInitializationData: null,
                lifetimeCts.Token);

            await using var applicationStream = context.ApplicationStream;
            await applicationStream.WriteAsync(Encoding.ASCII.GetBytes(clientPayload), lifetimeCts.Token);
            await applicationStream.FlushAsync(lifetimeCts.Token);

            var responseBuffer = new byte["packet-down".Length];
            await ReadExactAsync(applicationStream, responseBuffer, lifetimeCts.Token);
            Assert.Equal("packet-down", Encoding.ASCII.GetString(responseBuffer));

            captured = await serverTask;
        }
        finally
        {
            foreach (var client in ownedClients)
            {
                client.Dispose();
            }
        }

        var actualCaptured = Assert.IsType<CapturedSplitHttpPacketExchange>(captured);
        Assert.Equal(1, actualCaptured.UploadConnectionCount);
        Assert.Equal(2, actualCaptured.UploadRequests.Count);
        Assert.Equal("abcdef", actualCaptured.UploadRequests[0].PayloadText);
        Assert.Equal("ghijkl", actualCaptured.UploadRequests[1].PayloadText);
        Assert.Equal(["h2"], tlsSecurityFactory.ObservedApplicationProtocols);
    }

    [Fact]
    public async Task OpenAsync_packet_up_over_explicit_h2_reuses_upload_connection_across_sessions()
    {
        using var lifetimeCts = new CancellationTokenSource(TimeSpan.FromSeconds(10));
        using var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();

        var port = ((IPEndPoint)listener.LocalEndpoint).Port;
        var serverTask = CaptureSplitHttpHttp2PacketExchangeAcrossSessionsAsync(
            listener,
            serverPayloads: ["packet-down-1", "packet-down-2"],
            expectedUploadPayloads: ["first-packet", "second-packet"],
            uploadConnectionPattern: [0, 0],
            cancellationToken: lifetimeCts.Token);
        var tlsSecurityFactory = new TestRuntimeInternetProfileFactory.RecordingFakeTlsSecurityFactory("h2");
        var profile = TestRuntimeInternetProfileFactory.CreateWithFakeTls(tlsSecurityFactory);
        var options = new TestSplitHttpInternetOptions
        {
            ServerHost = "127.0.0.1",
            ServerPort = port,
            ServerName = "edge.example.com",
            SecurityType = RuntimeInternetSecurityTypes.Tls,
            SplitHttpPath = " h2-reuse-global?route=1 ",
            SplitHttpMode = "packet-up",
            SplitHttpSeqPlacement = "query",
            SplitHttpScMaxEachPostBytes = new RuntimeInt32Range
            {
                From = 64,
                To = 64
            },
            ApplicationProtocols = ["h2"]
        };
        var stack = RuntimeInternetStack.Create(
            RuntimeInternetTransportProtocols.SplitHttp,
            RuntimeInternetSecurityTypes.Tls);

        foreach (var (payload, responseText) in new[]
                 {
                     ("first-packet", "packet-down-1"),
                     ("second-packet", "packet-down-2")
                 })
        {
            var context = await RuntimeGrpcClientConnector.OpenAsync(
                options,
                stack,
                profile,
                SystemDnsResolver.Instance,
                transportInitializationData: null,
                lifetimeCts.Token);
            await using var applicationStream = context.ApplicationStream;
            await applicationStream.WriteAsync(Encoding.ASCII.GetBytes(payload), lifetimeCts.Token);
            await applicationStream.FlushAsync(lifetimeCts.Token);

            var responseBuffer = new byte[responseText.Length];
            await ReadExactAsync(applicationStream, responseBuffer, lifetimeCts.Token);
            Assert.Equal(responseText, Encoding.ASCII.GetString(responseBuffer));

            var eofBuffer = new byte[1];
            var eofRead = await applicationStream.ReadAsync(eofBuffer, lifetimeCts.Token);
            Assert.Equal(0, eofRead);
        }

        var captured = await serverTask;
        Assert.Equal(1, captured.UploadConnectionCount);
        Assert.Equal(2, captured.DownlinkRequests.Count);
        Assert.Equal(2, captured.UploadRequests.Count);
        Assert.Equal("first-packet", captured.UploadRequests[0].PayloadText);
        Assert.Equal("second-packet", captured.UploadRequests[1].PayloadText);
        Assert.Equal(["h2"], tlsSecurityFactory.ObservedApplicationProtocols);
        Assert.Equal("h2", tlsSecurityFactory.NegotiatedApplicationProtocol);

        var firstDownlinkTarget = new Uri("http://split.local" + captured.DownlinkRequests[0].Target);
        var secondDownlinkTarget = new Uri("http://split.local" + captured.DownlinkRequests[1].Target);
        var firstUploadTarget = new Uri("http://split.local" + captured.UploadRequests[0].Request.Target);
        var secondUploadTarget = new Uri("http://split.local" + captured.UploadRequests[1].Request.Target);

        Assert.Equal("route=1", firstDownlinkTarget.Query.TrimStart('?'));
        Assert.Equal("route=1", secondDownlinkTarget.Query.TrimStart('?'));
        Assert.Equal("route=1&x_seq=0", firstUploadTarget.Query.TrimStart('?'));
        Assert.Equal("route=1&x_seq=0", secondUploadTarget.Query.TrimStart('?'));

        var firstDownlinkSegments = firstDownlinkTarget.AbsolutePath.Split('/', StringSplitOptions.RemoveEmptyEntries);
        var secondDownlinkSegments = secondDownlinkTarget.AbsolutePath.Split('/', StringSplitOptions.RemoveEmptyEntries);
        var firstUploadSegments = firstUploadTarget.AbsolutePath.Split('/', StringSplitOptions.RemoveEmptyEntries);
        var secondUploadSegments = secondUploadTarget.AbsolutePath.Split('/', StringSplitOptions.RemoveEmptyEntries);

        Assert.Equal(["h2-reuse-global", Uri.UnescapeDataString(firstDownlinkSegments[1])], firstDownlinkSegments);
        Assert.Equal(["h2-reuse-global", Uri.UnescapeDataString(secondDownlinkSegments[1])], secondDownlinkSegments);
        Assert.Equal(["h2-reuse-global", Uri.UnescapeDataString(firstUploadSegments[1])], firstUploadSegments);
        Assert.Equal(["h2-reuse-global", Uri.UnescapeDataString(secondUploadSegments[1])], secondUploadSegments);
        Assert.True(Guid.TryParse(Uri.UnescapeDataString(firstDownlinkSegments[1]), out _));
        Assert.True(Guid.TryParse(Uri.UnescapeDataString(secondDownlinkSegments[1]), out _));
        Assert.Equal(Uri.UnescapeDataString(firstDownlinkSegments[1]), Uri.UnescapeDataString(firstUploadSegments[1]));
        Assert.Equal(Uri.UnescapeDataString(secondDownlinkSegments[1]), Uri.UnescapeDataString(secondUploadSegments[1]));
        Assert.NotEqual(
            Uri.UnescapeDataString(firstDownlinkSegments[1]),
            Uri.UnescapeDataString(secondDownlinkSegments[1]));
    }

    [Fact]
    public async Task OpenAsync_packet_up_over_explicit_h2_xmux_hmax_request_times_rotates_upload_connection_within_session()
    {
        using var lifetimeCts = new CancellationTokenSource(TimeSpan.FromSeconds(10));
        using var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();

        const string clientPayload = "abcdefghijkl";
        var port = ((IPEndPoint)listener.LocalEndpoint).Port;
        var serverTask = CaptureSplitHttpHttp2PacketExchangeAsync(
            listener,
            serverPayload: "packet-down",
            expectedUploadPayloads: ["abcdef", "ghijkl"],
            uploadConnectionPattern: [0, 1],
            cancellationToken: lifetimeCts.Token);
        var tlsSecurityFactory = new TestRuntimeInternetProfileFactory.RecordingFakeTlsSecurityFactory("h2");
        var profile = TestRuntimeInternetProfileFactory.CreateWithFakeTls(tlsSecurityFactory);

        var context = await RuntimeGrpcClientConnector.OpenAsync(
            new TestSplitHttpInternetOptions
            {
                ServerHost = "127.0.0.1",
                ServerPort = port,
                ServerName = "edge.example.com",
                SecurityType = RuntimeInternetSecurityTypes.Tls,
                SplitHttpPath = " h2-hmax-requests?route=1 ",
                SplitHttpMode = "packet-up",
                SplitHttpSeqPlacement = "query",
                SplitHttpScMaxEachPostBytes = new RuntimeInt32Range
                {
                    From = 6,
                    To = 6
                },
                SplitHttpXmux = new RuntimeSplitHttpXmuxOptions
                {
                    HMaxRequestTimes = new RuntimeInt32Range
                    {
                        From = 1,
                        To = 1
                    }
                },
                ApplicationProtocols = ["h2"]
            },
            RuntimeInternetStack.Create(RuntimeInternetTransportProtocols.SplitHttp, RuntimeInternetSecurityTypes.Tls),
            profile,
            SystemDnsResolver.Instance,
            transportInitializationData: null,
            lifetimeCts.Token);

        await using var applicationStream = context.ApplicationStream;
        await applicationStream.WriteAsync(Encoding.ASCII.GetBytes(clientPayload), lifetimeCts.Token);
        await applicationStream.FlushAsync(lifetimeCts.Token);

        var responseBuffer = new byte["packet-down".Length];
        await ReadExactAsync(applicationStream, responseBuffer, lifetimeCts.Token);
        Assert.Equal("packet-down", Encoding.ASCII.GetString(responseBuffer));

        var eofBuffer = new byte[1];
        var eofRead = await applicationStream.ReadAsync(eofBuffer, lifetimeCts.Token);
        Assert.Equal(0, eofRead);

        var captured = await serverTask;
        Assert.Equal(2, captured.UploadConnectionCount);
        Assert.Equal(2, captured.UploadRequests.Count);
        Assert.Equal("abcdef", captured.UploadRequests[0].PayloadText);
        Assert.Equal("ghijkl", captured.UploadRequests[1].PayloadText);
        Assert.Equal(["h2"], tlsSecurityFactory.ObservedApplicationProtocols);

        var firstTarget = new Uri("http://split.local" + captured.UploadRequests[0].Request.Target);
        var secondTarget = new Uri("http://split.local" + captured.UploadRequests[1].Request.Target);
        Assert.Equal("route=1&x_seq=0", firstTarget.Query.TrimStart('?'));
        Assert.Equal("route=1&x_seq=1", secondTarget.Query.TrimStart('?'));

        var firstSegments = firstTarget.AbsolutePath.Split('/', StringSplitOptions.RemoveEmptyEntries);
        var secondSegments = secondTarget.AbsolutePath.Split('/', StringSplitOptions.RemoveEmptyEntries);
        Assert.Equal(["h2-hmax-requests", Uri.UnescapeDataString(firstSegments[1])], firstSegments);
        Assert.Equal(["h2-hmax-requests", Uri.UnescapeDataString(secondSegments[1])], secondSegments);
        Assert.Equal(Uri.UnescapeDataString(firstSegments[1]), Uri.UnescapeDataString(secondSegments[1]));
    }

    [Fact]
    public async Task OpenAsync_packet_up_over_explicit_h2_xmux_cmax_reuse_times_rotates_upload_pool_after_reuse_budget()
    {
        using var lifetimeCts = new CancellationTokenSource(TimeSpan.FromSeconds(10));
        using var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();

        var port = ((IPEndPoint)listener.LocalEndpoint).Port;
        var serverTask = CaptureSplitHttpHttp2PacketExchangeAcrossSessionsAsync(
            listener,
            serverPayloads: ["packet-down-1", "packet-down-2", "packet-down-3"],
            expectedUploadPayloads: ["first-packet", "second-packet", "third-packet"],
            uploadConnectionPattern: [0, 0, 1],
            cancellationToken: lifetimeCts.Token);
        var tlsSecurityFactory = new TestRuntimeInternetProfileFactory.RecordingFakeTlsSecurityFactory("h2");
        var profile = TestRuntimeInternetProfileFactory.CreateWithFakeTls(tlsSecurityFactory);
        var options = new TestSplitHttpInternetOptions
        {
            ServerHost = "127.0.0.1",
            ServerPort = port,
            ServerName = "edge.example.com",
            SecurityType = RuntimeInternetSecurityTypes.Tls,
            SplitHttpPath = " h2-cmax-reuse?route=1 ",
            SplitHttpMode = "packet-up",
            SplitHttpSeqPlacement = "query",
            SplitHttpScMaxEachPostBytes = new RuntimeInt32Range
            {
                From = 64,
                To = 64
            },
            SplitHttpXmux = new RuntimeSplitHttpXmuxOptions
            {
                CMaxReuseTimes = new RuntimeInt32Range
                {
                    From = 2,
                    To = 2
                }
            },
            ApplicationProtocols = ["h2"]
        };
        var stack = RuntimeInternetStack.Create(
            RuntimeInternetTransportProtocols.SplitHttp,
            RuntimeInternetSecurityTypes.Tls);

        foreach (var (payload, responseText) in new[]
                 {
                     ("first-packet", "packet-down-1"),
                     ("second-packet", "packet-down-2"),
                     ("third-packet", "packet-down-3")
                 })
        {
            var context = await RuntimeGrpcClientConnector.OpenAsync(
                options,
                stack,
                profile,
                SystemDnsResolver.Instance,
                transportInitializationData: null,
                lifetimeCts.Token);
            await using var applicationStream = context.ApplicationStream;
            await applicationStream.WriteAsync(Encoding.ASCII.GetBytes(payload), lifetimeCts.Token);
            await applicationStream.FlushAsync(lifetimeCts.Token);

            var responseBuffer = new byte[responseText.Length];
            await ReadExactAsync(applicationStream, responseBuffer, lifetimeCts.Token);
            Assert.Equal(responseText, Encoding.ASCII.GetString(responseBuffer));

            var eofBuffer = new byte[1];
            var eofRead = await applicationStream.ReadAsync(eofBuffer, lifetimeCts.Token);
            Assert.Equal(0, eofRead);
        }

        var captured = await serverTask;
        Assert.Equal(2, captured.UploadConnectionCount);
        Assert.Equal(3, captured.UploadRequests.Count);
        Assert.Equal("first-packet", captured.UploadRequests[0].PayloadText);
        Assert.Equal("second-packet", captured.UploadRequests[1].PayloadText);
        Assert.Equal("third-packet", captured.UploadRequests[2].PayloadText);
        Assert.Equal(["h2"], tlsSecurityFactory.ObservedApplicationProtocols);
    }

    [Fact]
    public async Task OpenAsync_packet_up_over_explicit_h2_xmux_max_connections_prefers_distinct_upload_connections_across_sessions()
    {
        using var lifetimeCts = new CancellationTokenSource(TimeSpan.FromSeconds(10));
        using var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();

        var port = ((IPEndPoint)listener.LocalEndpoint).Port;
        var serverTask = CaptureSplitHttpHttp2PacketExchangeAcrossSessionsAsync(
            listener,
            serverPayloads: ["packet-down-1", "packet-down-2"],
            expectedUploadPayloads: ["first-packet", "second-packet"],
            uploadConnectionPattern: [0, 1],
            cancellationToken: lifetimeCts.Token);
        var tlsSecurityFactory = new TestRuntimeInternetProfileFactory.RecordingFakeTlsSecurityFactory("h2");
        var profile = TestRuntimeInternetProfileFactory.CreateWithFakeTls(tlsSecurityFactory);
        var options = new TestSplitHttpInternetOptions
        {
            ServerHost = "127.0.0.1",
            ServerPort = port,
            ServerName = "edge.example.com",
            SecurityType = RuntimeInternetSecurityTypes.Tls,
            SplitHttpPath = " h2-max-connections?route=1 ",
            SplitHttpMode = "packet-up",
            SplitHttpSeqPlacement = "query",
            SplitHttpScMaxEachPostBytes = new RuntimeInt32Range
            {
                From = 64,
                To = 64
            },
            SplitHttpXmux = new RuntimeSplitHttpXmuxOptions
            {
                MaxConnections = new RuntimeInt32Range
                {
                    From = 2,
                    To = 2
                }
            },
            ApplicationProtocols = ["h2"]
        };
        var stack = RuntimeInternetStack.Create(
            RuntimeInternetTransportProtocols.SplitHttp,
            RuntimeInternetSecurityTypes.Tls);

        foreach (var (payload, responseText) in new[]
                 {
                     ("first-packet", "packet-down-1"),
                     ("second-packet", "packet-down-2")
                 })
        {
            var context = await RuntimeGrpcClientConnector.OpenAsync(
                options,
                stack,
                profile,
                SystemDnsResolver.Instance,
                transportInitializationData: null,
                lifetimeCts.Token);
            await using var applicationStream = context.ApplicationStream;
            await applicationStream.WriteAsync(Encoding.ASCII.GetBytes(payload), lifetimeCts.Token);
            await applicationStream.FlushAsync(lifetimeCts.Token);

            var responseBuffer = new byte[responseText.Length];
            await ReadExactAsync(applicationStream, responseBuffer, lifetimeCts.Token);
            Assert.Equal(responseText, Encoding.ASCII.GetString(responseBuffer));

            var eofBuffer = new byte[1];
            var eofRead = await applicationStream.ReadAsync(eofBuffer, lifetimeCts.Token);
            Assert.Equal(0, eofRead);
        }

        var captured = await serverTask;
        Assert.Equal(2, captured.UploadConnectionCount);
        Assert.Equal(2, captured.DownlinkRequests.Count);
        Assert.Equal(2, captured.UploadRequests.Count);
        Assert.Equal("first-packet", captured.UploadRequests[0].PayloadText);
        Assert.Equal("second-packet", captured.UploadRequests[1].PayloadText);
        Assert.Equal(["h2"], tlsSecurityFactory.ObservedApplicationProtocols);
    }

    [Fact]
    public async Task OpenAsync_packet_up_over_explicit_h2_xmux_max_concurrency_limits_shared_connection_per_live_session()
    {
        using var lifetimeCts = new CancellationTokenSource(TimeSpan.FromSeconds(10));
        using var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();

        var port = ((IPEndPoint)listener.LocalEndpoint).Port;
        var serverTask = CaptureSplitHttpHttp2PacketExchangeAcrossSessionsAsync(
            listener,
            serverPayloads: ["packet-down-1", "packet-down-2"],
            expectedUploadPayloads: ["first-packet", "second-packet"],
            uploadConnectionPattern: [0, 1],
            cancellationToken: lifetimeCts.Token);
        var tlsSecurityFactory = new TestRuntimeInternetProfileFactory.RecordingFakeTlsSecurityFactory("h2");
        var profile = TestRuntimeInternetProfileFactory.CreateWithFakeTls(tlsSecurityFactory);
        var options = new TestSplitHttpInternetOptions
        {
            ServerHost = "127.0.0.1",
            ServerPort = port,
            ServerName = "edge.example.com",
            SecurityType = RuntimeInternetSecurityTypes.Tls,
            SplitHttpPath = " h2-max-concurrency?route=1 ",
            SplitHttpMode = "packet-up",
            SplitHttpSeqPlacement = "query",
            SplitHttpScMaxEachPostBytes = new RuntimeInt32Range
            {
                From = 64,
                To = 64
            },
            SplitHttpXmux = new RuntimeSplitHttpXmuxOptions
            {
                MaxConcurrency = new RuntimeInt32Range
                {
                    From = 1,
                    To = 1
                }
            },
            ApplicationProtocols = ["h2"]
        };
        var stack = RuntimeInternetStack.Create(
            RuntimeInternetTransportProtocols.SplitHttp,
            RuntimeInternetSecurityTypes.Tls);

        var context1 = await RuntimeGrpcClientConnector.OpenAsync(
            options,
            stack,
            profile,
            SystemDnsResolver.Instance,
            transportInitializationData: null,
            lifetimeCts.Token);
        await using var applicationStream1 = context1.ApplicationStream;
        await applicationStream1.WriteAsync(Encoding.ASCII.GetBytes("first-packet"), lifetimeCts.Token);
        await applicationStream1.FlushAsync(lifetimeCts.Token);

        var responseBuffer1 = new byte["packet-down-1".Length];
        await ReadExactAsync(applicationStream1, responseBuffer1, lifetimeCts.Token);
        Assert.Equal("packet-down-1", Encoding.ASCII.GetString(responseBuffer1));

        var eofBuffer1 = new byte[1];
        var eofRead1 = await applicationStream1.ReadAsync(eofBuffer1, lifetimeCts.Token);
        Assert.Equal(0, eofRead1);

        var context2 = await RuntimeGrpcClientConnector.OpenAsync(
            options,
            stack,
            profile,
            SystemDnsResolver.Instance,
            transportInitializationData: null,
            lifetimeCts.Token);
        await using var applicationStream2 = context2.ApplicationStream;
        await applicationStream2.WriteAsync(Encoding.ASCII.GetBytes("second-packet"), lifetimeCts.Token);
        await applicationStream2.FlushAsync(lifetimeCts.Token);

        var responseBuffer2 = new byte["packet-down-2".Length];
        await ReadExactAsync(applicationStream2, responseBuffer2, lifetimeCts.Token);
        Assert.Equal("packet-down-2", Encoding.ASCII.GetString(responseBuffer2));

        var eofBuffer2 = new byte[1];
        var eofRead2 = await applicationStream2.ReadAsync(eofBuffer2, lifetimeCts.Token);
        Assert.Equal(0, eofRead2);

        var captured = await serverTask;
        Assert.Equal(2, captured.UploadConnectionCount);
        Assert.Equal(2, captured.UploadRequests.Count);
        Assert.Equal("first-packet", captured.UploadRequests[0].PayloadText);
        Assert.Equal("second-packet", captured.UploadRequests[1].PayloadText);
        Assert.Equal(["h2"], tlsSecurityFactory.ObservedApplicationProtocols);
    }

    [Fact]
    public async Task OpenAsync_packet_up_over_explicit_h2_xmux_hmax_reusable_secs_rotates_expired_upload_connection()
    {
        using var lifetimeCts = new CancellationTokenSource(TimeSpan.FromSeconds(15));
        using var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();

        var port = ((IPEndPoint)listener.LocalEndpoint).Port;
        var serverTask = CaptureSplitHttpHttp2PacketExchangeAcrossSessionsAsync(
            listener,
            serverPayloads: ["packet-down-1", "packet-down-2"],
            expectedUploadPayloads: ["first-packet", "second-packet"],
            uploadConnectionPattern: [0, 1],
            cancellationToken: lifetimeCts.Token);
        var tlsSecurityFactory = new TestRuntimeInternetProfileFactory.RecordingFakeTlsSecurityFactory("h2");
        var profile = TestRuntimeInternetProfileFactory.CreateWithFakeTls(tlsSecurityFactory);
        var options = new TestSplitHttpInternetOptions
        {
            ServerHost = "127.0.0.1",
            ServerPort = port,
            ServerName = "edge.example.com",
            SecurityType = RuntimeInternetSecurityTypes.Tls,
            SplitHttpPath = " h2-hmax-reusable?route=1 ",
            SplitHttpMode = "packet-up",
            SplitHttpSeqPlacement = "query",
            SplitHttpScMaxEachPostBytes = new RuntimeInt32Range
            {
                From = 64,
                To = 64
            },
            SplitHttpXmux = new RuntimeSplitHttpXmuxOptions
            {
                HMaxReusableSecs = new RuntimeInt32Range
                {
                    From = 1,
                    To = 1
                }
            },
            ApplicationProtocols = ["h2"]
        };
        var stack = RuntimeInternetStack.Create(
            RuntimeInternetTransportProtocols.SplitHttp,
            RuntimeInternetSecurityTypes.Tls);

        var context1 = await RuntimeGrpcClientConnector.OpenAsync(
            options,
            stack,
            profile,
            SystemDnsResolver.Instance,
            transportInitializationData: null,
            lifetimeCts.Token);
        await using (var applicationStream1 = context1.ApplicationStream)
        {
            await applicationStream1.WriteAsync(Encoding.ASCII.GetBytes("first-packet"), lifetimeCts.Token);
            await applicationStream1.FlushAsync(lifetimeCts.Token);

            var responseBuffer = new byte["packet-down-1".Length];
            await ReadExactAsync(applicationStream1, responseBuffer, lifetimeCts.Token);
            Assert.Equal("packet-down-1", Encoding.ASCII.GetString(responseBuffer));

            var eofBuffer = new byte[1];
            var eofRead = await applicationStream1.ReadAsync(eofBuffer, lifetimeCts.Token);
            Assert.Equal(0, eofRead);
        }

        await Task.Delay(TimeSpan.FromMilliseconds(1500), lifetimeCts.Token);

        var context2 = await RuntimeGrpcClientConnector.OpenAsync(
            options,
            stack,
            profile,
            SystemDnsResolver.Instance,
            transportInitializationData: null,
            lifetimeCts.Token);
        await using (var applicationStream2 = context2.ApplicationStream)
        {
            await applicationStream2.WriteAsync(Encoding.ASCII.GetBytes("second-packet"), lifetimeCts.Token);
            await applicationStream2.FlushAsync(lifetimeCts.Token);

            var responseBuffer = new byte["packet-down-2".Length];
            await ReadExactAsync(applicationStream2, responseBuffer, lifetimeCts.Token);
            Assert.Equal("packet-down-2", Encoding.ASCII.GetString(responseBuffer));

            var eofBuffer = new byte[1];
            var eofRead = await applicationStream2.ReadAsync(eofBuffer, lifetimeCts.Token);
            Assert.Equal(0, eofRead);
        }

        var captured = await serverTask;
        Assert.Equal(2, captured.UploadConnectionCount);
        Assert.Equal(2, captured.UploadRequests.Count);
        Assert.Equal("first-packet", captured.UploadRequests[0].PayloadText);
        Assert.Equal("second-packet", captured.UploadRequests[1].PayloadText);
        Assert.Equal(["h2"], tlsSecurityFactory.ObservedApplicationProtocols);
    }

    [Fact]
    public async Task OpenAsync_packet_up_header_payload_moves_body_into_x_data_headers()
    {
        using var lifetimeCts = new CancellationTokenSource(TimeSpan.FromSeconds(10));
        using var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();

        const string clientPayload = "header-packet";
        var port = ((IPEndPoint)listener.LocalEndpoint).Port;
        var serverTask = CaptureSplitHttpPacketExchangeAsync(
            listener,
            serverPayload: "packet-down",
            expectedUploadPayloads: [string.Empty],
            lifetimeCts.Token);
        var profile = RuntimeInternetProfile.FromDefault();

        var context = await RuntimeGrpcClientConnector.OpenAsync(
            new TestSplitHttpInternetOptions
            {
                ServerHost = "127.0.0.1",
                ServerPort = port,
                SecurityType = RuntimeInternetSecurityTypes.None,
                SplitHttpPath = " header-data?route=1 ",
                SplitHttpHeaders = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
                {
                    ["X-Trace"] = "header-data"
                },
                SplitHttpMode = "packet-up",
                SplitHttpSessionPlacement = "query",
                SplitHttpUplinkDataPlacement = "header"
            },
            RuntimeInternetStack.Create(RuntimeInternetTransportProtocols.SplitHttp, RuntimeInternetSecurityTypes.None),
            profile,
            SystemDnsResolver.Instance,
            transportInitializationData: null,
            lifetimeCts.Token);

        await using var applicationStream = context.ApplicationStream;
        await applicationStream.WriteAsync(Encoding.ASCII.GetBytes(clientPayload), lifetimeCts.Token);
        await applicationStream.FlushAsync(lifetimeCts.Token);

        var responseBuffer = new byte["packet-down".Length];
        await ReadExactAsync(applicationStream, responseBuffer, lifetimeCts.Token);
        Assert.Equal("packet-down", Encoding.ASCII.GetString(responseBuffer));

        var captured = await serverTask;
        var upload = Assert.Single(captured.UploadRequests);
        Assert.Equal(string.Empty, upload.PayloadText);
        Assert.Equal("header-data", upload.Request.Headers["X-Trace"]);
        Assert.Equal(clientPayload, DecodeHeaderPayload(upload.Request.Headers, "X-Data"));

        var uploadTarget = new Uri("http://split.local" + upload.Request.Target);
        Assert.Contains("route=1", uploadTarget.Query, StringComparison.Ordinal);
        Assert.Contains("x_session=", uploadTarget.Query, StringComparison.Ordinal);
    }

    [Fact]
    public async Task OpenAsync_packet_up_header_payload_honors_configured_uplink_chunk_size()
    {
        using var lifetimeCts = new CancellationTokenSource(TimeSpan.FromSeconds(10));
        using var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();

        var clientPayload = new string('a', 90);
        var port = ((IPEndPoint)listener.LocalEndpoint).Port;
        var serverTask = CaptureSplitHttpPacketExchangeAsync(
            listener,
            serverPayload: "packet-down",
            expectedUploadPayloads: [string.Empty],
            lifetimeCts.Token);
        var profile = RuntimeInternetProfile.FromDefault();

        var context = await RuntimeGrpcClientConnector.OpenAsync(
            new TestSplitHttpInternetOptions
            {
                ServerHost = "127.0.0.1",
                ServerPort = port,
                SecurityType = RuntimeInternetSecurityTypes.None,
                SplitHttpPath = " header-chunk ",
                SplitHttpMode = "packet-up",
                SplitHttpUplinkDataPlacement = "header",
                SplitHttpUplinkChunkSize = new RuntimeInt32Range
                {
                    From = 64,
                    To = 64
                }
            },
            RuntimeInternetStack.Create(RuntimeInternetTransportProtocols.SplitHttp, RuntimeInternetSecurityTypes.None),
            profile,
            SystemDnsResolver.Instance,
            transportInitializationData: null,
            lifetimeCts.Token);

        await using var applicationStream = context.ApplicationStream;
        await applicationStream.WriteAsync(Encoding.ASCII.GetBytes(clientPayload), lifetimeCts.Token);
        await applicationStream.FlushAsync(lifetimeCts.Token);

        var responseBuffer = new byte["packet-down".Length];
        await ReadExactAsync(applicationStream, responseBuffer, lifetimeCts.Token);
        Assert.Equal("packet-down", Encoding.ASCII.GetString(responseBuffer));

        var captured = await serverTask;
        var upload = Assert.Single(captured.UploadRequests);
        Assert.Equal(string.Empty, upload.PayloadText);
        Assert.Equal(clientPayload, DecodeHeaderPayload(upload.Request.Headers, "X-Data"));
        Assert.Equal(64, upload.Request.Headers["X-Data-0"].Length);
        Assert.Equal(56, upload.Request.Headers["X-Data-1"].Length);
        Assert.False(upload.Request.Headers.ContainsKey("X-Data-2"));
    }

    [Fact]
    public async Task OpenAsync_packet_up_cookie_payload_moves_body_into_x_data_cookies()
    {
        using var lifetimeCts = new CancellationTokenSource(TimeSpan.FromSeconds(10));
        using var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();

        const string clientPayload = "cookie-packet";
        var port = ((IPEndPoint)listener.LocalEndpoint).Port;
        var serverTask = CaptureSplitHttpPacketExchangeAsync(
            listener,
            serverPayload: "packet-down",
            expectedUploadPayloads: [string.Empty],
            lifetimeCts.Token);
        var profile = RuntimeInternetProfile.FromDefault();

        var context = await RuntimeGrpcClientConnector.OpenAsync(
            new TestSplitHttpInternetOptions
            {
                ServerHost = "127.0.0.1",
                ServerPort = port,
                SecurityType = RuntimeInternetSecurityTypes.None,
                SplitHttpPath = " cookie-data?route=1 ",
                SplitHttpHeaders = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
                {
                    ["X-Trace"] = "cookie-data"
                },
                SplitHttpMode = "packet-up",
                SplitHttpSessionPlacement = "cookie",
                SplitHttpSeqPlacement = "query",
                SplitHttpUplinkDataPlacement = "cookie"
            },
            RuntimeInternetStack.Create(RuntimeInternetTransportProtocols.SplitHttp, RuntimeInternetSecurityTypes.None),
            profile,
            SystemDnsResolver.Instance,
            transportInitializationData: null,
            lifetimeCts.Token);

        await using var applicationStream = context.ApplicationStream;
        await applicationStream.WriteAsync(Encoding.ASCII.GetBytes(clientPayload), lifetimeCts.Token);
        await applicationStream.FlushAsync(lifetimeCts.Token);

        var responseBuffer = new byte["packet-down".Length];
        await ReadExactAsync(applicationStream, responseBuffer, lifetimeCts.Token);
        Assert.Equal("packet-down", Encoding.ASCII.GetString(responseBuffer));

        var captured = await serverTask;
        var upload = Assert.Single(captured.UploadRequests);
        Assert.Equal(string.Empty, upload.PayloadText);
        Assert.Equal("cookie-data", upload.Request.Headers["X-Trace"]);

        var downlinkCookies = ParseCookies(captured.DownlinkRequest.Headers["Cookie"]);
        var uploadCookies = ParseCookies(upload.Request.Headers["Cookie"]);
        Assert.True(Guid.TryParse(downlinkCookies["x_session"], out _));
        Assert.Equal(downlinkCookies["x_session"], uploadCookies["x_session"]);
        Assert.Equal(clientPayload, DecodeCookiePayload(upload.Request.Headers, "x_data"));

        var uploadTarget = new Uri("http://split.local" + upload.Request.Target);
        Assert.Equal("route=1&x_seq=0", uploadTarget.Query.TrimStart('?'));
    }

    [Fact]
    public async Task OpenAsync_packet_up_cookie_payload_honors_configured_uplink_chunk_size()
    {
        using var lifetimeCts = new CancellationTokenSource(TimeSpan.FromSeconds(10));
        using var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();

        var clientPayload = new string('b', 90);
        var port = ((IPEndPoint)listener.LocalEndpoint).Port;
        var serverTask = CaptureSplitHttpPacketExchangeAsync(
            listener,
            serverPayload: "packet-down",
            expectedUploadPayloads: [string.Empty],
            lifetimeCts.Token);
        var profile = RuntimeInternetProfile.FromDefault();

        var context = await RuntimeGrpcClientConnector.OpenAsync(
            new TestSplitHttpInternetOptions
            {
                ServerHost = "127.0.0.1",
                ServerPort = port,
                SecurityType = RuntimeInternetSecurityTypes.None,
                SplitHttpPath = " cookie-chunk ",
                SplitHttpMode = "packet-up",
                SplitHttpUplinkDataPlacement = "cookie",
                SplitHttpUplinkChunkSize = new RuntimeInt32Range
                {
                    From = 64,
                    To = 64
                }
            },
            RuntimeInternetStack.Create(RuntimeInternetTransportProtocols.SplitHttp, RuntimeInternetSecurityTypes.None),
            profile,
            SystemDnsResolver.Instance,
            transportInitializationData: null,
            lifetimeCts.Token);

        await using var applicationStream = context.ApplicationStream;
        await applicationStream.WriteAsync(Encoding.ASCII.GetBytes(clientPayload), lifetimeCts.Token);
        await applicationStream.FlushAsync(lifetimeCts.Token);

        var responseBuffer = new byte["packet-down".Length];
        await ReadExactAsync(applicationStream, responseBuffer, lifetimeCts.Token);
        Assert.Equal("packet-down", Encoding.ASCII.GetString(responseBuffer));

        var captured = await serverTask;
        var upload = Assert.Single(captured.UploadRequests);
        Assert.Equal(string.Empty, upload.PayloadText);
        Assert.Equal(clientPayload, DecodeCookiePayload(upload.Request.Headers, "x_data"));

        var cookies = ParseCookies(upload.Request.Headers["Cookie"]);
        Assert.Equal(64, cookies["x_data_0"].Length);
        Assert.Equal(56, cookies["x_data_1"].Length);
        Assert.False(cookies.ContainsKey("x_data_2"));
    }

    [Fact]
    public async Task OpenAsync_packet_up_download_settings_use_distinct_downlink_endpoint()
    {
        using var lifetimeCts = new CancellationTokenSource(TimeSpan.FromSeconds(10));
        using var downlinkListener = new TcpListener(IPAddress.Loopback, 0);
        using var uploadListener = new TcpListener(IPAddress.Loopback, 0);
        downlinkListener.Start();
        uploadListener.Start();

        var downlinkPort = ((IPEndPoint)downlinkListener.LocalEndpoint).Port;
        var uploadPort = ((IPEndPoint)uploadListener.LocalEndpoint).Port;
        var serverTask = CaptureSplitHttpPacketExchangeAcrossEndpointsAsync(
            downlinkListener,
            uploadListener,
            serverPayload: "packet-down",
            expectedUploadPayloads: ["outer-upload"],
            lifetimeCts.Token);
        var profile = RuntimeInternetProfile.FromDefault();

        var context = await RuntimeGrpcClientConnector.OpenAsync(
            new TestSplitHttpInternetOptions
            {
                ServerHost = "127.0.0.1",
                ServerPort = uploadPort,
                SecurityType = RuntimeInternetSecurityTypes.None,
                SplitHttpHost = "upload.example.com",
                SplitHttpPath = " upload?u=1 ",
                SplitHttpHeaders = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
                {
                    ["X-Up"] = "outer"
                },
                SplitHttpMode = "packet-up",
                SplitHttpDownloadSettings = new RuntimeSplitHttpDownloadOptions
                {
                    ServerHost = "127.0.0.1",
                    ServerPort = downlinkPort,
                    Host = "down.example.com",
                    Path = " down?d=1 ",
                    Headers = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
                    {
                        ["X-Down"] = "inner"
                    }
                }
            },
            RuntimeInternetStack.Create(RuntimeInternetTransportProtocols.SplitHttp, RuntimeInternetSecurityTypes.None),
            profile,
            SystemDnsResolver.Instance,
            transportInitializationData: null,
            lifetimeCts.Token);

        await using var applicationStream = context.ApplicationStream;
        await applicationStream.WriteAsync(Encoding.ASCII.GetBytes("outer-upload"), lifetimeCts.Token);

        var responseBuffer = new byte["packet-down".Length];
        await ReadExactAsync(applicationStream, responseBuffer, lifetimeCts.Token);
        Assert.Equal("packet-down", Encoding.ASCII.GetString(responseBuffer));

        var captured = await serverTask;
        Assert.Equal("GET", captured.DownlinkRequest.Method);
        Assert.Equal("down.example.com", captured.DownlinkRequest.Headers["Host"]);
        Assert.Equal("inner", captured.DownlinkRequest.Headers["X-Down"]);
        Assert.False(captured.DownlinkRequest.Headers.ContainsKey("X-Up"));

        var upload = Assert.Single(captured.UploadRequests);
        Assert.Equal("POST", upload.Request.Method);
        Assert.Equal("upload.example.com", upload.Request.Headers["Host"]);
        Assert.Equal("outer", upload.Request.Headers["X-Up"]);
        Assert.False(upload.Request.Headers.ContainsKey("X-Down"));
        Assert.Equal("outer-upload", upload.PayloadText);

        var downlinkTarget = new Uri("http://split.local" + captured.DownlinkRequest.Target);
        var uploadTarget = new Uri("http://split.local" + upload.Request.Target);
        Assert.Equal("d=1", downlinkTarget.Query.TrimStart('?'));
        Assert.Equal("u=1", uploadTarget.Query.TrimStart('?'));

        var downlinkSegments = downlinkTarget.AbsolutePath.Split('/', StringSplitOptions.RemoveEmptyEntries);
        var uploadSegments = uploadTarget.AbsolutePath.Split('/', StringSplitOptions.RemoveEmptyEntries);
        Assert.Equal("down", downlinkSegments[0]);
        Assert.Equal("upload", uploadSegments[0]);
        Assert.True(Guid.TryParse(Uri.UnescapeDataString(downlinkSegments[1]), out _));
        Assert.Equal(Uri.UnescapeDataString(downlinkSegments[1]), Uri.UnescapeDataString(uploadSegments[1]));
        Assert.Equal("0", Uri.UnescapeDataString(uploadSegments[2]));
    }

    [Fact]
    public async Task OpenAsync_reality_auto_mode_with_download_settings_uses_stream_up()
    {
        using var lifetimeCts = new CancellationTokenSource(TimeSpan.FromSeconds(10));
        using var downlinkListener = new TcpListener(IPAddress.Loopback, 0);
        using var uploadListener = new TcpListener(IPAddress.Loopback, 0);
        downlinkListener.Start();
        uploadListener.Start();

        const string clientPayload = "stream-up-client";
        const string serverPayload = "stream-up-server";
        var downlinkPort = ((IPEndPoint)downlinkListener.LocalEndpoint).Port;
        var uploadPort = ((IPEndPoint)uploadListener.LocalEndpoint).Port;
        var serverTask = CaptureSplitHttpHttp2StreamUpExchangeAcrossEndpointsAsync(
            downlinkListener,
            uploadListener,
            clientPayload,
            serverPayload,
            lifetimeCts.Token);
        var realitySecurityFactory = new TestRuntimeInternetProfileFactory.RecordingPassThroughSecurityFactory(
            RuntimeInternetSecurityTypes.Reality,
            negotiatedApplicationProtocol: "h2");
        var profile = TestRuntimeInternetProfileFactory.CreateWithRecordingSecurity(realitySecurityFactory);

        var context = await RuntimeGrpcClientConnector.OpenAsync(
            new TestSplitHttpInternetOptions
            {
                ServerHost = "127.0.0.1",
                ServerPort = uploadPort,
                ServerName = "edge.example.com",
                SecurityType = RuntimeInternetSecurityTypes.Reality,
                RealityOptions = new RuntimeRealityOptions
                {
                    PublicKey = EncodeBase64Url(32, 0x41)
                },
                SplitHttpMode = "auto",
                SplitHttpPath = " upload?u=1 ",
                SplitHttpDownloadSettings = new RuntimeSplitHttpDownloadOptions
                {
                    ServerHost = "127.0.0.1",
                    ServerPort = downlinkPort,
                    Host = "down.example.com",
                    Path = " down?d=1 "
                }
            },
            RuntimeInternetStack.Create(RuntimeInternetTransportProtocols.SplitHttp, RuntimeInternetSecurityTypes.Reality),
            profile,
            SystemDnsResolver.Instance,
            transportInitializationData: null,
            lifetimeCts.Token);

        await using var applicationStream = context.ApplicationStream;
        await applicationStream.WriteAsync(Encoding.ASCII.GetBytes(clientPayload), lifetimeCts.Token);
        await applicationStream.FlushAsync(lifetimeCts.Token);

        var responseBuffer = new byte[serverPayload.Length];
        await ReadExactAsync(applicationStream, responseBuffer, lifetimeCts.Token);
        Assert.Equal(serverPayload, Encoding.ASCII.GetString(responseBuffer));

        var eofBuffer = new byte[1];
        var eofRead = await applicationStream.ReadAsync(eofBuffer, lifetimeCts.Token);
        Assert.Equal(0, eofRead);

        var captured = await serverTask;
        Assert.Equal("GET", captured.DownlinkRequest.Method);
        Assert.Equal("POST", captured.UplinkRequest.Method);
        Assert.Equal("down.example.com", captured.DownlinkRequest.Headers[":authority"]);
        Assert.Equal("edge.example.com", captured.UplinkRequest.Headers[":authority"]);
        Assert.Equal("https", captured.DownlinkRequest.Headers[":scheme"]);
        Assert.Equal("https", captured.UplinkRequest.Headers[":scheme"]);
        Assert.False(captured.DownlinkRequest.Headers.ContainsKey("content-type"));
        Assert.Equal("application/grpc", captured.UplinkRequest.Headers["content-type"]);
        Assert.Equal(clientPayload, captured.UplinkPayloadText);

        var downlinkTarget = new Uri("http://split.local" + captured.DownlinkRequest.Target);
        var uploadTarget = new Uri("http://split.local" + captured.UplinkRequest.Target);
        Assert.Equal("d=1", downlinkTarget.Query.TrimStart('?'));
        Assert.Equal("u=1", uploadTarget.Query.TrimStart('?'));
        Assert.Equal("down", downlinkTarget.AbsolutePath.Split('/', StringSplitOptions.RemoveEmptyEntries)[0]);
        Assert.Equal("upload", uploadTarget.AbsolutePath.Split('/', StringSplitOptions.RemoveEmptyEntries)[0]);
        Assert.Equal(["h2", "http/1.1"], realitySecurityFactory.ObservedApplicationProtocols);
        Assert.Equal("h2", realitySecurityFactory.NegotiatedApplicationProtocol);
    }

    [Fact]
    public async Task OpenAsync_reality_auto_mode_uses_stream_one_without_session_metadata()
    {
        using var lifetimeCts = new CancellationTokenSource(TimeSpan.FromSeconds(10));
        using var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();

        const string clientPayload = "stream-one-client";
        const string serverPayload = "stream-one-server";
        var port = ((IPEndPoint)listener.LocalEndpoint).Port;
        var serverTask = CaptureSplitHttpHttp2StreamOneExchangeAsync(
            listener,
            clientPayload,
            serverPayload,
            lifetimeCts.Token);
        var realitySecurityFactory = new TestRuntimeInternetProfileFactory.RecordingPassThroughSecurityFactory(
            RuntimeInternetSecurityTypes.Reality,
            negotiatedApplicationProtocol: "h2");
        var profile = TestRuntimeInternetProfileFactory.CreateWithRecordingSecurity(realitySecurityFactory);

        var context = await RuntimeGrpcClientConnector.OpenAsync(
            new TestSplitHttpInternetOptions
            {
                ServerHost = "127.0.0.1",
                ServerPort = port,
                ServerName = "edge.example.com",
                SecurityType = RuntimeInternetSecurityTypes.Reality,
                RealityOptions = new RuntimeRealityOptions
                {
                    PublicKey = EncodeBase64Url(32, 0x41)
                },
                SplitHttpMode = "auto",
                SplitHttpPath = "stream-one?route=1"
            },
            RuntimeInternetStack.Create(RuntimeInternetTransportProtocols.SplitHttp, RuntimeInternetSecurityTypes.Reality),
            profile,
            SystemDnsResolver.Instance,
            transportInitializationData: null,
            lifetimeCts.Token);

        await using var applicationStream = context.ApplicationStream;
        await applicationStream.WriteAsync(Encoding.ASCII.GetBytes(clientPayload), lifetimeCts.Token);
        await applicationStream.FlushAsync(lifetimeCts.Token);

        var responseBuffer = new byte[serverPayload.Length];
        await ReadExactAsync(applicationStream, responseBuffer, lifetimeCts.Token);
        Assert.Equal(serverPayload, Encoding.ASCII.GetString(responseBuffer));

        var eofBuffer = new byte[1];
        var eofRead = await applicationStream.ReadAsync(eofBuffer, lifetimeCts.Token);
        Assert.Equal(0, eofRead);

        var captured = await serverTask;
        Assert.Equal("POST", captured.Request.Method);
        Assert.Equal("/stream-one/?route=1", captured.Request.Target);
        Assert.Equal("edge.example.com", captured.Request.Headers[":authority"]);
        Assert.Equal("https", captured.Request.Headers[":scheme"]);
        Assert.Equal("application/grpc", captured.Request.Headers["content-type"]);
        Assert.Equal("identity", captured.Request.Headers["accept-encoding"]);
        Assert.Equal(RuntimeInternetHttpUtilities.DefaultChromeUserAgent, captured.Request.Headers["user-agent"]);
        Assert.Equal(clientPayload, captured.PayloadText);
        Assert.Equal(["h2", "http/1.1"], realitySecurityFactory.ObservedApplicationProtocols);
        Assert.Equal("h2", realitySecurityFactory.NegotiatedApplicationProtocol);
    }

    [Fact]
    public async Task OpenAsync_stream_one_over_explicit_h2_uses_http2_request_stream()
    {
        using var lifetimeCts = new CancellationTokenSource(TimeSpan.FromSeconds(10));
        using var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();

        const string clientPayload = "h2-stream-one-client";
        const string serverPayload = "h2-stream-one-server";
        var port = ((IPEndPoint)listener.LocalEndpoint).Port;
        var serverTask = CaptureSplitHttpHttp2StreamOneExchangeAsync(
            listener,
            clientPayload,
            serverPayload,
            lifetimeCts.Token);
        var tlsSecurityFactory = new TestRuntimeInternetProfileFactory.RecordingFakeTlsSecurityFactory("h2");
        var profile = TestRuntimeInternetProfileFactory.CreateWithFakeTls(tlsSecurityFactory);

        var context = await RuntimeGrpcClientConnector.OpenAsync(
            new TestSplitHttpInternetOptions
            {
                ServerHost = "127.0.0.1",
                ServerPort = port,
                ServerName = "edge.example.com",
                SecurityType = RuntimeInternetSecurityTypes.Tls,
                SplitHttpMode = "stream-one",
                SplitHttpPath = "stream-one?route=1",
                ApplicationProtocols = ["h2"]
            },
            RuntimeInternetStack.Create(RuntimeInternetTransportProtocols.SplitHttp, RuntimeInternetSecurityTypes.Tls),
            profile,
            SystemDnsResolver.Instance,
            transportInitializationData: null,
            lifetimeCts.Token);

        await using var applicationStream = context.ApplicationStream;
        await applicationStream.WriteAsync(Encoding.ASCII.GetBytes(clientPayload), lifetimeCts.Token);
        await applicationStream.FlushAsync(lifetimeCts.Token);

        var responseBuffer = new byte[serverPayload.Length];
        await ReadExactAsync(applicationStream, responseBuffer, lifetimeCts.Token);
        Assert.Equal(serverPayload, Encoding.ASCII.GetString(responseBuffer));

        var eofBuffer = new byte[1];
        var eofRead = await applicationStream.ReadAsync(eofBuffer, lifetimeCts.Token);
        Assert.Equal(0, eofRead);

        var captured = await serverTask;
        Assert.Equal("POST", captured.Request.Method);
        Assert.Equal("/stream-one/?route=1", captured.Request.Target);
        Assert.Equal("edge.example.com", captured.Request.Headers[":authority"]);
        Assert.Equal("https", captured.Request.Headers[":scheme"]);
        Assert.Equal("application/grpc", captured.Request.Headers["content-type"]);
        Assert.Equal("identity", captured.Request.Headers["accept-encoding"]);
        Assert.Equal(RuntimeInternetHttpUtilities.DefaultChromeUserAgent, captured.Request.Headers["user-agent"]);
        Assert.Equal(clientPayload, captured.PayloadText);
        Assert.Equal(["h2"], tlsSecurityFactory.ObservedApplicationProtocols);
        Assert.Equal("h2", tlsSecurityFactory.NegotiatedApplicationProtocol);
    }

    [Fact]
    public async Task OpenAsync_stream_one_over_explicit_h2_accepts_custom_uplink_method()
    {
        using var lifetimeCts = new CancellationTokenSource(TimeSpan.FromSeconds(10));
        using var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();

        const string clientPayload = "h2-custom-stream-one-client";
        const string serverPayload = "h2-custom-stream-one-server";
        var port = ((IPEndPoint)listener.LocalEndpoint).Port;
        var serverTask = CaptureSplitHttpHttp2StreamOneExchangeAsync(
            listener,
            clientPayload,
            serverPayload,
            lifetimeCts.Token);
        var tlsSecurityFactory = new TestRuntimeInternetProfileFactory.RecordingFakeTlsSecurityFactory("h2");
        var profile = TestRuntimeInternetProfileFactory.CreateWithFakeTls(tlsSecurityFactory);

        var context = await RuntimeGrpcClientConnector.OpenAsync(
            new TestSplitHttpInternetOptions
            {
                ServerHost = "127.0.0.1",
                ServerPort = port,
                ServerName = "edge.example.com",
                SecurityType = RuntimeInternetSecurityTypes.Tls,
                SplitHttpMode = "stream-one",
                SplitHttpPath = "stream-one?route=2",
                SplitHttpUplinkHttpMethod = "PUT",
                ApplicationProtocols = ["h2"]
            },
            RuntimeInternetStack.Create(RuntimeInternetTransportProtocols.SplitHttp, RuntimeInternetSecurityTypes.Tls),
            profile,
            SystemDnsResolver.Instance,
            transportInitializationData: null,
            lifetimeCts.Token);

        await using var applicationStream = context.ApplicationStream;
        await applicationStream.WriteAsync(Encoding.ASCII.GetBytes(clientPayload), lifetimeCts.Token);
        await applicationStream.FlushAsync(lifetimeCts.Token);

        var responseBuffer = new byte[serverPayload.Length];
        await ReadExactAsync(applicationStream, responseBuffer, lifetimeCts.Token);
        Assert.Equal(serverPayload, Encoding.ASCII.GetString(responseBuffer));

        var eofBuffer = new byte[1];
        var eofRead = await applicationStream.ReadAsync(eofBuffer, lifetimeCts.Token);
        Assert.Equal(0, eofRead);

        var captured = await serverTask;
        Assert.Equal("PUT", captured.Request.Method);
        Assert.Equal("/stream-one/?route=2", captured.Request.Target);
        Assert.Equal("edge.example.com", captured.Request.Headers[":authority"]);
        Assert.Equal("https", captured.Request.Headers[":scheme"]);
        Assert.Equal("application/grpc", captured.Request.Headers["content-type"]);
        Assert.Equal(clientPayload, captured.PayloadText);
        Assert.Equal(["h2"], tlsSecurityFactory.ObservedApplicationProtocols);
        Assert.Equal("h2", tlsSecurityFactory.NegotiatedApplicationProtocol);
    }

    [Fact]
    public async Task OpenAsync_stream_one_over_explicit_h2_reuses_connection_across_sessions()
    {
        using var lifetimeCts = new CancellationTokenSource(TimeSpan.FromSeconds(10));
        using var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();

        var clientPayloads = new[] { "h2-stream-one-first", "h2-stream-one-second" };
        var serverPayloads = new[] { "h2-stream-one-response-1", "h2-stream-one-response-2" };
        var port = ((IPEndPoint)listener.LocalEndpoint).Port;
        var serverTask = CaptureSplitHttpHttp2StreamOneExchangeAcrossSessionsAsync(
            listener,
            clientPayloads,
            serverPayloads,
            lifetimeCts.Token);
        var tlsSecurityFactory = new TestRuntimeInternetProfileFactory.RecordingFakeTlsSecurityFactory("h2");
        var profile = TestRuntimeInternetProfileFactory.CreateWithFakeTls(tlsSecurityFactory);

        foreach (var index in Enumerable.Range(0, clientPayloads.Length))
        {
            {
                var context = await RuntimeGrpcClientConnector.OpenAsync(
                    new TestSplitHttpInternetOptions
                    {
                        ServerHost = "127.0.0.1",
                        ServerPort = port,
                        ServerName = "edge.example.com",
                        SecurityType = RuntimeInternetSecurityTypes.Tls,
                        SplitHttpMode = "stream-one",
                        SplitHttpPath = "stream-one-reuse?route=1",
                        ApplicationProtocols = ["h2"]
                    },
                    RuntimeInternetStack.Create(RuntimeInternetTransportProtocols.SplitHttp, RuntimeInternetSecurityTypes.Tls),
                    profile,
                    SystemDnsResolver.Instance,
                    transportInitializationData: null,
                    lifetimeCts.Token);

                await using var applicationStream = context.ApplicationStream;
                await applicationStream.WriteAsync(Encoding.ASCII.GetBytes(clientPayloads[index]), lifetimeCts.Token);
                await applicationStream.FlushAsync(lifetimeCts.Token);

                var responseBuffer = new byte[serverPayloads[index].Length];
                await ReadExactAsync(applicationStream, responseBuffer, lifetimeCts.Token);
                Assert.Equal(serverPayloads[index], Encoding.ASCII.GetString(responseBuffer));

                var eofBuffer = new byte[1];
                var eofRead = await applicationStream.ReadAsync(eofBuffer, lifetimeCts.Token);
                Assert.Equal(0, eofRead);
            }

            await Task.Delay(Http2TestDrainDelay, lifetimeCts.Token);
        }

        var captured = await serverTask;
        Assert.Equal(1, captured.ConnectionCount);
        Assert.Equal(2, captured.Exchanges.Count);
        Assert.Equal("POST", captured.Exchanges[0].Request.Method);
        Assert.Equal("POST", captured.Exchanges[1].Request.Method);
        Assert.Equal(clientPayloads[0], captured.Exchanges[0].PayloadText);
        Assert.Equal(clientPayloads[1], captured.Exchanges[1].PayloadText);
        Assert.Equal("/stream-one-reuse/?route=1", captured.Exchanges[0].Request.Target);
        Assert.Equal("/stream-one-reuse/?route=1", captured.Exchanges[1].Request.Target);
        Assert.Equal(["h2"], tlsSecurityFactory.ObservedApplicationProtocols);
        Assert.Equal("h2", tlsSecurityFactory.NegotiatedApplicationProtocol);
    }

    [Fact]
    public async Task OpenAsync_stream_one_over_explicit_h2_works_against_runtime_split_http_inbound_bridge()
    {
        using var lifetimeCts = new CancellationTokenSource(TimeSpan.FromSeconds(10));
        using var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();

        const string clientPayload = "h2-bridge-client";
        const string serverPayload = "h2-bridge-server";
        var port = ((IPEndPoint)listener.LocalEndpoint).Port;
        string? observedPayload = null;
        var bridge = new RuntimeSplitHttpInboundBridge(new RuntimeSplitHttpInboundOptions
        {
            Host = "edge.example.com",
            Path = "/stream-one/",
            Mode = "stream-one",
            XPaddingBytes = new RuntimeInt32Range
            {
                From = 1,
                To = 1
            }
        });
        var serverTask = ServeSplitHttpInboundBridgeAsync(
            listener,
            bridge,
            async (applicationStream, token) =>
            {
                var buffer = new byte[clientPayload.Length];
                await ReadExactAsync(applicationStream, buffer, token);
                observedPayload = Encoding.ASCII.GetString(buffer);
                await applicationStream.WriteAsync(Encoding.ASCII.GetBytes(serverPayload), token);
            },
            lifetimeCts.Token);
        var tlsSecurityFactory = new TestRuntimeInternetProfileFactory.RecordingFakeTlsSecurityFactory("h2");
        var profile = TestRuntimeInternetProfileFactory.CreateWithFakeTls(tlsSecurityFactory);

        var context = await RuntimeGrpcClientConnector.OpenAsync(
            new TestSplitHttpInternetOptions
            {
                ServerHost = "127.0.0.1",
                ServerPort = port,
                ServerName = "edge.example.com",
                SecurityType = RuntimeInternetSecurityTypes.Tls,
                SplitHttpMode = "stream-one",
                SplitHttpPath = "stream-one?route=bridge",
                SplitHttpXPaddingBytes = new RuntimeInt32Range
                {
                    From = 1,
                    To = 1
                },
                ApplicationProtocols = ["h2"]
            },
            RuntimeInternetStack.Create(RuntimeInternetTransportProtocols.SplitHttp, RuntimeInternetSecurityTypes.Tls),
            profile,
            SystemDnsResolver.Instance,
            transportInitializationData: null,
            lifetimeCts.Token);

        await using var applicationStream = context.ApplicationStream;
        await applicationStream.WriteAsync(Encoding.ASCII.GetBytes(clientPayload), lifetimeCts.Token);
        await applicationStream.FlushAsync(lifetimeCts.Token);

        var responseBuffer = new byte[serverPayload.Length];
        await ReadExactAsync(applicationStream, responseBuffer, lifetimeCts.Token);
        Assert.Equal(serverPayload, Encoding.ASCII.GetString(responseBuffer));

        var eofBuffer = new byte[1];
        var eofRead = await applicationStream.ReadAsync(eofBuffer, lifetimeCts.Token);
        Assert.Equal(0, eofRead);

        await serverTask;
        Assert.Equal(clientPayload, observedPayload);
        Assert.Equal(["h2"], tlsSecurityFactory.ObservedApplicationProtocols);
        Assert.Equal("h2", tlsSecurityFactory.NegotiatedApplicationProtocol);
    }

    [Fact]
    public async Task OpenAsync_stream_up_over_explicit_h2_reuses_single_http2_connection_for_downlink_and_upload()
    {
        using var lifetimeCts = new CancellationTokenSource(TimeSpan.FromSeconds(10));
        using var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();

        const string clientPayload = "h2-stream-up-client";
        const string serverPayload = "h2-stream-up-server";
        var port = ((IPEndPoint)listener.LocalEndpoint).Port;
        var serverTask = CaptureSplitHttpHttp2StreamUpExchangeAsync(
            listener,
            clientPayload,
            serverPayload,
            lifetimeCts.Token);
        var tlsSecurityFactory = new TestRuntimeInternetProfileFactory.RecordingFakeTlsSecurityFactory("h2");
        var profile = TestRuntimeInternetProfileFactory.CreateWithFakeTls(tlsSecurityFactory);

        var context = await RuntimeGrpcClientConnector.OpenAsync(
            new TestSplitHttpInternetOptions
            {
                ServerHost = "127.0.0.1",
                ServerPort = port,
                ServerName = "edge.example.com",
                SecurityType = RuntimeInternetSecurityTypes.Tls,
                SplitHttpMode = "stream-up",
                SplitHttpPath = "stream-up-h2?route=1",
                ApplicationProtocols = ["h2"]
            },
            RuntimeInternetStack.Create(RuntimeInternetTransportProtocols.SplitHttp, RuntimeInternetSecurityTypes.Tls),
            profile,
            SystemDnsResolver.Instance,
            transportInitializationData: null,
            lifetimeCts.Token);

        await using var applicationStream = context.ApplicationStream;
        await applicationStream.WriteAsync(Encoding.ASCII.GetBytes(clientPayload), lifetimeCts.Token);
        await applicationStream.FlushAsync(lifetimeCts.Token);

        var responseBuffer = new byte[serverPayload.Length];
        await ReadExactAsync(applicationStream, responseBuffer, lifetimeCts.Token);
        Assert.Equal(serverPayload, Encoding.ASCII.GetString(responseBuffer));

        var eofBuffer = new byte[1];
        var eofRead = await applicationStream.ReadAsync(eofBuffer, lifetimeCts.Token);
        Assert.Equal(0, eofRead);

        var captured = await serverTask;
        Assert.Equal(1, captured.ConnectionCount);
        Assert.Equal("GET", captured.DownlinkRequest.Method);
        Assert.Equal("POST", captured.UplinkRequest.Method);
        Assert.Equal("edge.example.com", captured.DownlinkRequest.Headers[":authority"]);
        Assert.Equal("edge.example.com", captured.UplinkRequest.Headers[":authority"]);
        Assert.Equal("https", captured.DownlinkRequest.Headers[":scheme"]);
        Assert.Equal("https", captured.UplinkRequest.Headers[":scheme"]);
        Assert.Equal("identity", captured.DownlinkRequest.Headers["accept-encoding"]);
        Assert.Equal("identity", captured.UplinkRequest.Headers["accept-encoding"]);
        Assert.Equal(RuntimeInternetHttpUtilities.DefaultChromeUserAgent, captured.DownlinkRequest.Headers["user-agent"]);
        Assert.Equal(RuntimeInternetHttpUtilities.DefaultChromeUserAgent, captured.UplinkRequest.Headers["user-agent"]);
        Assert.False(captured.DownlinkRequest.Headers.ContainsKey("content-type"));
        Assert.Equal("application/grpc", captured.UplinkRequest.Headers["content-type"]);
        Assert.Equal(clientPayload, captured.UplinkPayloadText);
        Assert.Equal(["h2"], tlsSecurityFactory.ObservedApplicationProtocols);
        Assert.Equal("h2", tlsSecurityFactory.NegotiatedApplicationProtocol);

        var downlinkTarget = new Uri("http://split.local" + captured.DownlinkRequest.Target);
        var uplinkTarget = new Uri("http://split.local" + captured.UplinkRequest.Target);
        Assert.Equal("route=1", downlinkTarget.Query.TrimStart('?'));
        Assert.Equal("route=1", uplinkTarget.Query.TrimStart('?'));

        var downlinkSegments = downlinkTarget.AbsolutePath.Split('/', StringSplitOptions.RemoveEmptyEntries);
        var uplinkSegments = uplinkTarget.AbsolutePath.Split('/', StringSplitOptions.RemoveEmptyEntries);
        Assert.Equal("stream-up-h2", downlinkSegments[0]);
        Assert.Equal("stream-up-h2", uplinkSegments[0]);
        Assert.True(Guid.TryParse(Uri.UnescapeDataString(downlinkSegments[1]), out _));
        Assert.Equal(Uri.UnescapeDataString(downlinkSegments[1]), Uri.UnescapeDataString(uplinkSegments[1]));
    }

    [Fact]
    public async Task OpenAsync_stream_up_over_explicit_h2_reuses_connection_across_sessions()
    {
        using var lifetimeCts = new CancellationTokenSource(TimeSpan.FromSeconds(10));
        using var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();

        var clientPayloads = new[] { "h2-stream-up-first", "h2-stream-up-second" };
        var serverPayloads = new[] { "h2-stream-up-response-1", "h2-stream-up-response-2" };
        var port = ((IPEndPoint)listener.LocalEndpoint).Port;
        var serverTask = CaptureSplitHttpHttp2StreamUpExchangeAcrossSessionsAsync(
            listener,
            clientPayloads,
            serverPayloads,
            lifetimeCts.Token);
        var tlsSecurityFactory = new TestRuntimeInternetProfileFactory.RecordingFakeTlsSecurityFactory("h2");
        var profile = TestRuntimeInternetProfileFactory.CreateWithFakeTls(tlsSecurityFactory);

        foreach (var index in Enumerable.Range(0, clientPayloads.Length))
        {
            var context = await RuntimeGrpcClientConnector.OpenAsync(
                new TestSplitHttpInternetOptions
                {
                    ServerHost = "127.0.0.1",
                    ServerPort = port,
                    ServerName = "edge.example.com",
                    SecurityType = RuntimeInternetSecurityTypes.Tls,
                    SplitHttpMode = "stream-up",
                    SplitHttpPath = "stream-up-reuse?route=1",
                    ApplicationProtocols = ["h2"]
                },
                RuntimeInternetStack.Create(RuntimeInternetTransportProtocols.SplitHttp, RuntimeInternetSecurityTypes.Tls),
                profile,
                SystemDnsResolver.Instance,
                transportInitializationData: null,
                lifetimeCts.Token);

            await using var applicationStream = context.ApplicationStream;
            await applicationStream.WriteAsync(Encoding.ASCII.GetBytes(clientPayloads[index]), lifetimeCts.Token);
            await applicationStream.FlushAsync(lifetimeCts.Token);

            var responseBuffer = new byte[serverPayloads[index].Length];
            await ReadExactAsync(applicationStream, responseBuffer, lifetimeCts.Token);
            Assert.Equal(serverPayloads[index], Encoding.ASCII.GetString(responseBuffer));

            var eofBuffer = new byte[1];
            var eofRead = await applicationStream.ReadAsync(eofBuffer, lifetimeCts.Token);
            Assert.Equal(0, eofRead);
        }

        var captured = await serverTask;
        Assert.Equal(1, captured.ConnectionCount);
        Assert.Equal(2, captured.Exchanges.Count);
        Assert.Equal(clientPayloads[0], captured.Exchanges[0].UplinkPayloadText);
        Assert.Equal(clientPayloads[1], captured.Exchanges[1].UplinkPayloadText);
        Assert.Equal("GET", captured.Exchanges[0].DownlinkRequest.Method);
        Assert.Equal("POST", captured.Exchanges[0].UplinkRequest.Method);
        Assert.Equal("GET", captured.Exchanges[1].DownlinkRequest.Method);
        Assert.Equal("POST", captured.Exchanges[1].UplinkRequest.Method);

        var firstDownlinkTarget = new Uri("http://split.local" + captured.Exchanges[0].DownlinkRequest.Target);
        var firstUplinkTarget = new Uri("http://split.local" + captured.Exchanges[0].UplinkRequest.Target);
        var secondDownlinkTarget = new Uri("http://split.local" + captured.Exchanges[1].DownlinkRequest.Target);
        var secondUplinkTarget = new Uri("http://split.local" + captured.Exchanges[1].UplinkRequest.Target);

        Assert.Equal("route=1", firstDownlinkTarget.Query.TrimStart('?'));
        Assert.Equal("route=1", firstUplinkTarget.Query.TrimStart('?'));
        Assert.Equal("route=1", secondDownlinkTarget.Query.TrimStart('?'));
        Assert.Equal("route=1", secondUplinkTarget.Query.TrimStart('?'));

        var firstDownlinkSegments = firstDownlinkTarget.AbsolutePath.Split('/', StringSplitOptions.RemoveEmptyEntries);
        var firstUplinkSegments = firstUplinkTarget.AbsolutePath.Split('/', StringSplitOptions.RemoveEmptyEntries);
        var secondDownlinkSegments = secondDownlinkTarget.AbsolutePath.Split('/', StringSplitOptions.RemoveEmptyEntries);
        var secondUplinkSegments = secondUplinkTarget.AbsolutePath.Split('/', StringSplitOptions.RemoveEmptyEntries);

        Assert.Equal("stream-up-reuse", firstDownlinkSegments[0]);
        Assert.Equal("stream-up-reuse", firstUplinkSegments[0]);
        Assert.Equal("stream-up-reuse", secondDownlinkSegments[0]);
        Assert.Equal("stream-up-reuse", secondUplinkSegments[0]);
        Assert.True(Guid.TryParse(Uri.UnescapeDataString(firstDownlinkSegments[1]), out _));
        Assert.True(Guid.TryParse(Uri.UnescapeDataString(secondDownlinkSegments[1]), out _));
        Assert.Equal(Uri.UnescapeDataString(firstDownlinkSegments[1]), Uri.UnescapeDataString(firstUplinkSegments[1]));
        Assert.Equal(Uri.UnescapeDataString(secondDownlinkSegments[1]), Uri.UnescapeDataString(secondUplinkSegments[1]));
        Assert.Equal(["h2"], tlsSecurityFactory.ObservedApplicationProtocols);
        Assert.Equal("h2", tlsSecurityFactory.NegotiatedApplicationProtocol);
    }

    [Fact]
    public async Task OpenAsync_stream_up_over_explicit_h2_with_download_settings_reuses_connections_across_sessions()
    {
        using var lifetimeCts = new CancellationTokenSource(TimeSpan.FromSeconds(10));
        using var downlinkListener = new TcpListener(IPAddress.Loopback, 0);
        using var uploadListener = new TcpListener(IPAddress.Loopback, 0);
        downlinkListener.Start();
        uploadListener.Start();

        var clientPayloads = new[] { "h2-dedicated-first", "h2-dedicated-second" };
        var serverPayloads = new[] { "h2-dedicated-response-1", "h2-dedicated-response-2" };
        var downlinkPort = ((IPEndPoint)downlinkListener.LocalEndpoint).Port;
        var uploadPort = ((IPEndPoint)uploadListener.LocalEndpoint).Port;
        var serverTask = CaptureSplitHttpHttp2StreamUpExchangeAcrossEndpointsAcrossSessionsAsync(
            downlinkListener,
            uploadListener,
            clientPayloads,
            serverPayloads,
            lifetimeCts.Token);
        var tlsSecurityFactory = new TestRuntimeInternetProfileFactory.RecordingFakeTlsSecurityFactory("h2");
        var profile = TestRuntimeInternetProfileFactory.CreateWithFakeTls(tlsSecurityFactory);

        foreach (var index in Enumerable.Range(0, clientPayloads.Length))
        {
            {
                var context = await RuntimeGrpcClientConnector.OpenAsync(
                    new TestSplitHttpInternetOptions
                    {
                        ServerHost = "127.0.0.1",
                        ServerPort = uploadPort,
                        ServerName = "upload.example.com",
                        SecurityType = RuntimeInternetSecurityTypes.Tls,
                        SplitHttpMode = "stream-up",
                        SplitHttpPath = "upload-h2-reuse?u=1",
                        SplitHttpDownloadSettings = new RuntimeSplitHttpDownloadOptions
                        {
                            ServerHost = "127.0.0.1",
                            ServerPort = downlinkPort,
                            Host = "down.example.com",
                            Path = "down-h2-reuse?d=1"
                        },
                        ApplicationProtocols = ["h2"]
                    },
                    RuntimeInternetStack.Create(RuntimeInternetTransportProtocols.SplitHttp, RuntimeInternetSecurityTypes.Tls),
                    profile,
                    SystemDnsResolver.Instance,
                    transportInitializationData: null,
                    lifetimeCts.Token);

                await using var applicationStream = context.ApplicationStream;
                await applicationStream.WriteAsync(Encoding.ASCII.GetBytes(clientPayloads[index]), lifetimeCts.Token);
                await applicationStream.FlushAsync(lifetimeCts.Token);

                var responseBuffer = new byte[serverPayloads[index].Length];
                await ReadExactAsync(applicationStream, responseBuffer, lifetimeCts.Token);
                Assert.Equal(serverPayloads[index], Encoding.ASCII.GetString(responseBuffer));

                var eofBuffer = new byte[1];
                var eofRead = await applicationStream.ReadAsync(eofBuffer, lifetimeCts.Token);
                Assert.Equal(0, eofRead);
            }

            await Task.Delay(Http2TestDrainDelay, lifetimeCts.Token);
        }

        var captured = await serverTask;
        Assert.Equal(1, captured.DownlinkConnectionCount);
        Assert.Equal(1, captured.UploadConnectionCount);
        Assert.Equal(2, captured.Exchanges.Count);

        foreach (var exchange in captured.Exchanges)
        {
            Assert.Equal("GET", exchange.DownlinkRequest.Method);
            Assert.Equal("POST", exchange.UplinkRequest.Method);
            Assert.Equal("down.example.com", exchange.DownlinkRequest.Headers[":authority"]);
            Assert.Equal("upload.example.com", exchange.UplinkRequest.Headers[":authority"]);
            Assert.Equal("https", exchange.DownlinkRequest.Headers[":scheme"]);
            Assert.Equal("https", exchange.UplinkRequest.Headers[":scheme"]);
            Assert.False(exchange.DownlinkRequest.Headers.ContainsKey("content-type"));
            Assert.Equal("application/grpc", exchange.UplinkRequest.Headers["content-type"]);
        }

        var firstDownlinkTarget = new Uri("http://split.local" + captured.Exchanges[0].DownlinkRequest.Target);
        var firstUplinkTarget = new Uri("http://split.local" + captured.Exchanges[0].UplinkRequest.Target);
        var secondDownlinkTarget = new Uri("http://split.local" + captured.Exchanges[1].DownlinkRequest.Target);
        var secondUplinkTarget = new Uri("http://split.local" + captured.Exchanges[1].UplinkRequest.Target);

        Assert.Equal("d=1", firstDownlinkTarget.Query.TrimStart('?'));
        Assert.Equal("u=1", firstUplinkTarget.Query.TrimStart('?'));
        Assert.Equal("d=1", secondDownlinkTarget.Query.TrimStart('?'));
        Assert.Equal("u=1", secondUplinkTarget.Query.TrimStart('?'));

        var firstDownlinkSegments = firstDownlinkTarget.AbsolutePath.Split('/', StringSplitOptions.RemoveEmptyEntries);
        var firstUplinkSegments = firstUplinkTarget.AbsolutePath.Split('/', StringSplitOptions.RemoveEmptyEntries);
        var secondDownlinkSegments = secondDownlinkTarget.AbsolutePath.Split('/', StringSplitOptions.RemoveEmptyEntries);
        var secondUplinkSegments = secondUplinkTarget.AbsolutePath.Split('/', StringSplitOptions.RemoveEmptyEntries);

        Assert.Equal("down-h2-reuse", firstDownlinkSegments[0]);
        Assert.Equal("upload-h2-reuse", firstUplinkSegments[0]);
        Assert.Equal("down-h2-reuse", secondDownlinkSegments[0]);
        Assert.Equal("upload-h2-reuse", secondUplinkSegments[0]);
        Assert.True(Guid.TryParse(Uri.UnescapeDataString(firstDownlinkSegments[1]), out _));
        Assert.True(Guid.TryParse(Uri.UnescapeDataString(secondDownlinkSegments[1]), out _));
        Assert.Equal(Uri.UnescapeDataString(firstDownlinkSegments[1]), Uri.UnescapeDataString(firstUplinkSegments[1]));
        Assert.Equal(Uri.UnescapeDataString(secondDownlinkSegments[1]), Uri.UnescapeDataString(secondUplinkSegments[1]));
        Assert.NotEqual(Uri.UnescapeDataString(firstDownlinkSegments[1]), Uri.UnescapeDataString(secondDownlinkSegments[1]));
        Assert.Equal(["h2"], tlsSecurityFactory.ObservedApplicationProtocols);
        Assert.Equal("h2", tlsSecurityFactory.NegotiatedApplicationProtocol);
    }

    [Fact]
    public async Task OpenAsync_stream_up_over_explicit_h2_works_against_runtime_split_http_inbound_bridge()
    {
        using var lifetimeCts = new CancellationTokenSource(TimeSpan.FromSeconds(10));
        using var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();

        const string clientPayload = "h2-bridge-stream-up-client";
        const string serverPayload = "h2-bridge-stream-up-server";
        var port = ((IPEndPoint)listener.LocalEndpoint).Port;
        string? observedPayload = null;
        var bridge = new RuntimeSplitHttpInboundBridge(new RuntimeSplitHttpInboundOptions
        {
            Host = "edge.example.com",
            Path = "/stream-up/",
            Mode = "stream-up",
            XPaddingBytes = new RuntimeInt32Range
            {
                From = 1,
                To = 1
            }
        });
        var serverTask = ServeSplitHttpInboundBridgeAsync(
            listener,
            bridge,
            connectionCount: 1,
            async (applicationStream, token) =>
            {
                var buffer = new byte[clientPayload.Length];
                await ReadExactAsync(applicationStream, buffer, token);
                observedPayload = Encoding.ASCII.GetString(buffer);
                await applicationStream.WriteAsync(Encoding.ASCII.GetBytes(serverPayload), token);
            },
            lifetimeCts.Token);
        var tlsSecurityFactory = new TestRuntimeInternetProfileFactory.RecordingFakeTlsSecurityFactory("h2");
        var profile = TestRuntimeInternetProfileFactory.CreateWithFakeTls(tlsSecurityFactory);

        var context = await RuntimeGrpcClientConnector.OpenAsync(
            new TestSplitHttpInternetOptions
            {
                ServerHost = "127.0.0.1",
                ServerPort = port,
                ServerName = "edge.example.com",
                SecurityType = RuntimeInternetSecurityTypes.Tls,
                SplitHttpMode = "stream-up",
                SplitHttpPath = "stream-up?route=bridge",
                SplitHttpXPaddingBytes = new RuntimeInt32Range
                {
                    From = 1,
                    To = 1
                },
                ApplicationProtocols = ["h2"]
            },
            RuntimeInternetStack.Create(RuntimeInternetTransportProtocols.SplitHttp, RuntimeInternetSecurityTypes.Tls),
            profile,
            SystemDnsResolver.Instance,
            transportInitializationData: null,
            lifetimeCts.Token);

        await using (var applicationStream = context.ApplicationStream)
        {
            await applicationStream.WriteAsync(Encoding.ASCII.GetBytes(clientPayload), lifetimeCts.Token);
            await applicationStream.FlushAsync(lifetimeCts.Token);

            var responseBuffer = new byte[serverPayload.Length];
            await ReadExactAsync(applicationStream, responseBuffer, lifetimeCts.Token);
            Assert.Equal(serverPayload, Encoding.ASCII.GetString(responseBuffer));

            var eofBuffer = new byte[1];
            var eofRead = await applicationStream.ReadAsync(eofBuffer, lifetimeCts.Token);
            Assert.Equal(0, eofRead);
        }

        await serverTask;
        Assert.Equal(clientPayload, observedPayload);
        Assert.Equal(["h2"], tlsSecurityFactory.ObservedApplicationProtocols);
        Assert.Equal("h2", tlsSecurityFactory.NegotiatedApplicationProtocol);
    }

    [Fact]
    public async Task OpenAsync_packet_up_over_explicit_h2_works_against_runtime_split_http_inbound_bridge()
    {
        using var lifetimeCts = new CancellationTokenSource(TimeSpan.FromSeconds(10));
        using var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();

        const string clientPayload = "abcdefghijkl";
        const string serverPayload = "h2-bridge-packet-up-server";
        var port = ((IPEndPoint)listener.LocalEndpoint).Port;
        string? observedPayload = null;
        var bridge = new RuntimeSplitHttpInboundBridge(new RuntimeSplitHttpInboundOptions
        {
            Host = "edge.example.com",
            Path = "/packet-up/",
            Mode = "packet-up",
            SeqPlacement = "query",
            XPaddingBytes = new RuntimeInt32Range
            {
                From = 1,
                To = 1
            }
        });
        var serverTask = ServeSplitHttpInboundBridgeAsync(
            listener,
            bridge,
            connectionCount: 2,
            async (applicationStream, token) =>
            {
                var buffer = new byte[clientPayload.Length];
                await ReadExactAsync(applicationStream, buffer, token);
                observedPayload = Encoding.ASCII.GetString(buffer);
                await applicationStream.WriteAsync(Encoding.ASCII.GetBytes(serverPayload), token);
            },
            lifetimeCts.Token);
        var tlsSecurityFactory = new TestRuntimeInternetProfileFactory.RecordingFakeTlsSecurityFactory("h2");
        var profile = TestRuntimeInternetProfileFactory.CreateWithFakeTls(tlsSecurityFactory);

        var context = await RuntimeGrpcClientConnector.OpenAsync(
            new TestSplitHttpInternetOptions
            {
                ServerHost = "127.0.0.1",
                ServerPort = port,
                ServerName = "edge.example.com",
                SecurityType = RuntimeInternetSecurityTypes.Tls,
                SplitHttpMode = "packet-up",
                SplitHttpPath = "packet-up?route=bridge",
                SplitHttpSeqPlacement = "query",
                SplitHttpScMaxEachPostBytes = new RuntimeInt32Range
                {
                    From = 6,
                    To = 6
                },
                SplitHttpXPaddingBytes = new RuntimeInt32Range
                {
                    From = 1,
                    To = 1
                },
                ApplicationProtocols = ["h2"]
            },
            RuntimeInternetStack.Create(RuntimeInternetTransportProtocols.SplitHttp, RuntimeInternetSecurityTypes.Tls),
            profile,
            SystemDnsResolver.Instance,
            transportInitializationData: null,
            lifetimeCts.Token);

        await using (var applicationStream = context.ApplicationStream)
        {
            await applicationStream.WriteAsync(Encoding.ASCII.GetBytes(clientPayload), lifetimeCts.Token);
            await applicationStream.FlushAsync(lifetimeCts.Token);

            var responseBuffer = new byte[serverPayload.Length];
            await ReadExactAsync(applicationStream, responseBuffer, lifetimeCts.Token);
            Assert.Equal(serverPayload, Encoding.ASCII.GetString(responseBuffer));

            var eofBuffer = new byte[1];
            var eofRead = await applicationStream.ReadAsync(eofBuffer, lifetimeCts.Token);
            Assert.Equal(0, eofRead);
        }

        await serverTask;
        Assert.Equal(clientPayload, observedPayload);
        Assert.Equal(["h2"], tlsSecurityFactory.ObservedApplicationProtocols);
        Assert.Equal("h2", tlsSecurityFactory.NegotiatedApplicationProtocol);
    }

    private static async Task<CapturedSplitHttpExchange> CaptureSplitHttpExchangeAsync(
        TcpListener listener,
        string expectedClientPayload,
        string serverPayload,
        SplitHttpDownlinkBodyMode downlinkBodyMode,
        CancellationToken cancellationToken)
    {
        using var downlinkClient = await listener.AcceptTcpClientAsync(cancellationToken);
        await using var downlinkStream = downlinkClient.GetStream();
        var downlinkRequest = await ReadHttpRequestAsync(downlinkStream, cancellationToken);

        await WriteAsciiAsync(
            downlinkStream,
            downlinkBodyMode switch
            {
                SplitHttpDownlinkBodyMode.Chunked => "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n",
                SplitHttpDownlinkBodyMode.ContentLength
                    => $"HTTP/1.1 200 OK\r\nContent-Length: {Encoding.ASCII.GetByteCount(serverPayload)}\r\nConnection: close\r\n\r\n",
                _ => throw new ArgumentOutOfRangeException(nameof(downlinkBodyMode))
            },
            cancellationToken);

        using var uplinkClient = await listener.AcceptTcpClientAsync(cancellationToken);
        await using var uplinkStream = uplinkClient.GetStream();
        var uplinkRequest = await ReadHttpRequestAsync(uplinkStream, cancellationToken);
        await WriteAsciiAsync(
            uplinkStream,
            "HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
            cancellationToken);

        var uplinkPayloadText = await ReadSingleChunkTextAsync(
            uplinkStream,
            Encoding.ASCII.GetByteCount(expectedClientPayload),
            cancellationToken);

        await WriteAsciiAsync(
            downlinkStream,
            downlinkBodyMode switch
            {
                SplitHttpDownlinkBodyMode.Chunked
                    => $"{Encoding.ASCII.GetByteCount(serverPayload):X}\r\n{serverPayload}\r\n0\r\n\r\n",
                SplitHttpDownlinkBodyMode.ContentLength => serverPayload,
                _ => throw new ArgumentOutOfRangeException(nameof(downlinkBodyMode))
            },
            cancellationToken);

        return new CapturedSplitHttpExchange(downlinkRequest, uplinkRequest, uplinkPayloadText);
    }

    private static async Task ServeSplitHttpInboundBridgeAsync(
        TcpListener listener,
        RuntimeSplitHttpInboundBridge bridge,
        Func<Stream, CancellationToken, Task> handler,
        CancellationToken cancellationToken)
        => await ServeSplitHttpInboundBridgeAsync(
                listener,
                bridge,
                connectionCount: 1,
                handler,
                cancellationToken)
            ;

    private static async Task ServeSplitHttpInboundBridgeAsync(
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

    private static async Task<CapturedSplitHttpExchange> CaptureSplitHttpExchangeAcrossEndpointsAsync(
        TcpListener downlinkListener,
        TcpListener uplinkListener,
        string expectedClientPayload,
        string serverPayload,
        SplitHttpDownlinkBodyMode downlinkBodyMode,
        CancellationToken cancellationToken)
    {
        using var downlinkClient = await downlinkListener.AcceptTcpClientAsync(cancellationToken);
        await using var downlinkStream = downlinkClient.GetStream();
        var downlinkRequest = await ReadHttpRequestAsync(downlinkStream, cancellationToken);

        await WriteAsciiAsync(
            downlinkStream,
            downlinkBodyMode switch
            {
                SplitHttpDownlinkBodyMode.Chunked => "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n",
                SplitHttpDownlinkBodyMode.ContentLength
                    => $"HTTP/1.1 200 OK\r\nContent-Length: {Encoding.ASCII.GetByteCount(serverPayload)}\r\nConnection: close\r\n\r\n",
                _ => throw new ArgumentOutOfRangeException(nameof(downlinkBodyMode))
            },
            cancellationToken);

        using var uplinkClient = await uplinkListener.AcceptTcpClientAsync(cancellationToken);
        await using var uplinkStream = uplinkClient.GetStream();
        var uplinkRequest = await ReadHttpRequestAsync(uplinkStream, cancellationToken);
        await WriteAsciiAsync(
            uplinkStream,
            "HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
            cancellationToken);

        var uplinkPayloadText = await ReadSingleChunkTextAsync(
            uplinkStream,
            Encoding.ASCII.GetByteCount(expectedClientPayload),
            cancellationToken);

        await WriteAsciiAsync(
            downlinkStream,
            downlinkBodyMode switch
            {
                SplitHttpDownlinkBodyMode.Chunked
                    => $"{Encoding.ASCII.GetByteCount(serverPayload):X}\r\n{serverPayload}\r\n0\r\n\r\n",
                SplitHttpDownlinkBodyMode.ContentLength => serverPayload,
                _ => throw new ArgumentOutOfRangeException(nameof(downlinkBodyMode))
            },
            cancellationToken);

        return new CapturedSplitHttpExchange(downlinkRequest, uplinkRequest, uplinkPayloadText);
    }

    private static async Task<CapturedSplitHttpPacketExchange> CaptureSplitHttpPacketExchangeAsync(
        TcpListener listener,
        string serverPayload,
        IReadOnlyList<string> expectedUploadPayloads,
        CancellationToken cancellationToken)
    {
        using var downlinkClient = await listener.AcceptTcpClientAsync(cancellationToken);
        await using var downlinkStream = downlinkClient.GetStream();
        var downlinkRequest = await ReadHttpRequestAsync(downlinkStream, cancellationToken);

        await WriteAsciiAsync(
            downlinkStream,
            "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n",
            cancellationToken);

        var uploadRequests = new List<CapturedPacketUpload>(expectedUploadPayloads.Count);
        foreach (var expectedPayload in expectedUploadPayloads)
        {
            using var uplinkClient = await listener.AcceptTcpClientAsync(cancellationToken);
            await using var uplinkStream = uplinkClient.GetStream();
            var request = await ReadHttpRequestAsync(uplinkStream, cancellationToken);
            var payloadText = await ReadContentLengthBodyTextAsync(uplinkStream, request.Headers, cancellationToken);
            uploadRequests.Add(new CapturedPacketUpload(request, payloadText, DateTime.UtcNow));

            await WriteAsciiAsync(
                uplinkStream,
                "HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
                cancellationToken);
        }

        await WriteAsciiAsync(
            downlinkStream,
            $"{Encoding.ASCII.GetByteCount(serverPayload):X}\r\n{serverPayload}\r\n0\r\n\r\n",
            cancellationToken);

        return new CapturedSplitHttpPacketExchange(downlinkRequest, uploadRequests);
    }

    private static async Task<CapturedSplitHttpPacketExchange> CaptureSplitHttpPacketExchangeAcrossEndpointsAsync(
        TcpListener downlinkListener,
        TcpListener uploadListener,
        string serverPayload,
        IReadOnlyList<string> expectedUploadPayloads,
        CancellationToken cancellationToken)
    {
        using var downlinkClient = await downlinkListener.AcceptTcpClientAsync(cancellationToken);
        await using var downlinkStream = downlinkClient.GetStream();
        var downlinkRequest = await ReadHttpRequestAsync(downlinkStream, cancellationToken);

        await WriteAsciiAsync(
            downlinkStream,
            "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n",
            cancellationToken);

        var uploadRequests = new List<CapturedPacketUpload>(expectedUploadPayloads.Count);
        foreach (var expectedPayload in expectedUploadPayloads)
        {
            using var uplinkClient = await uploadListener.AcceptTcpClientAsync(cancellationToken);
            await using var uplinkStream = uplinkClient.GetStream();
            var request = await ReadHttpRequestAsync(uplinkStream, cancellationToken);
            var payloadText = await ReadContentLengthBodyTextAsync(uplinkStream, request.Headers, cancellationToken);
            Assert.Equal(expectedPayload, payloadText);
            uploadRequests.Add(new CapturedPacketUpload(request, payloadText, DateTime.UtcNow));

            await WriteAsciiAsync(
                uplinkStream,
                "HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
                cancellationToken);
        }

        await WriteAsciiAsync(
            downlinkStream,
            $"{Encoding.ASCII.GetByteCount(serverPayload):X}\r\n{serverPayload}\r\n0\r\n\r\n",
            cancellationToken);

        return new CapturedSplitHttpPacketExchange(downlinkRequest, uploadRequests);
    }

    private static async Task<CapturedSplitHttpPacketExchange> CaptureSplitHttpPersistentPacketExchangeAsync(
        TcpListener listener,
        string serverPayload,
        IReadOnlyList<string> expectedUploadPayloads,
        CancellationToken cancellationToken)
    {
        using var downlinkClient = await listener.AcceptTcpClientAsync(cancellationToken);
        await using var downlinkStream = downlinkClient.GetStream();
        var downlinkRequest = await ReadHttpRequestAsync(downlinkStream, cancellationToken);

        await WriteAsciiAsync(
            downlinkStream,
            "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n",
            cancellationToken);

        using var uplinkClient = await listener.AcceptTcpClientAsync(cancellationToken);
        await using var uplinkStream = uplinkClient.GetStream();
        var uploadRequests = new List<CapturedPacketUpload>(expectedUploadPayloads.Count);
        for (var index = 0; index < expectedUploadPayloads.Count; index++)
        {
            var request = await ReadHttpRequestAsync(uplinkStream, cancellationToken);
            var payloadText = await ReadContentLengthBodyTextAsync(uplinkStream, request.Headers, cancellationToken);
            uploadRequests.Add(new CapturedPacketUpload(request, payloadText, DateTime.UtcNow));

            var keepAlive = index < expectedUploadPayloads.Count - 1;
            await WriteAsciiAsync(
                uplinkStream,
                keepAlive
                    ? "HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: keep-alive\r\n\r\n"
                    : "HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
                cancellationToken);
        }

        await WriteAsciiAsync(
            downlinkStream,
            $"{Encoding.ASCII.GetByteCount(serverPayload):X}\r\n{serverPayload}\r\n0\r\n\r\n",
            cancellationToken);

        return new CapturedSplitHttpPacketExchange(downlinkRequest, uploadRequests, UploadConnectionCount: 1);
    }

    private static async Task<CapturedSplitHttpPacketExchange> CaptureSplitHttpPersistentPacketExchangeWithDelayedFirstUploadResponseAsync(
        TcpListener listener,
        string serverPayload,
        IReadOnlyList<string> expectedUploadPayloads,
        CancellationToken cancellationToken)
    {
        Assert.Equal(2, expectedUploadPayloads.Count);

        using var downlinkClient = await listener.AcceptTcpClientAsync(cancellationToken);
        await using var downlinkStream = downlinkClient.GetStream();
        var downlinkRequest = await ReadHttpRequestAsync(downlinkStream, cancellationToken);

        await WriteAsciiAsync(
            downlinkStream,
            "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n",
            cancellationToken);

        using var uplinkClient = await listener.AcceptTcpClientAsync(cancellationToken);
        await using var uplinkStream = uplinkClient.GetStream();
        var uploadRequest1 = await ReadHttpRequestAsync(uplinkStream, cancellationToken);
        var payloadText1 = await ReadContentLengthBodyTextAsync(uplinkStream, uploadRequest1.Headers, cancellationToken);
        Assert.Equal(expectedUploadPayloads[0], payloadText1);

        var uploadRequest2 = await ReadHttpRequestAsync(uplinkStream, cancellationToken);
        var payloadText2 = await ReadContentLengthBodyTextAsync(uplinkStream, uploadRequest2.Headers, cancellationToken);
        Assert.Equal(expectedUploadPayloads[1], payloadText2);

        await WriteAsciiAsync(
            uplinkStream,
            "HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: keep-alive\r\n\r\n",
            cancellationToken);
        await WriteAsciiAsync(
            uplinkStream,
            "HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
            cancellationToken);

        await WriteAsciiAsync(
            downlinkStream,
            $"{Encoding.ASCII.GetByteCount(serverPayload):X}\r\n{serverPayload}\r\n0\r\n\r\n",
            cancellationToken);

        await Task.Delay(Http2TestDrainDelay, cancellationToken);

        return new CapturedSplitHttpPacketExchange(
            downlinkRequest,
            [
                new CapturedPacketUpload(uploadRequest1, payloadText1, DateTime.UtcNow),
                new CapturedPacketUpload(uploadRequest2, payloadText2, DateTime.UtcNow)
            ],
            UploadConnectionCount: 1);
    }

    private static async Task<CapturedMultiSessionSplitHttpPacketExchange> CaptureSplitHttpPersistentPacketExchangeAcrossSessionsAsync(
        TcpListener listener,
        IReadOnlyList<string> serverPayloads,
        IReadOnlyList<string> expectedUploadPayloads,
        CancellationToken cancellationToken)
    {
        Assert.Equal(2, serverPayloads.Count);
        Assert.Equal(2, expectedUploadPayloads.Count);

        var downlinkRequests = new List<SplitHttpRequest>(2);
        var uploadRequests = new List<CapturedPacketUpload>(2);

        using var downlinkClient1 = await listener.AcceptTcpClientAsync(cancellationToken);
        await using var downlinkStream1 = downlinkClient1.GetStream();
        downlinkRequests.Add(await ReadHttpRequestAsync(downlinkStream1, cancellationToken));

        await WriteAsciiAsync(
            downlinkStream1,
            "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n",
            cancellationToken);

        using var uploadClient = await listener.AcceptTcpClientAsync(cancellationToken);
        await using var uploadStream = uploadClient.GetStream();
        var uploadRequest1 = await ReadHttpRequestAsync(uploadStream, cancellationToken);
        var payloadText1 = await ReadContentLengthBodyTextAsync(uploadStream, uploadRequest1.Headers, cancellationToken);
        Assert.Equal(expectedUploadPayloads[0], payloadText1);
        uploadRequests.Add(new CapturedPacketUpload(uploadRequest1, payloadText1, DateTime.UtcNow));

        await WriteAsciiAsync(
            uploadStream,
            "HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: keep-alive\r\n\r\n",
            cancellationToken);

        await WriteAsciiAsync(
            downlinkStream1,
            $"{Encoding.ASCII.GetByteCount(serverPayloads[0]):X}\r\n{serverPayloads[0]}\r\n0\r\n\r\n",
            cancellationToken);

        using var downlinkClient2 = await listener.AcceptTcpClientAsync(cancellationToken);
        await using var downlinkStream2 = downlinkClient2.GetStream();
        downlinkRequests.Add(await ReadHttpRequestAsync(downlinkStream2, cancellationToken));

        await WriteAsciiAsync(
            downlinkStream2,
            "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n",
            cancellationToken);

        var uploadRequest2 = await ReadHttpRequestAsync(uploadStream, cancellationToken);
        var payloadText2 = await ReadContentLengthBodyTextAsync(uploadStream, uploadRequest2.Headers, cancellationToken);
        Assert.Equal(expectedUploadPayloads[1], payloadText2);
        uploadRequests.Add(new CapturedPacketUpload(uploadRequest2, payloadText2, DateTime.UtcNow));

        await WriteAsciiAsync(
            uploadStream,
            "HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
            cancellationToken);

        await WriteAsciiAsync(
            downlinkStream2,
            $"{Encoding.ASCII.GetByteCount(serverPayloads[1]):X}\r\n{serverPayloads[1]}\r\n0\r\n\r\n",
            cancellationToken);

        return new CapturedMultiSessionSplitHttpPacketExchange(
            downlinkRequests,
            uploadRequests,
            UploadConnectionCount: 1);
    }

    private static async Task<CapturedSplitHttpPacketExchange> CaptureSplitHttpPacketExchangeAsync(
        TcpListener listener,
        string serverPayload,
        IReadOnlyList<string> expectedUploadPayloads,
        IReadOnlyList<int> uploadConnectionPattern,
        CancellationToken cancellationToken)
    {
        Assert.Equal(expectedUploadPayloads.Count, uploadConnectionPattern.Count);

        using var downlinkClient = await listener.AcceptTcpClientAsync(cancellationToken);
        await using var downlinkStream = downlinkClient.GetStream();
        var downlinkRequest = await ReadHttpRequestAsync(downlinkStream, cancellationToken);

        await WriteAsciiAsync(
            downlinkStream,
            "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n",
            cancellationToken);

        var uploadRequests = new List<CapturedPacketUpload>(expectedUploadPayloads.Count);
        var uploadClients = new Dictionary<int, TcpClient>();
        var uploadStreams = new Dictionary<int, NetworkStream>();

        try
        {
            for (var index = 0; index < expectedUploadPayloads.Count; index++)
            {
                var connectionIndex = uploadConnectionPattern[index];
                if (!uploadClients.TryGetValue(connectionIndex, out var uploadClient))
                {
                    uploadClient = await listener.AcceptTcpClientAsync(cancellationToken);
                    uploadClients[connectionIndex] = uploadClient;
                    uploadStreams[connectionIndex] = uploadClient.GetStream();
                }

                var uploadStream = uploadStreams[connectionIndex];
                var request = await ReadHttpRequestAsync(uploadStream, cancellationToken);
                var payloadText = await ReadContentLengthBodyTextAsync(uploadStream, request.Headers, cancellationToken);
                Assert.Equal(expectedUploadPayloads[index], payloadText);
                uploadRequests.Add(new CapturedPacketUpload(request, payloadText, DateTime.UtcNow));

                var keepAlive = uploadConnectionPattern.Skip(index + 1).Contains(connectionIndex);
                await WriteAsciiAsync(
                    uploadStream,
                    keepAlive
                        ? "HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: keep-alive\r\n\r\n"
                        : "HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
                    cancellationToken);
            }
        }
        finally
        {
            foreach (var uploadClient in uploadClients.Values)
            {
                uploadClient.Dispose();
            }
        }

        await WriteAsciiAsync(
            downlinkStream,
            $"{Encoding.ASCII.GetByteCount(serverPayload):X}\r\n{serverPayload}\r\n0\r\n\r\n",
            cancellationToken);

        return new CapturedSplitHttpPacketExchange(
            downlinkRequest,
            uploadRequests,
            UploadConnectionCount: uploadClients.Count);
    }

    private static async Task<CapturedMultiSessionSplitHttpPacketExchange> CaptureSplitHttpPacketExchangeAcrossSessionsAsync(
        TcpListener listener,
        IReadOnlyList<string> serverPayloads,
        IReadOnlyList<string> expectedUploadPayloads,
        IReadOnlyList<int> uploadConnectionPattern,
        CancellationToken cancellationToken)
    {
        Assert.Equal(serverPayloads.Count, expectedUploadPayloads.Count);
        Assert.Equal(serverPayloads.Count, uploadConnectionPattern.Count);

        var downlinkRequests = new List<SplitHttpRequest>(serverPayloads.Count);
        var uploadRequests = new List<CapturedPacketUpload>(expectedUploadPayloads.Count);
        var uploadClients = new Dictionary<int, TcpClient>();
        var uploadStreams = new Dictionary<int, NetworkStream>();

        try
        {
            for (var index = 0; index < serverPayloads.Count; index++)
            {
                using var downlinkClient = await listener.AcceptTcpClientAsync(cancellationToken);
                await using var downlinkStream = downlinkClient.GetStream();
                downlinkRequests.Add(await ReadHttpRequestAsync(downlinkStream, cancellationToken));

                await WriteAsciiAsync(
                    downlinkStream,
                    "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n",
                    cancellationToken);

                var connectionIndex = uploadConnectionPattern[index];
                if (!uploadClients.TryGetValue(connectionIndex, out var uploadClient))
                {
                    uploadClient = await listener.AcceptTcpClientAsync(cancellationToken);
                    uploadClients[connectionIndex] = uploadClient;
                    uploadStreams[connectionIndex] = uploadClient.GetStream();
                }

                var uploadStream = uploadStreams[connectionIndex];
                var uploadRequest = await ReadHttpRequestAsync(uploadStream, cancellationToken);
                var payloadText = await ReadContentLengthBodyTextAsync(uploadStream, uploadRequest.Headers, cancellationToken);
                Assert.Equal(expectedUploadPayloads[index], payloadText);
                uploadRequests.Add(new CapturedPacketUpload(uploadRequest, payloadText, DateTime.UtcNow));

                var keepAlive = uploadConnectionPattern.Skip(index + 1).Contains(connectionIndex);
                await WriteAsciiAsync(
                    uploadStream,
                    keepAlive
                        ? "HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: keep-alive\r\n\r\n"
                        : "HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
                    cancellationToken);

                await WriteAsciiAsync(
                    downlinkStream,
                    $"{Encoding.ASCII.GetByteCount(serverPayloads[index]):X}\r\n{serverPayloads[index]}\r\n0\r\n\r\n",
                    cancellationToken);
            }
        }
        finally
        {
            foreach (var uploadClient in uploadClients.Values)
            {
                uploadClient.Dispose();
            }
        }

        return new CapturedMultiSessionSplitHttpPacketExchange(
            downlinkRequests,
            uploadRequests,
            UploadConnectionCount: uploadClients.Count);
    }

    private static async Task<CapturedSplitHttpPacketExchange> CaptureSplitHttpHttp2PacketExchangeAsync(
        TcpListener listener,
        string serverPayload,
        IReadOnlyList<string> expectedUploadPayloads,
        CancellationToken cancellationToken)
        => await CaptureSplitHttpHttp2PacketExchangeAsync(
                listener,
                serverPayload,
                expectedUploadPayloads,
                uploadConnectionPattern: Enumerable.Repeat(0, expectedUploadPayloads.Count).ToArray(),
                cancellationToken)
            ;

    private static async Task<CapturedSplitHttpPacketExchange> CaptureSplitHttpHttp2PacketExchangeAsync(
        TcpListener listener,
        string serverPayload,
        IReadOnlyList<string> expectedUploadPayloads,
        IReadOnlyList<int> uploadConnectionPattern,
        CancellationToken cancellationToken)
    {
        Assert.Equal(expectedUploadPayloads.Count, uploadConnectionPattern.Count);

        using var downlinkClient = await listener.AcceptTcpClientAsync(cancellationToken);
        await using var downlinkStream = downlinkClient.GetStream();
        await ExpectHttp2ClientPrefaceAsync(downlinkStream, cancellationToken);
        var downlinkRequest = await ReadHttp2SplitHttpRequestAsync(
            downlinkStream,
            expectedMethod: "GET",
            expectedStreamId: 1,
            cancellationToken);

        await WriteHttp2TestFrameAsync(
            downlinkStream,
            Http2SplitHttpFrameTypes.Headers,
            Http2SplitHttpFrameFlags.EndHeaders,
            streamId: 1,
            payload: BuildHttp2Status200HeaderBlock(),
            cancellationToken);

        var uploadRequests = new List<CapturedPacketUpload>(expectedUploadPayloads.Count);
        var uploadClients = new Dictionary<int, TcpClient>();
        var uploadStreams = new Dictionary<int, NetworkStream>();
        var uploadNextStreamIds = new Dictionary<int, int>();

        try
        {
            for (var index = 0; index < expectedUploadPayloads.Count; index++)
            {
                var connectionIndex = uploadConnectionPattern[index];
                if (!uploadClients.TryGetValue(connectionIndex, out var uploadClient))
                {
                    uploadClient = await listener.AcceptTcpClientAsync(cancellationToken);
                    uploadClients[connectionIndex] = uploadClient;
                    var uploadStream = uploadClient.GetStream();
                    uploadStreams[connectionIndex] = uploadStream;
                    uploadNextStreamIds[connectionIndex] = 1;
                    await ExpectHttp2ClientPrefaceAsync(uploadStream, cancellationToken);
                }

                var streamId = uploadNextStreamIds[connectionIndex];
                var uploadStreamForRequest = uploadStreams[connectionIndex];
                uploadRequests.Add(
                    await ReadHttp2PacketUploadAsync(
                            uploadStreamForRequest,
                            expectedUploadPayloads[index],
                            streamId,
                            cancellationToken)
                        );
                uploadNextStreamIds[connectionIndex] = streamId + 2;
            }
            await WriteHttp2TestFrameAsync(
                downlinkStream,
                Http2SplitHttpFrameTypes.Data,
                Http2SplitHttpFrameFlags.EndStream,
                streamId: 1,
                payload: Encoding.ASCII.GetBytes(serverPayload),
                cancellationToken);

            await Task.Delay(Http2TestDrainDelay, cancellationToken);

            return new CapturedSplitHttpPacketExchange(
                downlinkRequest,
                uploadRequests,
                UploadConnectionCount: uploadClients.Count);
        }
        finally
        {
            foreach (var uploadClient in uploadClients.Values)
            {
                uploadClient.Dispose();
            }
        }
    }

    private static async Task<CapturedHttp2StreamUpExchange> CaptureSplitHttpHttp2StreamUpExchangeAsync(
        TcpListener listener,
        string expectedClientPayload,
        string serverPayload,
        CancellationToken cancellationToken)
    {
        using var client = await listener.AcceptTcpClientAsync(cancellationToken);
        await using var stream = client.GetStream();
        await ExpectHttp2ClientPrefaceAsync(stream, cancellationToken);

        var exchange = await ReadHttp2StreamUpExchangeAsync(
            stream,
            expectedClientPayload,
            serverPayload,
            downlinkStreamId: 1,
            uploadStreamId: 3,
            cancellationToken);

        var connectionCount = 1;
        using var extraAcceptCts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        extraAcceptCts.CancelAfter(Http2TestDrainDelay);
        try
        {
            using var extraClient = await listener.AcceptTcpClientAsync(extraAcceptCts.Token);
            connectionCount = 2;
        }
        catch (OperationCanceledException) when (!cancellationToken.IsCancellationRequested)
        {
        }

        return new CapturedHttp2StreamUpExchange(
            exchange.DownlinkRequest,
            exchange.UplinkRequest,
            exchange.UplinkPayloadText,
            connectionCount);
    }

    private static async Task<CapturedHttp2StreamUpExchange> CaptureSplitHttpHttp2StreamUpExchangeAcrossEndpointsAsync(
        TcpListener downlinkListener,
        TcpListener uploadListener,
        string expectedClientPayload,
        string serverPayload,
        CancellationToken cancellationToken)
    {
        using var downlinkClient = await downlinkListener.AcceptTcpClientAsync(cancellationToken);
        await using var downlinkStream = downlinkClient.GetStream();
        await ExpectHttp2ClientPrefaceAsync(downlinkStream, cancellationToken);
        var downlinkRequest = await ReadHttp2StreamUpDownlinkRequestAsync(
            downlinkStream,
            streamId: 1,
            cancellationToken);

        using var uploadClient = await uploadListener.AcceptTcpClientAsync(cancellationToken);
        await using var uploadStream = uploadClient.GetStream();
        await ExpectHttp2ClientPrefaceAsync(uploadStream, cancellationToken);
        var (uploadRequest, uplinkPayloadText) = await ReadHttp2StreamUpUploadAsync(
            uploadStream,
            expectedClientPayload,
            streamId: 1,
            cancellationToken);

        await CompleteHttp2PacketUploadResponseAsync(uploadStream, streamId: 1, cancellationToken);
        await CompleteHttp2StreamUpDownlinkResponseAsync(
            downlinkStream,
            streamId: 1,
            serverPayload,
            cancellationToken);
        await Task.Delay(Http2TestDrainDelay, cancellationToken);

        return new CapturedHttp2StreamUpExchange(
            downlinkRequest,
            uploadRequest,
            uplinkPayloadText,
            ConnectionCount: 2);
    }

    private static async Task<CapturedMultiSessionHttp2StreamUpExchange> CaptureSplitHttpHttp2StreamUpExchangeAcrossSessionsAsync(
        TcpListener listener,
        IReadOnlyList<string> expectedClientPayloads,
        IReadOnlyList<string> serverPayloads,
        CancellationToken cancellationToken)
    {
        Assert.Equal(2, expectedClientPayloads.Count);
        Assert.Equal(2, serverPayloads.Count);

        using var firstClient = await listener.AcceptTcpClientAsync(cancellationToken);
        await using var firstStream = firstClient.GetStream();
        await ExpectHttp2ClientPrefaceAsync(firstStream, cancellationToken);

        var exchanges = new List<CapturedHttp2StreamUpExchange>(2)
        {
            await ReadHttp2StreamUpExchangeAsync(
                firstStream,
                expectedClientPayloads[0],
                serverPayloads[0],
                downlinkStreamId: 1,
                uploadStreamId: 3,
                cancellationToken)
        };
        await Task.Delay(Http2TestDrainDelay, cancellationToken);

        try
        {
            using var sameConnectionCts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
            sameConnectionCts.CancelAfter(TimeSpan.FromSeconds(2));
            exchanges.Add(
                await ReadHttp2StreamUpExchangeAsync(
                    firstStream,
                    expectedClientPayloads[1],
                    serverPayloads[1],
                    downlinkStreamId: 5,
                    uploadStreamId: 7,
                    sameConnectionCts.Token));
            return new CapturedMultiSessionHttp2StreamUpExchange(exchanges, ConnectionCount: 1);
        }
        catch (OperationCanceledException) when (!cancellationToken.IsCancellationRequested)
        {
            using var secondClient = await listener.AcceptTcpClientAsync(cancellationToken);
            await using var secondStream = secondClient.GetStream();
            await ExpectHttp2ClientPrefaceAsync(secondStream, cancellationToken);
            exchanges.Add(
                await ReadHttp2StreamUpExchangeAsync(
                    secondStream,
                    expectedClientPayloads[1],
                    serverPayloads[1],
                    downlinkStreamId: 1,
                    uploadStreamId: 3,
                    cancellationToken));
            return new CapturedMultiSessionHttp2StreamUpExchange(exchanges, ConnectionCount: 2);
        }
    }

    private static async Task<CapturedMultiEndpointHttp2StreamUpExchange> CaptureSplitHttpHttp2StreamUpExchangeAcrossEndpointsAcrossSessionsAsync(
        TcpListener downlinkListener,
        TcpListener uploadListener,
        IReadOnlyList<string> expectedClientPayloads,
        IReadOnlyList<string> serverPayloads,
        CancellationToken cancellationToken)
    {
        Assert.Equal(2, expectedClientPayloads.Count);
        Assert.Equal(2, serverPayloads.Count);

        using var firstDownlinkClient = await downlinkListener.AcceptTcpClientAsync(cancellationToken);
        await using var firstDownlinkStream = firstDownlinkClient.GetStream();
        await ExpectHttp2ClientPrefaceAsync(firstDownlinkStream, cancellationToken);
        var firstDownlinkRequest = await ReadHttp2StreamUpDownlinkRequestAsync(
            firstDownlinkStream,
            streamId: 1,
            cancellationToken);

        using var firstUploadClient = await uploadListener.AcceptTcpClientAsync(cancellationToken);
        await using var firstUploadStream = firstUploadClient.GetStream();
        await ExpectHttp2ClientPrefaceAsync(firstUploadStream, cancellationToken);
        var (firstUploadRequest, firstUplinkPayloadText) = await ReadHttp2StreamUpUploadAsync(
            firstUploadStream,
            expectedClientPayloads[0],
            streamId: 1,
            cancellationToken);
        await CompleteHttp2PacketUploadResponseAsync(firstUploadStream, streamId: 1, cancellationToken);
        await CompleteHttp2StreamUpDownlinkResponseAsync(
            firstDownlinkStream,
            streamId: 1,
            serverPayloads[0],
            cancellationToken);
        await Task.Delay(Http2TestDrainDelay, cancellationToken);

        var exchanges = new List<CapturedHttp2StreamUpExchange>(2)
        {
            new CapturedHttp2StreamUpExchange(
                firstDownlinkRequest,
                firstUploadRequest,
                firstUplinkPayloadText,
                ConnectionCount: 1)
        };

        TcpClient? secondDownlinkClient = null;
        TcpClient? secondUploadClient = null;
        Stream secondDownlinkStream = firstDownlinkStream;
        Stream secondUploadStream = firstUploadStream;
        var downlinkConnectionCount = 1;
        var uploadConnectionCount = 1;
        try
        {
            var secondDownlinkResult = await WaitForNextHttp2StreamUpDownlinkAsync(
                firstDownlinkStream,
                reusedStreamId: 3,
                downlinkListener,
                cancellationToken);
            secondDownlinkClient = secondDownlinkResult.Client;
            secondDownlinkStream = secondDownlinkResult.Stream;
            downlinkConnectionCount = secondDownlinkResult.ConnectionCount;

            var secondUploadResult = await WaitForNextHttp2StreamUpUploadAsync(
                firstUploadStream,
                expectedClientPayloads[1],
                reusedStreamId: 3,
                uploadListener,
                cancellationToken);
            secondUploadClient = secondUploadResult.Client;
            secondUploadStream = secondUploadResult.Stream;
            uploadConnectionCount = secondUploadResult.ConnectionCount;

            await CompleteHttp2PacketUploadResponseAsync(
                    secondUploadStream,
                    secondUploadResult.StreamId,
                    cancellationToken)
                ;
            await CompleteHttp2StreamUpDownlinkResponseAsync(
                secondDownlinkStream,
                secondDownlinkResult.StreamId,
                serverPayloads[1],
                cancellationToken);

            exchanges.Add(new CapturedHttp2StreamUpExchange(
                secondDownlinkResult.Request,
                secondUploadResult.Request,
                secondUploadResult.PayloadText,
                ConnectionCount: 1));
            return new CapturedMultiEndpointHttp2StreamUpExchange(
                exchanges,
                downlinkConnectionCount,
                uploadConnectionCount);
        }
        finally
        {
            secondDownlinkClient?.Dispose();
            secondUploadClient?.Dispose();
        }
    }

    private static async Task<CapturedMultiSessionSplitHttpPacketExchange> CaptureSplitHttpHttp2PacketExchangeAcrossSessionsAsync(
        TcpListener listener,
        IReadOnlyList<string> serverPayloads,
        IReadOnlyList<string> expectedUploadPayloads,
        IReadOnlyList<int> uploadConnectionPattern,
        CancellationToken cancellationToken)
    {
        Assert.Equal(serverPayloads.Count, expectedUploadPayloads.Count);
        Assert.Equal(serverPayloads.Count, uploadConnectionPattern.Count);

        var downlinkRequests = new List<SplitHttpRequest>(serverPayloads.Count);
        var uploadRequests = new List<CapturedPacketUpload>(expectedUploadPayloads.Count);
        var uploadClients = new Dictionary<int, TcpClient>();
        var uploadStreams = new Dictionary<int, NetworkStream>();
        var uploadNextStreamIds = new Dictionary<int, int>();

        try
        {
            for (var index = 0; index < serverPayloads.Count; index++)
            {
                using var downlinkClient = await listener.AcceptTcpClientAsync(cancellationToken);
                await using var downlinkStream = downlinkClient.GetStream();
                await ExpectHttp2ClientPrefaceAsync(downlinkStream, cancellationToken);
                downlinkRequests.Add(
                    await ReadHttp2SplitHttpRequestAsync(
                            downlinkStream,
                            expectedMethod: "GET",
                            expectedStreamId: 1,
                            cancellationToken)
                        );

                await WriteHttp2TestFrameAsync(
                    downlinkStream,
                    Http2SplitHttpFrameTypes.Headers,
                    Http2SplitHttpFrameFlags.EndHeaders,
                    streamId: 1,
                    payload: BuildHttp2Status200HeaderBlock(),
                    cancellationToken);

                var connectionIndex = uploadConnectionPattern[index];
                if (!uploadClients.TryGetValue(connectionIndex, out var uploadClient))
                {
                    uploadClient = await listener.AcceptTcpClientAsync(cancellationToken);
                    uploadClients[connectionIndex] = uploadClient;
                    var uploadStream = uploadClient.GetStream();
                    uploadStreams[connectionIndex] = uploadStream;
                    uploadNextStreamIds[connectionIndex] = 1;
                    await ExpectHttp2ClientPrefaceAsync(uploadStream, cancellationToken);
                }

                var streamId = uploadNextStreamIds[connectionIndex];
                var uploadStreamForRequest = uploadStreams[connectionIndex];
                uploadRequests.Add(
                    await ReadHttp2PacketUploadAsync(
                            uploadStreamForRequest,
                            expectedUploadPayloads[index],
                            streamId,
                            cancellationToken)
                        );
                uploadNextStreamIds[connectionIndex] = streamId + 2;

                await WriteHttp2TestFrameAsync(
                    downlinkStream,
                    Http2SplitHttpFrameTypes.Data,
                    Http2SplitHttpFrameFlags.EndStream,
                    streamId: 1,
                    payload: Encoding.ASCII.GetBytes(serverPayloads[index]),
                    cancellationToken);

                await Task.Delay(Http2TestDrainDelay, cancellationToken);
            }

            return new CapturedMultiSessionSplitHttpPacketExchange(
                downlinkRequests,
                uploadRequests,
                UploadConnectionCount: uploadClients.Count);
        }
        finally
        {
            foreach (var uploadClient in uploadClients.Values)
            {
                uploadClient.Dispose();
            }
        }
    }

    private static async Task<CapturedSplitHttpPacketExchange> CaptureSplitHttpHttp2PacketExchangeWithDelayedFirstUploadResponseAsync(
        TcpListener listener,
        string serverPayload,
        IReadOnlyList<string> expectedUploadPayloads,
        CancellationToken cancellationToken)
    {
        Assert.Equal(2, expectedUploadPayloads.Count);

        using var downlinkClient = await listener.AcceptTcpClientAsync(cancellationToken);
        await using var downlinkStream = downlinkClient.GetStream();
        await ExpectHttp2ClientPrefaceAsync(downlinkStream, cancellationToken);
        var downlinkRequest = await ReadHttp2SplitHttpRequestAsync(
            downlinkStream,
            expectedMethod: "GET",
            expectedStreamId: 1,
            cancellationToken);

        await WriteHttp2TestFrameAsync(
            downlinkStream,
            Http2SplitHttpFrameTypes.Headers,
            Http2SplitHttpFrameFlags.EndHeaders,
            streamId: 1,
            payload: BuildHttp2Status200HeaderBlock(),
            cancellationToken);

        using var uploadClient = await listener.AcceptTcpClientAsync(cancellationToken);
        await using var uploadStream = uploadClient.GetStream();
        await ExpectHttp2ClientPrefaceAsync(uploadStream, cancellationToken);

        var uploadRequest1 = await ReadHttp2PacketUploadAsync(
            uploadStream,
            expectedUploadPayloads[0],
            streamId: 1,
            cancellationToken,
            sendResponse: false);
        var uploadRequest2 = await ReadHttp2PacketUploadAsync(
            uploadStream,
            expectedUploadPayloads[1],
            streamId: 3,
            cancellationToken,
            sendResponse: false);

        await CompleteHttp2PacketUploadResponseAsync(uploadStream, streamId: 1, cancellationToken);
        await CompleteHttp2PacketUploadResponseAsync(uploadStream, streamId: 3, cancellationToken);

        await WriteHttp2TestFrameAsync(
            downlinkStream,
            Http2SplitHttpFrameTypes.Data,
            Http2SplitHttpFrameFlags.EndStream,
            streamId: 1,
            payload: Encoding.ASCII.GetBytes(serverPayload),
            cancellationToken);

        await Task.Delay(Http2TestDrainDelay, cancellationToken);

        return new CapturedSplitHttpPacketExchange(
            downlinkRequest,
            [uploadRequest1, uploadRequest2],
            UploadConnectionCount: 1);
    }

    private static async Task<CapturedStreamOneExchange> CaptureSplitHttpStreamOneExchangeAsync(
        TcpListener listener,
        string expectedClientPayload,
        string serverPayload,
        CancellationToken cancellationToken)
    {
        using var client = await listener.AcceptTcpClientAsync(cancellationToken);
        await using var stream = client.GetStream();
        var request = await ReadHttpRequestAsync(stream, cancellationToken);
        var payloadText = await ReadSingleChunkTextAsync(
            stream,
            Encoding.ASCII.GetByteCount(expectedClientPayload),
            cancellationToken);

        await WriteAsciiAsync(
            stream,
            "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n",
            cancellationToken);
        await WriteAsciiAsync(
            stream,
            $"{Encoding.ASCII.GetByteCount(serverPayload):X}\r\n{serverPayload}\r\n0\r\n\r\n",
            cancellationToken);

        return new CapturedStreamOneExchange(request, payloadText);
    }

    private static async Task<CapturedStreamOneExchange> CaptureSplitHttpHttp2StreamOneExchangeAsync(
        TcpListener listener,
        string expectedClientPayload,
        string serverPayload,
        CancellationToken cancellationToken)
    {
        using var client = await listener.AcceptTcpClientAsync(cancellationToken);
        await using var stream = client.GetStream();

        var preface = new byte["PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n".Length];
        await ReadExactAsync(stream, preface, cancellationToken);
        Assert.Equal("PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n", Encoding.ASCII.GetString(preface));

        var settingsFrame = await ReadHttp2TestFrameAsync(stream, cancellationToken);
        Assert.Equal(Http2SplitHttpFrameTypes.Settings, settingsFrame.Type);
        Assert.Equal(0, settingsFrame.StreamId);

        await WriteHttp2TestFrameAsync(
            stream,
            Http2SplitHttpFrameTypes.Settings,
            Http2SplitHttpFrameFlags.None,
            streamId: 0,
            payload: Array.Empty<byte>(),
            cancellationToken);

        var headersFrame = await ReadNextHttp2TestFrameAsync(
            stream,
            static frame => frame.Type == Http2SplitHttpFrameTypes.Headers && frame.StreamId == 1,
            cancellationToken);
        var headers = DecodeHttp2HeaderBlock(headersFrame.Payload);

        var dataFrame = await ReadNextHttp2TestFrameAsync(
            stream,
            static frame => frame.Type == Http2SplitHttpFrameTypes.Data && frame.StreamId == 1,
            cancellationToken);
        var payloadText = Encoding.ASCII.GetString(dataFrame.Payload);
        Assert.Equal(expectedClientPayload, payloadText);

        await WriteHttp2TestFrameAsync(
            stream,
            Http2SplitHttpFrameTypes.Headers,
            Http2SplitHttpFrameFlags.EndHeaders,
            streamId: 1,
            payload: BuildHttp2Status200HeaderBlock(),
            cancellationToken);
        await WriteHttp2TestFrameAsync(
            stream,
            Http2SplitHttpFrameTypes.Data,
            Http2SplitHttpFrameFlags.EndStream,
            streamId: 1,
            payload: Encoding.ASCII.GetBytes(serverPayload),
            cancellationToken);

        await Task.Delay(Http2TestDrainDelay, cancellationToken);

        return new CapturedStreamOneExchange(
            new SplitHttpRequest(headers[":method"], headers[":path"], headers),
            payloadText);
    }

    private static async Task<CapturedMultiSessionStreamOneExchange> CaptureSplitHttpHttp2StreamOneExchangeAcrossSessionsAsync(
        TcpListener listener,
        IReadOnlyList<string> expectedClientPayloads,
        IReadOnlyList<string> serverPayloads,
        CancellationToken cancellationToken)
    {
        Assert.Equal(2, expectedClientPayloads.Count);
        Assert.Equal(2, serverPayloads.Count);

        using var firstClient = await listener.AcceptTcpClientAsync(cancellationToken);
        await using var firstStream = firstClient.GetStream();
        await ExpectHttp2ClientPrefaceAsync(firstStream, cancellationToken);

        var exchanges = new List<CapturedStreamOneExchange>(2)
        {
            await ReadHttp2StreamOneExchangeAsync(
                firstStream,
                expectedClientPayloads[0],
                serverPayloads[0],
                streamId: 1,
                cancellationToken)
        };

        try
        {
            using var sameConnectionCts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
            sameConnectionCts.CancelAfter(TimeSpan.FromSeconds(2));
            exchanges.Add(
                await ReadHttp2StreamOneExchangeAsync(
                    firstStream,
                    expectedClientPayloads[1],
                    serverPayloads[1],
                    streamId: 3,
                    sameConnectionCts.Token));
            return new CapturedMultiSessionStreamOneExchange(exchanges, ConnectionCount: 1);
        }
        catch (OperationCanceledException) when (!cancellationToken.IsCancellationRequested)
        {
            using var secondClient = await listener.AcceptTcpClientAsync(cancellationToken);
            await using var secondStream = secondClient.GetStream();
            await ExpectHttp2ClientPrefaceAsync(secondStream, cancellationToken);
            exchanges.Add(
                await ReadHttp2StreamOneExchangeAsync(
                    secondStream,
                    expectedClientPayloads[1],
                    serverPayloads[1],
                    streamId: 1,
                    cancellationToken));
            return new CapturedMultiSessionStreamOneExchange(exchanges, ConnectionCount: 2);
        }
    }

    private static async Task ExpectHttp2ClientPrefaceAsync(
        Stream stream,
        CancellationToken cancellationToken)
    {
        var preface = new byte["PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n".Length];
        await ReadExactAsync(stream, preface, cancellationToken);
        Assert.Equal("PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n", Encoding.ASCII.GetString(preface));

        var settingsFrame = await ReadHttp2TestFrameAsync(stream, cancellationToken);
        Assert.Equal(Http2SplitHttpFrameTypes.Settings, settingsFrame.Type);
        Assert.Equal(0, settingsFrame.StreamId);

        await WriteHttp2TestFrameAsync(
            stream,
            Http2SplitHttpFrameTypes.Settings,
            Http2SplitHttpFrameFlags.None,
            streamId: 0,
            payload: Array.Empty<byte>(),
            cancellationToken);
    }

    private static async Task<SplitHttpRequest> ReadHttp2SplitHttpRequestAsync(
        Stream stream,
        string expectedMethod,
        int expectedStreamId,
        CancellationToken cancellationToken)
    {
        var headersFrame = await ReadNextHttp2TestFrameAsync(
            stream,
            frame => frame.Type == Http2SplitHttpFrameTypes.Headers && frame.StreamId == expectedStreamId,
            cancellationToken);
        var headers = DecodeHttp2HeaderBlock(headersFrame.Payload);
        Assert.Equal(expectedMethod, headers[":method"]);
        return new SplitHttpRequest(headers[":method"], headers[":path"], headers);
    }

    private static async Task<CapturedStreamOneExchange> ReadHttp2StreamOneExchangeAsync(
        Stream stream,
        string expectedClientPayload,
        string serverPayload,
        int streamId,
        CancellationToken cancellationToken)
    {
        var request = await ReadHttp2SplitHttpRequestAsync(
            stream,
            expectedMethod: "POST",
            expectedStreamId: streamId,
            cancellationToken);
        var dataFrame = await ReadNextHttp2TestFrameAsync(
            stream,
            frame => frame.Type == Http2SplitHttpFrameTypes.Data && frame.StreamId == streamId,
            cancellationToken);
        var payloadText = Encoding.ASCII.GetString(dataFrame.Payload);
        Assert.Equal(expectedClientPayload, payloadText);

        await WriteHttp2TestFrameAsync(
            stream,
            Http2SplitHttpFrameTypes.Headers,
            Http2SplitHttpFrameFlags.EndHeaders,
            streamId,
            BuildHttp2Status200HeaderBlock(),
            cancellationToken);
        await WriteHttp2TestFrameAsync(
            stream,
            Http2SplitHttpFrameTypes.Data,
            Http2SplitHttpFrameFlags.EndStream,
            streamId,
            Encoding.ASCII.GetBytes(serverPayload),
            cancellationToken);

        return new CapturedStreamOneExchange(request, payloadText);
    }

    private static async Task<CapturedHttp2StreamUpExchange> ReadHttp2StreamUpExchangeAsync(
        Stream stream,
        string expectedClientPayload,
        string serverPayload,
        int downlinkStreamId,
        int uploadStreamId,
        CancellationToken cancellationToken)
    {
        var downlinkRequest = await ReadHttp2StreamUpDownlinkRequestAsync(
            stream,
            downlinkStreamId,
            cancellationToken);
        var (uplinkRequest, uplinkPayloadText) = await ReadHttp2StreamUpUploadAsync(
            stream,
            expectedClientPayload,
            uploadStreamId,
            cancellationToken);

        await CompleteHttp2PacketUploadResponseAsync(stream, uploadStreamId, cancellationToken);
        await CompleteHttp2StreamUpDownlinkResponseAsync(stream, downlinkStreamId, serverPayload, cancellationToken)
            ;
        await Task.Delay(Http2TestDrainDelay, cancellationToken);

        return new CapturedHttp2StreamUpExchange(
            downlinkRequest,
            uplinkRequest,
            uplinkPayloadText,
            ConnectionCount: 1);
    }

    private static async Task<SplitHttpRequest> ReadHttp2StreamUpDownlinkRequestAsync(
        Stream stream,
        int streamId,
        CancellationToken cancellationToken)
    {
        var request = await ReadHttp2SplitHttpRequestAsync(
            stream,
            expectedMethod: "GET",
            expectedStreamId: streamId,
            cancellationToken);

        await WriteHttp2TestFrameAsync(
            stream,
            Http2SplitHttpFrameTypes.Headers,
            Http2SplitHttpFrameFlags.EndHeaders,
            streamId,
            BuildHttp2Status200HeaderBlock(),
            cancellationToken);
        return request;
    }

    private static async Task<(SplitHttpRequest Request, string PayloadText)> ReadHttp2StreamUpUploadAsync(
        Stream stream,
        string expectedClientPayload,
        int streamId,
        CancellationToken cancellationToken)
    {
        var request = await ReadHttp2SplitHttpRequestAsync(
            stream,
            expectedMethod: "POST",
            expectedStreamId: streamId,
            cancellationToken);
        var dataFrame = await ReadNextHttp2TestFrameAsync(
            stream,
            frame => frame.Type == Http2SplitHttpFrameTypes.Data && frame.StreamId == streamId,
            cancellationToken);
        var payloadText = Encoding.ASCII.GetString(dataFrame.Payload);
        Assert.Equal(expectedClientPayload, payloadText);
        return (request, payloadText);
    }

    private static async Task<(TcpClient? Client, Stream Stream, SplitHttpRequest Request, int StreamId, int ConnectionCount)>
        WaitForNextHttp2StreamUpDownlinkAsync(
            Stream reusedStream,
            int reusedStreamId,
            TcpListener listener,
            CancellationToken cancellationToken)
    {
        using var reusedCts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        using var newConnectionCts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        var reusedTask = ReadHttp2StreamUpDownlinkRequestAsync(reusedStream, reusedStreamId, reusedCts.Token);
        var newConnectionTask = AcceptNewHttp2StreamUpDownlinkAsync(listener, newConnectionCts.Token);
        var reusedPending = true;
        var newPending = true;

        while (reusedPending || newPending)
        {
            var candidates = new List<Task>(2);
            if (reusedPending)
            {
                candidates.Add(reusedTask);
            }

            if (newPending)
            {
                candidates.Add(newConnectionTask);
            }

            var completed = await Task.WhenAny(candidates);
            if (ReferenceEquals(completed, reusedTask))
            {
                reusedPending = false;
                try
                {
                    var request = await reusedTask;
                    newConnectionCts.Cancel();
                    _ = ObserveTaskAsync(newConnectionTask);
                    return (null, reusedStream, request, reusedStreamId, 1);
                }
                catch (OperationCanceledException) when (!cancellationToken.IsCancellationRequested)
                {
                }
                catch (IOException)
                {
                }

                continue;
            }

            newPending = false;
            try
            {
                var accepted = await newConnectionTask;
                reusedCts.Cancel();
                _ = ObserveTaskAsync(reusedTask);
                return accepted;
            }
            catch (OperationCanceledException) when (!cancellationToken.IsCancellationRequested)
            {
            }
            catch (IOException)
            {
            }
        }

        throw new IOException("Failed to observe the next SplitHTTP HTTP/2 downlink stream.");
    }

    private static async Task<(TcpClient? Client, Stream Stream, SplitHttpRequest Request, string PayloadText, int StreamId, int ConnectionCount)>
        WaitForNextHttp2StreamUpUploadAsync(
            Stream reusedStream,
            string expectedClientPayload,
            int reusedStreamId,
            TcpListener listener,
            CancellationToken cancellationToken)
    {
        using var reusedCts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        using var newConnectionCts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        var reusedTask = ReadHttp2StreamUpUploadAsync(
            reusedStream,
            expectedClientPayload,
            reusedStreamId,
            reusedCts.Token);
        var newConnectionTask = AcceptNewHttp2StreamUpUploadAsync(
            listener,
            expectedClientPayload,
            newConnectionCts.Token);
        var reusedPending = true;
        var newPending = true;

        while (reusedPending || newPending)
        {
            var candidates = new List<Task>(2);
            if (reusedPending)
            {
                candidates.Add(reusedTask);
            }

            if (newPending)
            {
                candidates.Add(newConnectionTask);
            }

            var completed = await Task.WhenAny(candidates);
            if (ReferenceEquals(completed, reusedTask))
            {
                reusedPending = false;
                try
                {
                    var (request, payloadText) = await reusedTask;
                    newConnectionCts.Cancel();
                    _ = ObserveTaskAsync(newConnectionTask);
                    return (null, reusedStream, request, payloadText, reusedStreamId, 1);
                }
                catch (OperationCanceledException) when (!cancellationToken.IsCancellationRequested)
                {
                }
                catch (IOException)
                {
                }

                continue;
            }

            newPending = false;
            try
            {
                var accepted = await newConnectionTask;
                reusedCts.Cancel();
                _ = ObserveTaskAsync(reusedTask);
                return accepted;
            }
            catch (OperationCanceledException) when (!cancellationToken.IsCancellationRequested)
            {
            }
            catch (IOException)
            {
            }
        }

        throw new IOException("Failed to observe the next SplitHTTP HTTP/2 upload stream.");
    }

    private static async Task<(TcpClient Client, Stream Stream, SplitHttpRequest Request, int StreamId, int ConnectionCount)>
        AcceptNewHttp2StreamUpDownlinkAsync(
            TcpListener listener,
            CancellationToken cancellationToken)
    {
        TcpClient? client = null;
        try
        {
            client = await listener.AcceptTcpClientAsync(cancellationToken);
            var stream = client.GetStream();
            await ExpectHttp2ClientPrefaceAsync(stream, cancellationToken);
            var request = await ReadHttp2StreamUpDownlinkRequestAsync(stream, 1, cancellationToken);
            return (client, stream, request, 1, 2);
        }
        catch
        {
            client?.Dispose();
            throw;
        }
    }

    private static async Task<(TcpClient Client, Stream Stream, SplitHttpRequest Request, string PayloadText, int StreamId, int ConnectionCount)>
        AcceptNewHttp2StreamUpUploadAsync(
            TcpListener listener,
            string expectedClientPayload,
            CancellationToken cancellationToken)
    {
        TcpClient? client = null;
        try
        {
            client = await listener.AcceptTcpClientAsync(cancellationToken);
            var stream = client.GetStream();
            await ExpectHttp2ClientPrefaceAsync(stream, cancellationToken);
            var (request, payloadText) = await ReadHttp2StreamUpUploadAsync(
                stream,
                expectedClientPayload,
                streamId: 1,
                cancellationToken);
            return (client, stream, request, payloadText, 1, 2);
        }
        catch
        {
            client?.Dispose();
            throw;
        }
    }

    private static async Task ObserveTaskAsync(Task task)
    {
        try
        {
            await task;
        }
        catch
        {
        }
    }

    private static Task CompleteHttp2StreamUpDownlinkResponseAsync(
        Stream stream,
        int streamId,
        string serverPayload,
        CancellationToken cancellationToken)
        => WriteHttp2TestFrameAsync(
            stream,
            Http2SplitHttpFrameTypes.Data,
            Http2SplitHttpFrameFlags.EndStream,
            streamId,
            Encoding.ASCII.GetBytes(serverPayload),
            cancellationToken);

    private static async Task<CapturedPacketUpload> ReadHttp2PacketUploadAsync(
        Stream stream,
        string expectedPayload,
        int streamId,
        CancellationToken cancellationToken,
        bool sendResponse = true)
    {
        var request = await ReadHttp2SplitHttpRequestAsync(
                stream,
                expectedMethod: "POST",
                expectedStreamId: streamId,
                cancellationToken)
            ;
        var dataFrame = await ReadNextHttp2TestFrameAsync(
                stream,
                frame => frame.Type == Http2SplitHttpFrameTypes.Data && frame.StreamId == streamId,
                cancellationToken)
            ;
        var payloadText = Encoding.ASCII.GetString(dataFrame.Payload);
        Assert.Equal(expectedPayload, payloadText);

        if (sendResponse)
        {
            await CompleteHttp2PacketUploadResponseAsync(stream, streamId, cancellationToken);
        }

        return new CapturedPacketUpload(request, payloadText, DateTime.UtcNow);
    }

    private static async Task CompleteHttp2PacketUploadResponseAsync(
        Stream stream,
        int streamId,
        CancellationToken cancellationToken)
    {
        await WriteHttp2TestFrameAsync(
            stream,
            Http2SplitHttpFrameTypes.Headers,
            Http2SplitHttpFrameFlags.EndHeaders,
            streamId,
            BuildHttp2Status200HeaderBlock(),
            cancellationToken);
        await WriteHttp2TestFrameAsync(
            stream,
            Http2SplitHttpFrameTypes.Data,
            Http2SplitHttpFrameFlags.EndStream,
            streamId,
            Array.Empty<byte>(),
            cancellationToken);
    }

    private static async Task<Http2SplitHttpTestFrame> ReadNextHttp2TestFrameAsync(
        Stream stream,
        Func<Http2SplitHttpTestFrame, bool> predicate,
        CancellationToken cancellationToken)
    {
        while (true)
        {
            var frame = await ReadHttp2TestFrameAsync(stream, cancellationToken);
            if (predicate(frame))
            {
                return frame;
            }
        }
    }

    private static async Task WriteHttp2TestFrameAsync(
        Stream stream,
        byte type,
        Http2SplitHttpFrameFlags flags,
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

    private static async Task<Http2SplitHttpTestFrame> ReadHttp2TestFrameAsync(
        Stream stream,
        CancellationToken cancellationToken)
    {
        var header = new byte[9];
        await ReadExactAsync(stream, header, cancellationToken);

        var length = (header[0] << 16) | (header[1] << 8) | header[2];
        var payload = new byte[length];
        if (length > 0)
        {
            await ReadExactAsync(stream, payload, cancellationToken);
        }

        return new Http2SplitHttpTestFrame(
            header[3],
            (Http2SplitHttpFrameFlags)header[4],
            ((header[5] & 0x7F) << 24) |
            (header[6] << 16) |
            (header[7] << 8) |
            header[8],
            payload);
    }

    private static byte[] BuildHttp2Status200HeaderBlock()
        => [unchecked((byte)0x88)];

    private static IReadOnlyDictionary<string, string> DecodeHttp2HeaderBlock(byte[] headerBlock)
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

    private static bool TryResolveIndexedHttp2Header(
        int index,
        out string name,
        out string value)
    {
        switch (index)
        {
            case 8:
                name = ":status";
                value = "200";
                return true;
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
            _ => string.Empty
        };

    private static int ReadHpackInteger(byte[] buffer, ref int offset, int prefixBits)
    {
        if (offset >= buffer.Length)
        {
            throw new InvalidDataException("HPACK integer exceeded the available header block bytes.");
        }

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
            if (offset >= buffer.Length)
            {
                throw new InvalidDataException("HPACK integer exceeded the available header block bytes.");
            }

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
        if (offset >= buffer.Length)
        {
            throw new InvalidDataException("HPACK string literal exceeded the available header block bytes.");
        }

        var huffmanEncoded = (buffer[offset] & 0x80) != 0;
        if (huffmanEncoded)
        {
            throw new NotSupportedException("HPACK Huffman-encoded strings are not supported by this test.");
        }

        var length = ReadHpackInteger(buffer, ref offset, 7);
        if (length < 0 || offset + length > buffer.Length)
        {
            throw new InvalidDataException("HPACK string literal exceeded the available header block bytes.");
        }

        var value = Encoding.ASCII.GetString(buffer, offset, length);
        offset += length;
        return value;
    }

    private static async Task<SplitHttpRequest> ReadHttpRequestAsync(
        Stream stream,
        CancellationToken cancellationToken)
    {
        var requestLine = await RuntimeInternetHttpUtilities
            .ReadHttpLineAsync(
                stream,
                "Unexpected EOF while reading SplitHTTP request line.",
                cancellationToken)
            ;
        var parts = requestLine.Split(' ', StringSplitOptions.RemoveEmptyEntries);
        if (parts.Length < 2)
        {
            throw new InvalidDataException("SplitHTTP test server received an invalid HTTP request line.");
        }

        var headers = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        while (true)
        {
            var line = await RuntimeInternetHttpUtilities
                .ReadHttpLineAsync(
                    stream,
                    "Unexpected EOF while reading SplitHTTP request headers.",
                    cancellationToken)
                ;
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

        return new SplitHttpRequest(parts[0], parts[1], headers);
    }

    private static async Task<string> ReadSingleChunkTextAsync(
        Stream stream,
        int expectedLength,
        CancellationToken cancellationToken)
    {
        var chunkHeader = await RuntimeInternetHttpUtilities
            .ReadHttpLineAsync(
                stream,
                "Unexpected EOF while reading SplitHTTP upload chunk header.",
                cancellationToken)
            ;
        var separator = chunkHeader.IndexOf(';');
        var sizeText = separator >= 0 ? chunkHeader[..separator] : chunkHeader;
        if (!int.TryParse(sizeText, System.Globalization.NumberStyles.HexNumber, null, out var chunkLength))
        {
            throw new InvalidDataException("SplitHTTP test server received an invalid upload chunk length.");
        }

        Assert.Equal(expectedLength, chunkLength);
        var payload = new byte[chunkLength];
        await ReadExactAsync(stream, payload, cancellationToken);

        var crlf = new byte[2];
        await ReadExactAsync(stream, crlf, cancellationToken);
        Assert.Equal((byte)'\r', crlf[0]);
        Assert.Equal((byte)'\n', crlf[1]);
        return Encoding.ASCII.GetString(payload);
    }

    private static async Task<string> ReadContentLengthBodyTextAsync(
        Stream stream,
        IReadOnlyDictionary<string, string> headers,
        CancellationToken cancellationToken)
    {
        if (!headers.TryGetValue("Content-Length", out var contentLengthText) ||
            !int.TryParse(contentLengthText, out var contentLength) ||
            contentLength <= 0)
        {
            return string.Empty;
        }

        var payload = new byte[contentLength];
        await ReadExactAsync(stream, payload, cancellationToken);
        return Encoding.ASCII.GetString(payload);
    }

    private static string DecodeHeaderPayload(
        IReadOnlyDictionary<string, string> headers,
        string key)
    {
        var builder = new StringBuilder();
        for (var index = 0; ; index++)
        {
            if (!headers.TryGetValue($"{key}-{index}", out var chunk) ||
                string.IsNullOrEmpty(chunk))
            {
                break;
            }

            builder.Append(chunk);
        }

        return builder.Length == 0
            ? string.Empty
            : Encoding.ASCII.GetString(DecodeBase64Url(builder.ToString()));
    }

    private static string DecodeCookiePayload(
        IReadOnlyDictionary<string, string> headers,
        string key)
    {
        if (!headers.TryGetValue("Cookie", out var cookieHeader) ||
            string.IsNullOrWhiteSpace(cookieHeader))
        {
            return string.Empty;
        }

        var cookies = ParseCookies(cookieHeader);
        var builder = new StringBuilder();
        for (var index = 0; ; index++)
        {
            if (!cookies.TryGetValue($"{key}_{index}", out var chunk) ||
                string.IsNullOrEmpty(chunk))
            {
                break;
            }

            builder.Append(chunk);
        }

        return builder.Length == 0
            ? string.Empty
            : Encoding.ASCII.GetString(DecodeBase64Url(builder.ToString()));
    }

    private static IReadOnlyDictionary<string, string> ParseCookies(string cookieHeader)
    {
        var cookies = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        foreach (var segment in cookieHeader.Split(';', StringSplitOptions.RemoveEmptyEntries))
        {
            var separator = segment.IndexOf('=');
            if (separator <= 0)
            {
                continue;
            }

            cookies[segment[..separator].Trim()] = segment[(separator + 1)..].Trim();
        }

        return cookies;
    }

    private static IReadOnlyDictionary<string, string> ParseQuery(string query)
    {
        var parameters = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        foreach (var segment in query.TrimStart('?').Split('&', StringSplitOptions.RemoveEmptyEntries))
        {
            var separator = segment.IndexOf('=');
            var key = separator >= 0 ? segment[..separator] : segment;
            var value = separator >= 0 ? segment[(separator + 1)..] : string.Empty;
            parameters[Uri.UnescapeDataString(key)] = Uri.UnescapeDataString(value);
        }

        return parameters;
    }

    private static byte[] DecodeBase64Url(string value)
    {
        var normalized = value.Replace('-', '+').Replace('_', '/');
        var padding = normalized.Length % 4;
        if (padding > 0)
        {
            normalized = normalized.PadRight(normalized.Length + (4 - padding), '=');
        }

        return Convert.FromBase64String(normalized);
    }

    private static async Task WriteAsciiAsync(
        Stream stream,
        string value,
        CancellationToken cancellationToken)
    {
        var bytes = Encoding.ASCII.GetBytes(value);
        await stream.WriteAsync(bytes, cancellationToken);
        await stream.FlushAsync(cancellationToken);
    }

    private static async Task ReadExactAsync(
        Stream stream,
        byte[] buffer,
        CancellationToken cancellationToken)
    {
        var read = 0;
        while (read < buffer.Length)
        {
            var count = await stream.ReadAsync(buffer.AsMemory(read, buffer.Length - read), cancellationToken);
            if (count == 0)
            {
                throw new EndOfStreamException("Unexpected EOF while reading SplitHTTP test payload.");
            }

            read += count;
        }
    }

    private static int ReserveTcpPort()
    {
        const int portRangeStart = 40000;
        const int portRangeSize = 20000;

        for (var attempt = 0; attempt < portRangeSize; attempt++)
        {
            var candidate = portRangeStart +
                            Math.Abs(Interlocked.Increment(ref s_nextReservedTcpPort) % portRangeSize);
            try
            {
                using var listener = new TcpListener(IPAddress.Loopback, candidate);
                listener.Start();
                return ((IPEndPoint)listener.LocalEndpoint).Port;
            }
            catch (SocketException)
            {
            }
        }

        throw new InvalidOperationException("Unable to reserve a loopback TCP port for SplitHTTP transport tests.");
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

    private static SplitHttpRequest CaptureAspNetRequest(Microsoft.AspNetCore.Http.HttpRequest request)
        => new(
            request.Method,
            $"{request.Path}{request.QueryString}",
            request.Headers.ToDictionary(
                static pair => pair.Key,
                static pair => pair.Value.ToString(),
                StringComparer.OrdinalIgnoreCase));

    private static string ExtractSplitHttpPathSessionId(string? path)
    {
        if (string.IsNullOrWhiteSpace(path))
        {
            throw new InvalidOperationException("SplitHTTP HTTP/3 test request path was missing.");
        }

        var segments = path.Split('/', StringSplitOptions.RemoveEmptyEntries);
        if (segments.Length < 2)
        {
            throw new InvalidOperationException($"SplitHTTP HTTP/3 test request path did not contain a session id: {path}.");
        }

        return Uri.UnescapeDataString(segments[1]);
    }

    private static Http3StreamUpServerSession GetOrAddHttp3StreamUpSession(
        ConcurrentDictionary<string, Http3StreamUpServerSession> sessions,
        object syncRoot,
        string sessionId,
        ref int nextSessionIndex)
    {
        lock (syncRoot)
        {
            if (sessions.TryGetValue(sessionId, out var existing))
            {
                return existing;
            }

            var created = new Http3StreamUpServerSession(nextSessionIndex++);
            sessions[sessionId] = created;
            return created;
        }
    }

    private static async Task WaitUntilAsync(Func<bool> condition, CancellationToken cancellationToken)
    {
        while (!condition())
        {
            await Task.Delay(10, cancellationToken);
        }
    }

    private sealed record CapturedSplitHttpExchange(
        SplitHttpRequest DownlinkRequest,
        SplitHttpRequest UplinkRequest,
        string UplinkPayloadText);

    private sealed record CapturedSplitHttpPacketExchange(
        SplitHttpRequest DownlinkRequest,
        IReadOnlyList<CapturedPacketUpload> UploadRequests,
        int UploadConnectionCount = 0);

    private sealed record CapturedMultiSessionSplitHttpPacketExchange(
        IReadOnlyList<SplitHttpRequest> DownlinkRequests,
        IReadOnlyList<CapturedPacketUpload> UploadRequests,
        int UploadConnectionCount = 0);

    private sealed record CapturedPacketUpload(
        SplitHttpRequest Request,
        string PayloadText,
        DateTime ReceivedAtUtc);

    private sealed record CapturedStreamOneExchange(
        SplitHttpRequest Request,
        string PayloadText);

    private sealed record CapturedMultiSessionStreamOneExchange(
        IReadOnlyList<CapturedStreamOneExchange> Exchanges,
        int ConnectionCount);

    private sealed record CapturedHttp2StreamUpExchange(
        SplitHttpRequest DownlinkRequest,
        SplitHttpRequest UplinkRequest,
        string UplinkPayloadText,
        int ConnectionCount);

    private sealed record CapturedMultiSessionHttp2StreamUpExchange(
        IReadOnlyList<CapturedHttp2StreamUpExchange> Exchanges,
        int ConnectionCount);

    private sealed record CapturedMultiEndpointHttp2StreamUpExchange(
        IReadOnlyList<CapturedHttp2StreamUpExchange> Exchanges,
        int DownlinkConnectionCount,
        int UploadConnectionCount);

    private sealed record CapturedHttp3StreamUpExchange(
        SplitHttpRequest DownlinkRequest,
        SplitHttpRequest UplinkRequest,
        string UplinkPayloadText,
        string DownlinkConnectionId,
        string UplinkConnectionId);

    private sealed record CapturedHttp3ServerRequest(
        string Protocol,
        SplitHttpRequest Request,
        string RequestBodyText,
        string ConnectionId = "");

    private sealed class Http3StreamUpServerSession
    {
        public Http3StreamUpServerSession(int index)
        {
            Index = index;
        }

        public int Index { get; }

        public TaskCompletionSource<string> ResponseReady { get; } = new(
            TaskCreationOptions.RunContinuationsAsynchronously);

        public TaskCompletionSource<CapturedHttp3StreamUpExchange> Exchange { get; } = new(
            TaskCreationOptions.RunContinuationsAsynchronously);

        public SplitHttpRequest? DownlinkRequest { get; set; }

        public string? DownlinkConnectionId { get; set; }

        public SplitHttpRequest? UplinkRequest { get; set; }

        public string? UplinkPayloadText { get; set; }

        public string? UplinkConnectionId { get; set; }

        public void TryCompleteExchange()
        {
            if (DownlinkRequest is null ||
                UplinkRequest is null ||
                string.IsNullOrWhiteSpace(UplinkPayloadText) ||
                string.IsNullOrWhiteSpace(DownlinkConnectionId) ||
                string.IsNullOrWhiteSpace(UplinkConnectionId))
            {
                return;
            }

            Exchange.TrySetResult(new CapturedHttp3StreamUpExchange(
                DownlinkRequest,
                UplinkRequest,
                UplinkPayloadText,
                DownlinkConnectionId,
                UplinkConnectionId));
        }
    }

    private readonly record struct Http2SplitHttpTestFrame(
        byte Type,
        Http2SplitHttpFrameFlags Flags,
        int StreamId,
        byte[] Payload);

    private sealed record SplitHttpRequest(
        string Method,
        string Target,
        IReadOnlyDictionary<string, string> Headers);

    private sealed record BrowserDialerStreamCall(
        string Url,
        IReadOnlyDictionary<string, string> Headers);

    private sealed record BrowserDialerPacketCall(
        string Method,
        string Url,
        IReadOnlyDictionary<string, string> Headers,
        byte[] Payload);

    private sealed class RecordingBrowserDialer : IRuntimeInternetBrowserDialer
    {
        private readonly Func<RuntimeInternetBrowserStreamRequest, CancellationToken, ValueTask<Stream>> _streamFactory;
        private readonly Func<RuntimeInternetBrowserWebSocketRequest, CancellationToken, ValueTask<Stream>> _webSocketFactory;
        private readonly Func<RuntimeInternetBrowserPacketRequest, ReadOnlyMemory<byte>, CancellationToken, ValueTask> _packetHandler;

        public RecordingBrowserDialer(
            Func<RuntimeInternetBrowserStreamRequest, CancellationToken, ValueTask<Stream>>? streamFactory = null,
            Func<RuntimeInternetBrowserWebSocketRequest, CancellationToken, ValueTask<Stream>>? webSocketFactory = null,
            Func<RuntimeInternetBrowserPacketRequest, ReadOnlyMemory<byte>, CancellationToken, ValueTask>? packetHandler = null)
        {
            _streamFactory = streamFactory ?? CreateEmptyStreamAsync;
            _webSocketFactory = webSocketFactory ?? CreateEmptyStreamAsync;
            _packetHandler = packetHandler ?? IgnorePacketAsync;
        }

        public ConcurrentQueue<BrowserDialerStreamCall> StreamRequests { get; } = new();

        public ConcurrentQueue<BrowserDialerPacketCall> PacketRequests { get; } = new();

        public async ValueTask<Stream> OpenStreamAsync(
            RuntimeInternetBrowserStreamRequest request,
            CancellationToken cancellationToken)
        {
            StreamRequests.Enqueue(new BrowserDialerStreamCall(
                request.Url,
                new Dictionary<string, string>(request.Headers, StringComparer.OrdinalIgnoreCase)));
            return await _streamFactory(request, cancellationToken);
        }

        public ValueTask<Stream> OpenWebSocketStreamAsync(
            RuntimeInternetBrowserWebSocketRequest request,
            CancellationToken cancellationToken)
            => _webSocketFactory(request, cancellationToken);

        public async ValueTask SendPacketAsync(
            RuntimeInternetBrowserPacketRequest request,
            ReadOnlyMemory<byte> payload,
            CancellationToken cancellationToken)
        {
            PacketRequests.Enqueue(new BrowserDialerPacketCall(
                request.Method,
                request.Url,
                new Dictionary<string, string>(request.Headers, StringComparer.OrdinalIgnoreCase),
                payload.ToArray()));
            await _packetHandler(request, payload, cancellationToken);
        }

        private static ValueTask<Stream> CreateEmptyStreamAsync(
            RuntimeInternetBrowserStreamRequest _,
            CancellationToken __)
            => ValueTask.FromResult<Stream>(new MemoryStream(Array.Empty<byte>(), writable: false));

        private static ValueTask<Stream> CreateEmptyStreamAsync(
            RuntimeInternetBrowserWebSocketRequest _,
            CancellationToken __)
            => ValueTask.FromResult<Stream>(new MemoryStream(Array.Empty<byte>(), writable: false));

        private static ValueTask IgnorePacketAsync(
            RuntimeInternetBrowserPacketRequest _,
            ReadOnlyMemory<byte> __,
            CancellationToken ___)
            => ValueTask.CompletedTask;
    }

    private enum SplitHttpDownlinkBodyMode
    {
        Chunked,
        ContentLength
    }

    [Flags]
    private enum Http2SplitHttpFrameFlags : byte
    {
        None = 0,
        EndStream = 0x1,
        EndHeaders = 0x4
    }

    private static class Http2SplitHttpFrameTypes
    {
        public const byte Data = 0x0;
        public const byte Headers = 0x1;
        public const byte Settings = 0x4;
    }

    private sealed record TestSplitHttpInternetOptions : IRuntimeGrpcClientDialOptions
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

        public string TransportProtocol => RuntimeInternetTransportProtocols.SplitHttp;

        public string SecurityType { get; init; } = RuntimeInternetSecurityTypes.Tls;

        public RuntimeRealityOptions RealityOptions { get; init; } = RuntimeRealityOptions.Empty;

        public string WebSocketPath => "/";

        public IReadOnlyDictionary<string, string> WebSocketHeaders { get; init; }
            = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);

        public int WebSocketEarlyDataBytes { get; init; }

        public int WebSocketHeartbeatPeriodSeconds => 0;

        public string SplitHttpHost { get; init; } = string.Empty;

        public string SplitHttpPath { get; init; } = "/";

        public IReadOnlyDictionary<string, string> SplitHttpHeaders { get; init; }
            = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);

        public string SplitHttpMode { get; init; } = string.Empty;

        public bool SplitHttpNoGrpcHeader { get; init; }

        public RuntimeInt32Range SplitHttpXPaddingBytes { get; init; } = RuntimeInt32Range.Empty;

        public bool SplitHttpXPaddingObfsMode { get; init; }

        public string SplitHttpXPaddingKey { get; init; } = string.Empty;

        public string SplitHttpXPaddingHeader { get; init; } = string.Empty;

        public string SplitHttpXPaddingPlacement { get; init; } = string.Empty;

        public string SplitHttpXPaddingMethod { get; init; } = string.Empty;

        public string SplitHttpUplinkHttpMethod { get; init; } = string.Empty;

        public string SplitHttpSessionPlacement { get; init; } = string.Empty;

        public string SplitHttpSessionKey { get; init; } = string.Empty;

        public string SplitHttpSeqPlacement { get; init; } = string.Empty;

        public string SplitHttpSeqKey { get; init; } = string.Empty;

        public string SplitHttpUplinkDataPlacement { get; init; } = string.Empty;

        public string SplitHttpUplinkDataKey { get; init; } = string.Empty;

        public RuntimeInt32Range SplitHttpUplinkChunkSize { get; init; } = RuntimeInt32Range.Empty;

        public RuntimeInt32Range SplitHttpScMaxEachPostBytes { get; init; } = RuntimeInt32Range.Empty;

        public RuntimeInt32Range SplitHttpScMinPostsIntervalMs { get; init; } = RuntimeInt32Range.Empty;

        public int SplitHttpScMaxBufferedPosts { get; init; }

        public RuntimeSplitHttpXmuxOptions SplitHttpXmux { get; init; } = RuntimeSplitHttpXmuxOptions.Empty;

        public RuntimeSplitHttpDownloadOptions? SplitHttpDownloadSettings { get; init; }

        public IReadOnlyList<string> ApplicationProtocols { get; init; } = Array.Empty<string>();

        public RuntimeQuicOptions QuicOptions { get; init; } = RuntimeQuicOptions.Empty;

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

        public IRuntimeRealityHandshakeProvider? RealityHandshakeProvider => null;

        public Func<CancellationToken, ValueTask<Stream>>? TransportStreamFactory { get; init; }

        public Func<CancellationToken, ValueTask<Stream>>? SplitHttpDownloadTransportStreamFactory { get; init; }
    }

    private static string EncodeBase64Url(int length, byte value)
        => Convert.ToBase64String(Enumerable.Repeat(value, length).ToArray())
            .TrimEnd('=')
            .Replace('+', '-')
            .Replace('/', '_');
}

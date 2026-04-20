using System.Net;
using System.Net.Quic;
using System.Net.Security;
using System.Runtime.Versioning;
using System.Security.Authentication;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using NodePanel.Core.Runtime;

namespace NodePanel.Core.Tests;

[SupportedOSPlatform("windows")]
[SupportedOSPlatform("linux")]
[SupportedOSPlatform("macos")]
public sealed class RuntimeHttp3ServerSessionTests
{
    [Fact]
    public async Task ServerSession_accepts_sequential_get_and_post_requests_on_one_connection()
    {
        if (!QuicConnection.IsSupported || !QuicListener.IsSupported)
        {
            return;
        }

        using var lifetimeCts = new CancellationTokenSource(TimeSpan.FromSeconds(30));
        using var certificate = TestCertificateFactory.CreateSelfSignedServerCertificate("localhost", ["localhost"]);

        try
        {
            await using var listener = await CreateListenerAsync(certificate, lifetimeCts.Token);
            var serverSessionTask = AcceptServerSessionAsync(listener, lifetimeCts.Token);

            await using var clientSession = await CreateClientSessionAsync(listener.LocalEndPoint, lifetimeCts.Token);
            await using var serverSession = await serverSessionTask.WaitAsync(lifetimeCts.Token);

            const string firstResponseText = "first-response-body";
            await using (var firstPendingRequest = await clientSession.StartHttpRequestAsync(
                             "GET",
                             "unit.test",
                             "https",
                             "/alpha?mode=1",
                             new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
                             {
                                 ["user-agent"] = "runtime-http3-tests",
                                 ["x-test-case"] = "first"
                             },
                             Array.Empty<byte>(),
                             lifetimeCts.Token,
                             endRequestOnHeaders: true))
            {
                var firstAcceptedRequest = await serverSession.AcceptRequestAsync(lifetimeCts.Token);
                Assert.NotNull(firstAcceptedRequest);

                await using (firstAcceptedRequest!)
                {
                    Assert.Equal("GET", firstAcceptedRequest.Method);
                    Assert.Equal("/alpha?mode=1", firstAcceptedRequest.Target);
                    Assert.Equal("/alpha", firstAcceptedRequest.Path);
                    Assert.Equal("unit.test", firstAcceptedRequest.Host);
                    Assert.Equal("first", firstAcceptedRequest.Headers["x-test-case"]);

                    var eofRead = await firstAcceptedRequest.Body.ReadAsync(new byte[1], lifetimeCts.Token);
                    Assert.Equal(0, eofRead);

                    await using var responseBody = await firstAcceptedRequest.OpenResponseBodyAsync(
                        200,
                        new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
                        {
                            ["x-server-case"] = "first"
                        },
                        lifetimeCts.Token);
                    await responseBody.WriteAsync(Encoding.ASCII.GetBytes(firstResponseText), lifetimeCts.Token);
                }

                await firstPendingRequest.WaitForSuccessfulStatusAsync(lifetimeCts.Token);
                await using var firstResponseStream = firstPendingRequest.DetachResponseStream();
                var firstResponseBuffer = new byte[firstResponseText.Length];
                await firstResponseStream.ReadExactlyAsync(firstResponseBuffer, lifetimeCts.Token);
                Assert.Equal(firstResponseText, Encoding.ASCII.GetString(firstResponseBuffer));
                Assert.Equal(0, await firstResponseStream.ReadAsync(new byte[1], lifetimeCts.Token));
            }

            const string postBodyText = "second-request-body";
            await using (var secondPendingRequest = await clientSession.StartHttpRequestAsync(
                             "POST",
                             "unit.test",
                             "https",
                             "/beta/upload",
                             new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
                             {
                                 ["content-type"] = "application/octet-stream",
                                 ["x-test-case"] = "second"
                             },
                             Encoding.ASCII.GetBytes(postBodyText),
                             lifetimeCts.Token,
                             completeRequestAfterInitialPayload: true))
            {
                var secondAcceptedRequest = await serverSession.AcceptRequestAsync(lifetimeCts.Token);
                Assert.NotNull(secondAcceptedRequest);

                await using (secondAcceptedRequest!)
                {
                    Assert.Equal("POST", secondAcceptedRequest.Method);
                    Assert.Equal("/beta/upload", secondAcceptedRequest.Target);
                    Assert.Equal("/beta/upload", secondAcceptedRequest.Path);
                    Assert.Equal("unit.test", secondAcceptedRequest.Host);
                    Assert.Equal("application/octet-stream", secondAcceptedRequest.Headers["content-type"]);
                    Assert.Equal("second", secondAcceptedRequest.Headers["x-test-case"]);

                    var requestBodyBuffer = new byte[postBodyText.Length];
                    await secondAcceptedRequest.Body.ReadExactlyAsync(requestBodyBuffer, lifetimeCts.Token);
                    Assert.Equal(postBodyText, Encoding.ASCII.GetString(requestBodyBuffer));
                    Assert.Equal(0, await secondAcceptedRequest.Body.ReadAsync(new byte[1], lifetimeCts.Token));

                    await secondAcceptedRequest.WriteHeadersOnlyAsync(
                        200,
                        new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
                        {
                            ["x-server-case"] = "second"
                        },
                        lifetimeCts.Token);
                }

                await secondPendingRequest.WaitForSuccessfulStatusAsync(lifetimeCts.Token);
                await using var secondResponseStream = secondPendingRequest.DetachResponseStream();
                Assert.Equal(0, await secondResponseStream.ReadAsync(new byte[1], lifetimeCts.Token));
            }
        }
        catch (Exception ex) when (IsKnownLocalQuicCredentialLoadFailure(ex))
        {
            return;
        }
    }

    [Fact]
    public async Task ServerSession_dispose_sends_goaway_on_control_stream()
    {
        if (!QuicConnection.IsSupported || !QuicListener.IsSupported)
        {
            return;
        }

        using var lifetimeCts = new CancellationTokenSource(TimeSpan.FromSeconds(30));
        using var certificate = TestCertificateFactory.CreateSelfSignedServerCertificate("localhost", ["localhost"]);

        try
        {
            await using var listener = await CreateListenerAsync(certificate, lifetimeCts.Token);
            var serverSessionTask = AcceptServerSessionAsync(listener, lifetimeCts.Token);
            await using var clientConnection = await CreateClientConnectionAsync(listener.LocalEndPoint, lifetimeCts.Token);
            await using var serverSession = await serverSessionTask.WaitAsync(lifetimeCts.Token);

            var goAwayObservedTask = ObserveServerGoAwayAsync(clientConnection, lifetimeCts.Token);

            await serverSession.DisposeAsync();

            await goAwayObservedTask.WaitAsync(lifetimeCts.Token);
        }
        catch (Exception ex) when (IsKnownLocalQuicCredentialLoadFailure(ex))
        {
            return;
        }
    }

    [Fact]
    public async Task ServerSession_writes_response_trailers_after_response_body()
    {
        if (!QuicConnection.IsSupported || !QuicListener.IsSupported)
        {
            return;
        }

        using var lifetimeCts = new CancellationTokenSource(TimeSpan.FromSeconds(30));
        using var certificate = TestCertificateFactory.CreateSelfSignedServerCertificate("localhost", ["localhost"]);

        try
        {
            await using var listener = await CreateListenerAsync(certificate, lifetimeCts.Token);
            var serverSessionTask = AcceptServerSessionAsync(listener, lifetimeCts.Token);
            await using var clientConnection = await CreateClientConnectionAsync(listener.LocalEndPoint, lifetimeCts.Token);
            await using var serverSession = await serverSessionTask.WaitAsync(lifetimeCts.Token);

            await using var requestStream = await clientConnection.OpenOutboundStreamAsync(
                QuicStreamType.Bidirectional,
                lifetimeCts.Token);
            var requestHeaderBlock = RuntimeHttp3ProtocolPrimitives.BuildRequestHeaderBlock(
                new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
                {
                    ["x-test-case"] = "trailers"
                },
                "GET",
                "unit.test",
                "https",
                "/trailers");
            await RuntimeHttp3ProtocolPrimitives
                .WriteFrameAsync(
                    requestStream,
                    RuntimeHttp3ProtocolPrimitives.HeadersFrameType,
                    requestHeaderBlock,
                    completeWrites: true,
                    lifetimeCts.Token);

            var acceptedRequest = await serverSession.AcceptRequestAsync(lifetimeCts.Token);
            Assert.NotNull(acceptedRequest);

            const string responseText = "response-with-trailers";
            await using (acceptedRequest!)
            {
                Assert.Equal(0, await acceptedRequest.Body.ReadAsync(new byte[1], lifetimeCts.Token));

                await using var responseBody = await acceptedRequest.OpenResponseBodyAsync(
                    200,
                    new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
                    {
                        ["x-server-case"] = "trailers"
                    },
                    lifetimeCts.Token,
                    completeOnDispose: false);
                await responseBody.WriteAsync(Encoding.ASCII.GetBytes(responseText), lifetimeCts.Token);
                await responseBody.DisposeAsync();

                await acceptedRequest.WriteTrailersAsync(
                    new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
                    {
                        ["grpc-status"] = "0",
                        ["x-final"] = "ok"
                    },
                    lifetimeCts.Token);
            }

            var responseHeadersFrame = await RuntimeHttp3ProtocolPrimitives
                .ReadFrameAsync(requestStream, lifetimeCts.Token);
            Assert.NotNull(responseHeadersFrame);
            Assert.Equal(RuntimeHttp3ProtocolPrimitives.HeadersFrameType, responseHeadersFrame.Value.Type);

            var responseHeaders = RuntimeQPackDecoderState.DecodeHeaders(responseHeadersFrame.Value.Payload);
            Assert.Equal("200", responseHeaders[":status"]);
            Assert.Equal("trailers", responseHeaders["x-server-case"]);

            var dataFrame = await RuntimeHttp3ProtocolPrimitives
                .ReadFrameAsync(requestStream, lifetimeCts.Token);
            Assert.NotNull(dataFrame);
            Assert.Equal(RuntimeHttp3ProtocolPrimitives.DataFrameType, dataFrame.Value.Type);
            Assert.Equal(responseText, Encoding.ASCII.GetString(dataFrame.Value.Payload));

            var trailersFrame = await RuntimeHttp3ProtocolPrimitives
                .ReadFrameAsync(requestStream, lifetimeCts.Token);
            Assert.NotNull(trailersFrame);
            Assert.Equal(RuntimeHttp3ProtocolPrimitives.HeadersFrameType, trailersFrame.Value.Type);

            var trailers = RuntimeQPackDecoderState.DecodeHeaders(trailersFrame.Value.Payload);
            Assert.Equal("0", trailers["grpc-status"]);
            Assert.Equal("ok", trailers["x-final"]);

            Assert.Null(
                await RuntimeHttp3ProtocolPrimitives
                    .ReadFrameAsync(requestStream, lifetimeCts.Token));
        }
        catch (Exception ex) when (IsKnownLocalQuicCredentialLoadFailure(ex))
        {
            return;
        }
    }

    [Fact]
    public async Task ClientSession_reads_response_trailers_after_response_body()
    {
        if (!QuicConnection.IsSupported || !QuicListener.IsSupported)
        {
            return;
        }

        using var lifetimeCts = new CancellationTokenSource(TimeSpan.FromSeconds(30));
        using var certificate = TestCertificateFactory.CreateSelfSignedServerCertificate("localhost", ["localhost"]);

        try
        {
            await using var listener = await CreateListenerAsync(certificate, lifetimeCts.Token);
            var serverSessionTask = AcceptServerSessionAsync(listener, lifetimeCts.Token);
            await using var clientSession = await CreateClientSessionAsync(listener.LocalEndPoint, lifetimeCts.Token);
            await using var serverSession = await serverSessionTask.WaitAsync(lifetimeCts.Token);

            const string responseText = "client-response-with-trailers";
            await using var pendingRequest = await clientSession.StartHttpRequestAsync(
                "GET",
                "unit.test",
                "https",
                "/client/trailers",
                new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
                {
                    ["x-test-case"] = "client-trailers"
                },
                Array.Empty<byte>(),
                lifetimeCts.Token,
                endRequestOnHeaders: true);

            var acceptedRequest = await serverSession.AcceptRequestAsync(lifetimeCts.Token);
            Assert.NotNull(acceptedRequest);

            await using (acceptedRequest!)
            {
                Assert.Equal(0, await acceptedRequest.Body.ReadAsync(new byte[1], lifetimeCts.Token));

                await using var responseBody = await acceptedRequest.OpenResponseBodyAsync(
                    200,
                    new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
                    {
                        ["x-server-case"] = "client-trailers"
                    },
                    lifetimeCts.Token,
                    completeOnDispose: false);
                await responseBody.WriteAsync(Encoding.ASCII.GetBytes(responseText), lifetimeCts.Token);
                await responseBody.DisposeAsync();

                await acceptedRequest.WriteTrailersAsync(
                    new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
                    {
                        ["grpc-status"] = "0",
                        ["x-final"] = "ok"
                    },
                    lifetimeCts.Token);
            }

            await pendingRequest.WaitForSuccessfulStatusAsync(lifetimeCts.Token);
            await using var responseStream = pendingRequest.DetachResponseStream();

            var responseBuffer = new byte[responseText.Length];
            await responseStream.ReadExactlyAsync(responseBuffer, lifetimeCts.Token);
            Assert.Equal(responseText, Encoding.ASCII.GetString(responseBuffer));
            Assert.Equal(0, await responseStream.ReadAsync(new byte[1], lifetimeCts.Token));

            var trailers = await pendingRequest.WaitForResponseTrailersAsync(lifetimeCts.Token);
            Assert.Equal("0", trailers["grpc-status"]);
            Assert.Equal("ok", trailers["x-final"]);
        }
        catch (Exception ex) when (IsKnownLocalQuicCredentialLoadFailure(ex))
        {
            return;
        }
    }

    [Fact]
    public async Task ClientSession_returns_empty_response_trailers_when_response_has_none()
    {
        if (!QuicConnection.IsSupported || !QuicListener.IsSupported)
        {
            return;
        }

        using var lifetimeCts = new CancellationTokenSource(TimeSpan.FromSeconds(30));
        using var certificate = TestCertificateFactory.CreateSelfSignedServerCertificate("localhost", ["localhost"]);

        try
        {
            await using var listener = await CreateListenerAsync(certificate, lifetimeCts.Token);
            var serverSessionTask = AcceptServerSessionAsync(listener, lifetimeCts.Token);
            await using var clientSession = await CreateClientSessionAsync(listener.LocalEndPoint, lifetimeCts.Token);
            await using var serverSession = await serverSessionTask.WaitAsync(lifetimeCts.Token);

            const string responseText = "client-response-without-trailers";
            await using var pendingRequest = await clientSession.StartHttpRequestAsync(
                "GET",
                "unit.test",
                "https",
                "/client/no-trailers",
                new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
                {
                    ["x-test-case"] = "client-no-trailers"
                },
                Array.Empty<byte>(),
                lifetimeCts.Token,
                endRequestOnHeaders: true);

            var acceptedRequest = await serverSession.AcceptRequestAsync(lifetimeCts.Token);
            Assert.NotNull(acceptedRequest);

            await using (acceptedRequest!)
            {
                Assert.Equal(0, await acceptedRequest.Body.ReadAsync(new byte[1], lifetimeCts.Token));

                await using var responseBody = await acceptedRequest.OpenResponseBodyAsync(
                    200,
                    new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
                    {
                        ["x-server-case"] = "client-no-trailers"
                    },
                    lifetimeCts.Token);
                await responseBody.WriteAsync(Encoding.ASCII.GetBytes(responseText), lifetimeCts.Token);
            }

            await pendingRequest.WaitForSuccessfulStatusAsync(lifetimeCts.Token);
            await using var responseStream = pendingRequest.DetachResponseStream();

            var responseBuffer = new byte[responseText.Length];
            await responseStream.ReadExactlyAsync(responseBuffer, lifetimeCts.Token);
            Assert.Equal(responseText, Encoding.ASCII.GetString(responseBuffer));
            Assert.Equal(0, await responseStream.ReadAsync(new byte[1], lifetimeCts.Token));

            var trailers = await pendingRequest.WaitForResponseTrailersAsync(lifetimeCts.Token);
            Assert.Empty(trailers);
        }
        catch (Exception ex) when (IsKnownLocalQuicCredentialLoadFailure(ex))
        {
            return;
        }
    }

    private static async Task<QuicListener> CreateListenerAsync(
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

    private static async Task<RuntimeHttp3ServerSession> AcceptServerSessionAsync(
        QuicListener listener,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(listener);

        var connection = await listener.AcceptConnectionAsync(cancellationToken);
        return await RuntimeHttp3ServerSession.AcceptAsync(connection, cancellationToken);
    }

    private static async Task<RuntimeHttp3ClientSession> CreateClientSessionAsync(
        IPEndPoint remoteEndPoint,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(remoteEndPoint);

        var connection = await CreateClientConnectionAsync(remoteEndPoint, cancellationToken);

        return await RuntimeHttp3ClientSession.CreateAsync(
            new RuntimeQuicClientConnection(connection),
            cancellationToken);
    }

    private static async Task<QuicConnection> CreateClientConnectionAsync(
        IPEndPoint remoteEndPoint,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(remoteEndPoint);

        return await QuicConnection.ConnectAsync(
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
    }

    private static async Task ObserveServerGoAwayAsync(
        QuicConnection connection,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(connection);

        while (true)
        {
            await using var stream = await connection.AcceptInboundStreamAsync(cancellationToken);
            if (stream.Type != QuicStreamType.Unidirectional)
            {
                continue;
            }

            var streamType = await RuntimeHttp3ProtocolPrimitives
                .ReadOptionalVariableLengthIntegerAsync(stream, cancellationToken)
                ;
            if (!streamType.HasValue)
            {
                continue;
            }

            if (streamType.Value != RuntimeHttp3ProtocolPrimitives.ControlStreamType)
            {
                continue;
            }

            var goAwaySeen = false;
            await RuntimeHttp3ClientSession.ScanControlStreamAsync(
                stream,
                () => goAwaySeen = true,
                cancellationToken);
            Assert.True(goAwaySeen);
            return;
        }
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
}

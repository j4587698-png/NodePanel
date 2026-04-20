using System.Net;
using System.Net.Quic;
using System.Net.Security;
using System.Net.Sockets;
using System.Runtime.Versioning;
using System.Security.Authentication;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using NodePanel.Core.Cryptography;
using NodePanel.Core.Protocol;
using NodePanel.Core.Runtime;

namespace NodePanel.Core.Tests;

[SupportedOSPlatform("windows")]
[SupportedOSPlatform("linux")]
[SupportedOSPlatform("macos")]
public sealed class SplitHttpH3InboundServerTests
{
    [Fact]
    public async Task TrojanInboundServer_routes_h3_splithttp_request_into_trojan_handler()
    {
        if (!QuicConnection.IsSupported || !QuicListener.IsSupported)
        {
            return;
        }

        const string inboundTag = "trojan-xhttp-h3";
        const string userId = "trojan-user";
        const string password = "demo-password";

        var result = await ExecuteHttp3InboundScenarioAsync(
            new TrojanHandshakeWriter().Build(password, TrojanCommand.Connect, "example.com", 443),
            (port, certificate, dispatcher, relayService, listenerStarted, cancellationToken) =>
            {
                var user = CreateTrojanUser(userId, password, inboundTag);
                var inbound = new TrojanTlsInboundRuntime
                {
                    Tag = inboundTag,
                    Transport = InboundTransports.SplitHttp,
                    TransportProtocol = RuntimeInternetTransportProtocols.SplitHttp,
                    SecurityType = RuntimeInternetSecurityTypes.Tls,
                    Binding = new ListenerBinding("127.0.0.1", port),
                    Host = "edge.example.com",
                    Path = "/xhttp/",
                    ApplicationProtocols = ["h3"],
                    SplitHttp = CreateSplitHttpInboundOptions(),
                    RuntimeState = new TrojanInboundRuntimeState([user]),
                    UsersByHash = new Dictionary<string, TrojanUser>(StringComparer.Ordinal)
                    {
                        [user.PasswordHash] = user
                    }
                };

                var server = CreateTrojanServer(dispatcher, relayService);
                return server.RunAsync(
                    new TrojanInboundServerOptions
                    {
                        Plan = new TrojanInboundRuntimePlan
                        {
                            TlsListeners =
                            [
                                new TrojanTlsListenerRuntime
                                {
                                    Binding = new ListenerBinding("127.0.0.1", port),
                                    ApplicationProtocols = ["h3"],
                                    SplitHttpInbound = inbound
                                }
                            ]
                        },
                        Tls = new RuntimeTlsOptions
                        {
                            Certificate = certificate
                        },
                        Callbacks = new TrojanInboundServerCallbacks
                        {
                            ListenerStarted = _ => listenerStarted.TrySetResult(true)
                        }
                    },
                    cancellationToken);
            });

        if (result is null)
        {
            return;
        }

        var relayOptions = Assert.IsType<TrojanInboundSessionOptions>(result.RelayOptions);
        Assert.Equal(InboundProtocols.Trojan, result.Context.InboundProtocol);
        Assert.Equal(inboundTag, result.Context.InboundTag);
        Assert.Equal(userId, result.Context.UserId);
        Assert.Equal(RuntimeUserKeys.Create(InboundProtocols.Trojan, inboundTag, userId), result.Context.ScopedUserId);
        Assert.Equal("example.com", result.Destination.Host);
        Assert.Equal(443, result.Destination.Port);
        Assert.Equal("localhost", relayOptions.ServerName);
        Assert.Equal("h3", relayOptions.Alpn);
    }

    [Fact]
    public async Task VlessInboundServer_routes_h3_splithttp_request_into_vless_handler()
    {
        if (!QuicConnection.IsSupported || !QuicListener.IsSupported)
        {
            return;
        }

        const string inboundTag = "vless-xhttp-h3";
        const string userId = "vless-user";
        const string uuid = "11111111-1111-1111-1111-111111111111";

        var result = await ExecuteHttp3InboundScenarioAsync(
            new VlessHandshakeWriter().Build(uuid, VlessCommand.Connect, "example.org", 8443, version: 0),
            (port, certificate, dispatcher, relayService, listenerStarted, cancellationToken) =>
            {
                var user = new VlessUser
                {
                    UserId = userId,
                    Uuid = uuid,
                    RuntimeKey = RuntimeUserKeys.Create(InboundProtocols.Vless, inboundTag, userId),
                    BytesPerSecond = 0
                };
                var inbound = new VlessTlsInboundRuntime
                {
                    Tag = inboundTag,
                    Transport = InboundTransports.SplitHttp,
                    TransportProtocol = RuntimeInternetTransportProtocols.SplitHttp,
                    SecurityType = RuntimeInternetSecurityTypes.Tls,
                    Binding = new ListenerBinding("127.0.0.1", port),
                    Host = "edge.example.com",
                    Path = "/xhttp/",
                    ApplicationProtocols = ["h3"],
                    SplitHttp = CreateSplitHttpInboundOptions(),
                    RuntimeState = new VlessInboundRuntimeState([user]),
                    UsersByUuid = new Dictionary<string, VlessUser>(StringComparer.OrdinalIgnoreCase)
                    {
                        [user.Uuid] = user
                    }
                };

                var server = CreateVlessServer(dispatcher, relayService);
                return server.RunAsync(
                    new VlessInboundServerOptions
                    {
                        Plan = new VlessInboundRuntimePlan
                        {
                            TlsListeners =
                            [
                                new VlessTlsListenerRuntime
                                {
                                    Binding = new ListenerBinding("127.0.0.1", port),
                                    ApplicationProtocols = ["h3"],
                                    SplitHttpInbound = inbound
                                }
                            ]
                        },
                        Tls = new RuntimeTlsOptions
                        {
                            Certificate = certificate
                        },
                        Callbacks = new VlessInboundServerCallbacks
                        {
                            ListenerStarted = _ => listenerStarted.TrySetResult(true)
                        }
                    },
                    cancellationToken);
            });

        if (result is null)
        {
            return;
        }

        var relayOptions = Assert.IsType<VlessInboundSessionOptions>(result.RelayOptions);
        Assert.Equal(InboundProtocols.Vless, result.Context.InboundProtocol);
        Assert.Equal(inboundTag, result.Context.InboundTag);
        Assert.Equal(userId, result.Context.UserId);
        Assert.Equal(RuntimeUserKeys.Create(InboundProtocols.Vless, inboundTag, userId), result.Context.ScopedUserId);
        Assert.Equal("example.org", result.Destination.Host);
        Assert.Equal(8443, result.Destination.Port);
        Assert.Equal(InboundTransports.SplitHttp, relayOptions.Transport);
        Assert.Equal(SslProtocols.Tls13, relayOptions.OuterTlsProtocol);
        Assert.Equal("localhost", relayOptions.ServerName);
        Assert.Equal("h3", relayOptions.Alpn);
    }

    [Fact]
    public async Task VmessInboundServer_routes_h3_splithttp_request_into_vmess_handler()
    {
        if (!QuicConnection.IsSupported || !QuicListener.IsSupported)
        {
            return;
        }

        const string inboundTag = "vmess-xhttp-h3";
        const string userId = "vmess-user";
        const string uuid = "22222222-2222-2222-2222-222222222222";
        var user = new VmessUser
        {
            UserId = userId,
            Uuid = uuid,
            RuntimeKey = RuntimeUserKeys.Create(InboundProtocols.Vmess, inboundTag, userId),
            CmdKey = Enumerable.Range(1, 16).Select(static value => (byte)value).ToArray(),
            BytesPerSecond = 0
        };
        var request = new VmessRequest
        {
            Version = 1,
            User = user,
            RequestBodyKey = Enumerable.Range(0x10, 16).Select(static value => (byte)value).ToArray(),
            RequestBodyIv = Enumerable.Range(0x80, 16).Select(static value => (byte)value).ToArray(),
            ResponseHeader = 0x5A,
            Option = VmessRequestOptions.ChunkStream |
                     VmessRequestOptions.ChunkMasking |
                     VmessRequestOptions.GlobalPadding |
                     VmessRequestOptions.AuthenticatedLength,
            Security = VmessSecurityType.Aes128Gcm,
            Command = VmessCommand.Connect,
            TargetHost = "vmess.example",
            TargetPort = 2053
        };

        var result = await ExecuteHttp3InboundScenarioAsync(
            VmessTestRequestEncoder.BuildRequestHeader(user, request),
            (port, certificate, dispatcher, relayService, listenerStarted, cancellationToken) =>
            {
                var inbound = new VmessTlsInboundRuntime
                {
                    Tag = inboundTag,
                    Transport = InboundTransports.SplitHttp,
                    TransportProtocol = RuntimeInternetTransportProtocols.SplitHttp,
                    SecurityType = RuntimeInternetSecurityTypes.Tls,
                    Binding = new ListenerBinding("127.0.0.1", port),
                    Host = "edge.example.com",
                    Path = "/xhttp/",
                    ApplicationProtocols = ["h3"],
                    SplitHttp = CreateSplitHttpInboundOptions(),
                    RuntimeState = new VmessInboundRuntimeState([user]),
                    Users = [user]
                };

                var server = CreateVmessServer(dispatcher, relayService);
                return server.RunAsync(
                    new VmessInboundServerOptions
                    {
                        Plan = new VmessInboundRuntimePlan
                        {
                            TlsListeners =
                            [
                                new VmessTlsListenerRuntime
                                {
                                    Binding = new ListenerBinding("127.0.0.1", port),
                                    ApplicationProtocols = ["h3"],
                                    SplitHttpInbound = inbound
                                }
                            ]
                        },
                        Tls = new RuntimeTlsOptions
                        {
                            Certificate = certificate
                        },
                        Callbacks = new VmessInboundServerCallbacks
                        {
                            ListenerStarted = _ => listenerStarted.TrySetResult(true)
                        }
                    },
                    cancellationToken);
            });

        if (result is null)
        {
            return;
        }

        var relayOptions = Assert.IsType<VmessInboundSessionOptions>(result.RelayOptions);
        Assert.Equal(InboundProtocols.Vmess, result.Context.InboundProtocol);
        Assert.Equal(inboundTag, result.Context.InboundTag);
        Assert.Equal(userId, result.Context.UserId);
        Assert.Equal(RuntimeUserKeys.Create(InboundProtocols.Vmess, inboundTag, userId), result.Context.ScopedUserId);
        Assert.Equal("vmess.example", result.Destination.Host);
        Assert.Equal(2053, result.Destination.Port);
        Assert.True(relayOptions.DrainOnHandshakeFailure);
        Assert.Equal("localhost", relayOptions.ServerName);
        Assert.Equal("h3", relayOptions.Alpn);
    }

    private static async Task<ObservedInboundResult?> ExecuteHttp3InboundScenarioAsync(
        byte[] requestPayload,
        Func<int, X509Certificate2, BlockingDispatcher, RecordingRelayService, TaskCompletionSource<bool>, CancellationToken, Task> startServer)
    {
        using var lifetimeCts = new CancellationTokenSource(TimeSpan.FromSeconds(20));
        using var certificate = TestCertificateFactory.CreateSelfSignedServerCertificate("localhost", ["localhost"]);

        try
        {
            var port = AllocateUdpPort();
            var dispatcher = new BlockingDispatcher(new MemoryStream());
            var relayService = new RecordingRelayService();
            var listenerStarted = new TaskCompletionSource<bool>(TaskCreationOptions.RunContinuationsAsynchronously);
            var serverTask = startServer(port, certificate, dispatcher, relayService, listenerStarted, lifetimeCts.Token);

            try
            {
                await listenerStarted.Task.WaitAsync(lifetimeCts.Token);

                await using var clientSession = await CreateHttp3ClientSessionAsync(port, lifetimeCts.Token);
                await ExecuteSplitHttpRequestAsync(clientSession, requestPayload, lifetimeCts.Token);

                var context = await dispatcher.DispatchContext.Task.WaitAsync(lifetimeCts.Token);
                var destination = await dispatcher.DispatchDestination.Task.WaitAsync(lifetimeCts.Token);
                var relayOptions = await relayService.ObservedOptions.Task.WaitAsync(lifetimeCts.Token);
                return new ObservedInboundResult(context, destination, relayOptions);
            }
            finally
            {
                lifetimeCts.Cancel();
                await AwaitCompletionAsync(serverTask);
            }
        }
        catch (Exception ex) when (IsKnownLocalQuicCredentialLoadFailure(ex))
        {
            return null;
        }
    }

    private static TrojanUser CreateTrojanUser(string userId, string password, string inboundTag)
    {
        var passwordHash = TrojanPassword.ComputeHash(password);
        return new TrojanUser
        {
            UserId = userId,
            PasswordHash = passwordHash,
            RuntimeKey = RuntimeUserKeys.Create(InboundProtocols.Trojan, inboundTag, userId),
            BytesPerSecond = 0
        };
    }

    private static RuntimeSplitHttpInboundOptions CreateSplitHttpInboundOptions()
        => new()
        {
            Host = "edge.example.com",
            Path = "/xhttp/",
            Mode = "stream-one",
            XPaddingBytes = new RuntimeInt32Range
            {
                From = 1,
                To = 1
            }
        };

    private static TrojanInboundServer CreateTrojanServer(IDispatcher dispatcher, IRuntimeRelayService relayService)
    {
        var rateLimiterRegistry = new RateLimiterRegistry();
        var trafficRegistry = new TrafficRegistry();
        return new TrojanInboundServer(
            new TrojanInboundConnectionHandler(
                dispatcher,
                new TrojanHandshakeReader(),
                new TrojanUdpAssociateRelay(
                    dispatcher,
                    rateLimiterRegistry,
                    trafficRegistry,
                    new TrojanUdpPacketReader(),
                    new TrojanUdpPacketWriter()),
                new TrojanMuxInboundServer(
                    dispatcher,
                    rateLimiterRegistry,
                    trafficRegistry),
                new TrojanFallbackRelayService(new RelayService()),
                new SessionRegistry(),
                relayService,
                rateLimiterRegistry,
                trafficRegistry));
    }

    private static VlessInboundServer CreateVlessServer(IDispatcher dispatcher, IRuntimeRelayService relayService)
    {
        var rateLimiterRegistry = new RateLimiterRegistry();
        var trafficRegistry = new TrafficRegistry();
        return new VlessInboundServer(
            new VlessInboundConnectionHandler(
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
                relayService,
                rateLimiterRegistry,
                trafficRegistry));
    }

    private static VmessInboundServer CreateVmessServer(IDispatcher dispatcher, IRuntimeRelayService relayService)
    {
        var rateLimiterRegistry = new RateLimiterRegistry();
        var trafficRegistry = new TrafficRegistry();
        return new VmessInboundServer(
            new VmessInboundConnectionHandler(
                dispatcher,
                new VmessHandshakeReader(),
                new TrojanMuxInboundServer(
                    dispatcher,
                    rateLimiterRegistry,
                    trafficRegistry),
                new VmessUdpRelay(
                    dispatcher,
                    rateLimiterRegistry,
                    trafficRegistry),
                new SessionRegistry(),
                relayService,
                rateLimiterRegistry,
                trafficRegistry));
    }

    private static async Task<RuntimeHttp3ClientSession> CreateHttp3ClientSessionAsync(
        int port,
        CancellationToken cancellationToken)
    {
        var connection = await QuicConnection.ConnectAsync(
            new QuicClientConnectionOptions
            {
                RemoteEndPoint = new IPEndPoint(IPAddress.Loopback, port),
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

    private static async Task ExecuteSplitHttpRequestAsync(
        RuntimeHttp3ClientSession clientSession,
        byte[] payload,
        CancellationToken cancellationToken)
    {
        await using var pendingRequest = await clientSession.StartHttpRequestAsync(
            "POST",
            "edge.example.com",
            "https",
            "/xhttp/?x_padding=X",
            new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
            {
                ["content-type"] = "application/grpc"
            },
            payload,
            cancellationToken,
            completeRequestAfterInitialPayload: true);
        await pendingRequest.WaitForSuccessfulStatusAsync(cancellationToken);
        await using var responseStream = pendingRequest.DetachResponseStream();
        await DrainStreamAsync(responseStream, cancellationToken);
    }

    private static async Task DrainStreamAsync(Stream stream, CancellationToken cancellationToken)
    {
        var buffer = new byte[256];
        while (await stream.ReadAsync(buffer.AsMemory(), cancellationToken) > 0)
        {
        }
    }

    private static async Task AwaitCompletionAsync(Task task)
    {
        try
        {
            await task;
        }
        catch (OperationCanceledException)
        {
        }
    }

    private static int AllocateUdpPort()
    {
        using var socket = new Socket(AddressFamily.InterNetwork, SocketType.Dgram, ProtocolType.Udp);
        socket.Bind(new IPEndPoint(IPAddress.Loopback, 0));
        return ((IPEndPoint)socket.LocalEndPoint!).Port;
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

    private sealed record ObservedInboundResult(
        DispatchContext Context,
        DispatchDestination Destination,
        IRuntimeInboundConnectionOptions RelayOptions);

    private sealed class RecordingRelayService : IRuntimeRelayService
    {
        private static readonly IRuntimeInboundConnectionOptions DefaultOptions = new StaticInboundConnectionOptions();

        public TaskCompletionSource<IRuntimeInboundConnectionOptions> ObservedOptions { get; }
            = new(TaskCreationOptions.RunContinuationsAsynchronously);

        public Task RelayAsync(
            Stream clientStream,
            Stream remoteStream,
            CancellationToken cancellationToken)
            => RelayCoreAsync(clientStream, DefaultOptions, cancellationToken);

        public Task RelayAsync(
            Stream clientStream,
            Stream remoteStream,
            IRuntimeInboundConnectionOptions options,
            CancellationToken cancellationToken)
            => RelayCoreAsync(clientStream, options, cancellationToken);

        public Task RelayAsync(
            Stream clientStream,
            Stream remoteStream,
            IRuntimeUserDefinition user,
            ByteRateGate userGate,
            ByteRateGate globalGate,
            IRuntimeTrafficRegistry trafficRegistry,
            CancellationToken cancellationToken)
            => RelayCoreAsync(clientStream, DefaultOptions, cancellationToken);

        public Task RelayAsync(
            Stream clientStream,
            Stream remoteStream,
            IRuntimeUserDefinition user,
            ByteRateGate userGate,
            ByteRateGate globalGate,
            IRuntimeTrafficRegistry trafficRegistry,
            IRuntimeInboundConnectionOptions options,
            CancellationToken cancellationToken)
            => RelayCoreAsync(clientStream, options, cancellationToken);

        private async Task RelayCoreAsync(
            Stream clientStream,
            IRuntimeInboundConnectionOptions options,
            CancellationToken cancellationToken)
        {
            ObservedOptions.TrySetResult(options);
            await clientStream.WriteAsync(Encoding.ASCII.GetBytes("ok"), cancellationToken);
            await clientStream.FlushAsync(cancellationToken);
        }
    }

    private sealed record StaticInboundConnectionOptions : IRuntimeInboundConnectionOptions
    {
        public string InboundTag { get; init; } = string.Empty;

        public int UserLevel { get; init; }

        public int HandshakeTimeoutSeconds { get; init; } = 60;

        public int ConnectTimeoutSeconds { get; init; } = 10;

        public int ConnectionIdleSeconds { get; init; } = 300;

        public int UplinkOnlySeconds { get; init; } = 1;

        public int DownlinkOnlySeconds { get; init; } = 1;

        public bool UseCone { get; init; } = true;

        public bool ReceiveOriginalDestination { get; init; }

        public string ServerName { get; init; } = string.Empty;

        public string Alpn { get; init; } = string.Empty;

        public EndPoint? RemoteEndPoint { get; init; }

        public EndPoint? LocalEndPoint { get; init; }

        public EndPoint? OriginalDestinationEndPoint { get; init; }

        public IRuntimeSniffingDefinition Sniffing { get; init; } = RuntimeSniffingOptions.Disabled;
    }
}

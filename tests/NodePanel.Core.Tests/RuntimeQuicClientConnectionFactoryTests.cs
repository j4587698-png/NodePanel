using System.Net;
using System.Net.Quic;
using System.Net.Security;
using System.Runtime.Versioning;
using System.Security.Authentication;
using NodePanel.Core.Runtime;

namespace NodePanel.Core.Tests;

[SupportedOSPlatform("windows")]
[SupportedOSPlatform("linux")]
[SupportedOSPlatform("macos")]
public sealed class RuntimeQuicClientConnectionFactoryTests
{
    [Fact]
    public async Task ResolveRemoteEndPointsAsync_uses_configured_dns_resolver()
    {
        var options = CreateOptions();
        var dnsResolver = new StubDnsResolver(
        [
            IPAddress.Parse("203.0.113.10"),
            IPAddress.Parse("2001:db8::10")
        ]);

        var endPoints = await RuntimeQuicClientConnectionFactory.ResolveRemoteEndPointsAsync(
            options,
            RuntimeInternetStack.Create(RuntimeInternetTransportProtocols.SplitHttp, RuntimeInternetSecurityTypes.Tls),
            dnsResolver,
            CancellationToken.None);

        Assert.Equal("quic.example", dnsResolver.LastHost);
        Assert.Equal(
        [
            new IPEndPoint(IPAddress.Parse("203.0.113.10"), 443),
            new IPEndPoint(IPAddress.Parse("2001:db8::10"), 443)
        ],
            endPoints);
    }

    [Fact]
    public void CreateConnectionOptions_maps_tls_alpn_timeouts_windows_and_bind_endpoint()
    {
        var options = CreateOptions() with
        {
            LocalEndPoint = new IPEndPoint(IPAddress.Parse("198.18.0.7"), 9000),
            Via = "origin",
            HandshakeTimeoutSeconds = 17,
            QuicOptions = new RuntimeQuicOptions
            {
                InitStreamReceiveWindow = 16_384,
                InitConnReceiveWindow = 32_768,
                MaxIdleTimeoutSeconds = 29,
                KeepAlivePeriodSeconds = 11,
                MaxIncomingStreams = 8
            }
        };

        var connectionOptions = RuntimeQuicClientConnectionFactory.CreateConnectionOptions(
            options,
            RuntimeInternetStack.Create(RuntimeInternetTransportProtocols.SplitHttp, RuntimeInternetSecurityTypes.Tls),
            new IPEndPoint(IPAddress.Parse("203.0.113.10"), 443));

        Assert.Equal(
            new IPEndPoint(IPAddress.Parse("203.0.113.10"), 443),
            Assert.IsType<IPEndPoint>(connectionOptions.RemoteEndPoint));

        var localEndPoint = Assert.IsType<IPEndPoint>(connectionOptions.LocalEndPoint);
        Assert.Equal(IPAddress.Parse("198.18.0.7"), localEndPoint.Address);
        Assert.Equal(0, localEndPoint.Port);

        Assert.Equal(TimeSpan.FromSeconds(17), connectionOptions.HandshakeTimeout);
        Assert.Equal(TimeSpan.FromSeconds(29), connectionOptions.IdleTimeout);
        Assert.Equal(TimeSpan.FromSeconds(11), connectionOptions.KeepAliveInterval);
        Assert.Equal(8, connectionOptions.MaxInboundBidirectionalStreams);
        Assert.Equal(8, connectionOptions.MaxInboundUnidirectionalStreams);

        var authOptions = connectionOptions.ClientAuthenticationOptions;
        Assert.Equal("edge.example.com", authOptions.TargetHost);
        Assert.Equal(SslProtocols.Tls13, authOptions.EnabledSslProtocols);
        Assert.Equal(["h3"], authOptions.ApplicationProtocols!.Select(static protocol => protocol.ToString()).ToArray());
        Assert.NotNull(authOptions.RemoteCertificateValidationCallback);

        var receiveWindowSizes = connectionOptions.InitialReceiveWindowSizes;
        Assert.NotNull(receiveWindowSizes);
        Assert.Equal(32_768, receiveWindowSizes.Connection);
        Assert.Equal(16_384, receiveWindowSizes.LocallyInitiatedBidirectionalStream);
        Assert.Equal(16_384, receiveWindowSizes.RemotelyInitiatedBidirectionalStream);
        Assert.Equal(16_384, receiveWindowSizes.UnidirectionalStream);
    }

    [Fact]
    public void CreateConnectionOptions_for_h3_defaults_idle_timeout_keepalive_and_inbound_unidirectional_stream_capacity()
    {
        var options = CreateOptions();

        var connectionOptions = RuntimeQuicClientConnectionFactory.CreateConnectionOptions(
            options,
            RuntimeInternetStack.Create(RuntimeInternetTransportProtocols.SplitHttp, RuntimeInternetSecurityTypes.Tls),
            new IPEndPoint(IPAddress.Parse("203.0.113.10"), 443));

        Assert.Equal(TimeSpan.FromSeconds(300), connectionOptions.IdleTimeout);
        Assert.Equal(TimeSpan.FromSeconds(10), connectionOptions.KeepAliveInterval);
        Assert.Equal(0, connectionOptions.MaxInboundBidirectionalStreams);
        Assert.Equal(10, connectionOptions.MaxInboundUnidirectionalStreams);
    }

    [Fact]
    public void CreateConnectionOptions_preserves_initial_receive_windows_when_initial_and_max_differ()
    {
        var options = CreateOptions() with
        {
            QuicOptions = new RuntimeQuicOptions
            {
                InitStreamReceiveWindow = 16_384,
                MaxStreamReceiveWindow = 65_536,
                InitConnReceiveWindow = 32_768,
                MaxConnReceiveWindow = 131_072
            }
        };

        var connectionOptions = RuntimeQuicClientConnectionFactory.CreateConnectionOptions(
            options,
            RuntimeInternetStack.Create(RuntimeInternetTransportProtocols.SplitHttp, RuntimeInternetSecurityTypes.Tls),
            new IPEndPoint(IPAddress.Parse("203.0.113.10"), 443));

        var receiveWindowSizes = Assert.IsType<QuicReceiveWindowSizes>(connectionOptions.InitialReceiveWindowSizes);
        Assert.Equal(32_768, receiveWindowSizes.Connection);
        Assert.Equal(16_384, receiveWindowSizes.LocallyInitiatedBidirectionalStream);
        Assert.Equal(16_384, receiveWindowSizes.RemotelyInitiatedBidirectionalStream);
        Assert.Equal(16_384, receiveWindowSizes.UnidirectionalStream);
    }

    [Fact]
    public void CreateConnectionOptions_uses_max_receive_windows_when_initial_values_are_not_configured()
    {
        var options = CreateOptions() with
        {
            QuicOptions = new RuntimeQuicOptions
            {
                MaxStreamReceiveWindow = 65_536,
                MaxConnReceiveWindow = 131_072
            }
        };

        var connectionOptions = RuntimeQuicClientConnectionFactory.CreateConnectionOptions(
            options,
            RuntimeInternetStack.Create(RuntimeInternetTransportProtocols.SplitHttp, RuntimeInternetSecurityTypes.Tls),
            new IPEndPoint(IPAddress.Parse("203.0.113.10"), 443));

        var receiveWindowSizes = Assert.IsType<QuicReceiveWindowSizes>(connectionOptions.InitialReceiveWindowSizes);
        Assert.Equal(131_072, receiveWindowSizes.Connection);
        Assert.Equal(65_536, receiveWindowSizes.LocallyInitiatedBidirectionalStream);
        Assert.Equal(65_536, receiveWindowSizes.RemotelyInitiatedBidirectionalStream);
        Assert.Equal(65_536, receiveWindowSizes.UnidirectionalStream);
    }

    [Fact]
    public void CreateConnectionOptions_rejects_custom_transport_stream_factory()
    {
        var options = CreateOptions() with
        {
            TransportStreamFactory = static cancellationToken => ValueTask.FromResult<Stream>(Stream.Null)
        };

        var exception = Assert.Throws<NotSupportedException>(() => RuntimeQuicClientConnectionFactory.CreateConnectionOptions(
            options,
            RuntimeInternetStack.Create(RuntimeInternetTransportProtocols.SplitHttp, RuntimeInternetSecurityTypes.Tls),
            new IPEndPoint(IPAddress.Loopback, 443)));

        Assert.Contains("TransportStreamFactory", exception.Message, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void CreateConnectionOptions_rejects_too_small_receive_window()
    {
        var options = CreateOptions() with
        {
            QuicOptions = new RuntimeQuicOptions
            {
                InitStreamReceiveWindow = 16_383
            }
        };

        var exception = Assert.Throws<ArgumentOutOfRangeException>(() => RuntimeQuicClientConnectionFactory.CreateConnectionOptions(
            options,
            RuntimeInternetStack.Create(RuntimeInternetTransportProtocols.SplitHttp, RuntimeInternetSecurityTypes.Tls),
            new IPEndPoint(IPAddress.Loopback, 443)));

        Assert.Contains("receive window", exception.Message, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void CreateConnectionOptions_rejects_idle_timeout_outside_xray_range()
    {
        var options = CreateOptions() with
        {
            QuicOptions = new RuntimeQuicOptions
            {
                MaxIdleTimeoutSeconds = 3
            }
        };

        var exception = Assert.Throws<ArgumentOutOfRangeException>(() => RuntimeQuicClientConnectionFactory.CreateConnectionOptions(
            options,
            RuntimeInternetStack.Create(RuntimeInternetTransportProtocols.SplitHttp, RuntimeInternetSecurityTypes.Tls),
            new IPEndPoint(IPAddress.Loopback, 443)));

        Assert.Contains("MaxIdleTimeoutSeconds", exception.Message, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void CreateConnectionOptions_rejects_keepalive_outside_xray_range()
    {
        var options = CreateOptions() with
        {
            QuicOptions = new RuntimeQuicOptions
            {
                KeepAlivePeriodSeconds = 61
            }
        };

        var exception = Assert.Throws<ArgumentOutOfRangeException>(() => RuntimeQuicClientConnectionFactory.CreateConnectionOptions(
            options,
            RuntimeInternetStack.Create(RuntimeInternetTransportProtocols.SplitHttp, RuntimeInternetSecurityTypes.Tls),
            new IPEndPoint(IPAddress.Loopback, 443)));

        Assert.Contains("KeepAlivePeriodSeconds", exception.Message, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void CreateConnectionOptions_rejects_too_small_max_incoming_streams()
    {
        var options = CreateOptions() with
        {
            QuicOptions = new RuntimeQuicOptions
            {
                MaxIncomingStreams = 7
            }
        };

        var exception = Assert.Throws<ArgumentOutOfRangeException>(() => RuntimeQuicClientConnectionFactory.CreateConnectionOptions(
            options,
            RuntimeInternetStack.Create(RuntimeInternetTransportProtocols.SplitHttp, RuntimeInternetSecurityTypes.Tls),
            new IPEndPoint(IPAddress.Loopback, 443)));

        Assert.Contains("MaxIncomingStreams", exception.Message, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void CreateConnectionOptions_rejects_negative_max_incoming_streams()
    {
        var options = CreateOptions() with
        {
            QuicOptions = new RuntimeQuicOptions
            {
                MaxIncomingStreams = -1
            }
        };

        var exception = Assert.Throws<ArgumentOutOfRangeException>(() => RuntimeQuicClientConnectionFactory.CreateConnectionOptions(
            options,
            RuntimeInternetStack.Create(RuntimeInternetTransportProtocols.SplitHttp, RuntimeInternetSecurityTypes.Tls),
            new IPEndPoint(IPAddress.Loopback, 443)));

        Assert.Contains("greater than or equal to zero", exception.Message, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void CreateConnectionOptions_rejects_unknown_congestion_algorithm()
    {
        var options = CreateOptions() with
        {
            QuicOptions = new RuntimeQuicOptions
            {
                Congestion = " cubic "
            }
        };

        var exception = Assert.Throws<ArgumentException>(() => RuntimeQuicClientConnectionFactory.CreateConnectionOptions(
            options,
            RuntimeInternetStack.Create(RuntimeInternetTransportProtocols.SplitHttp, RuntimeInternetSecurityTypes.Tls),
            new IPEndPoint(IPAddress.Loopback, 443)));

        Assert.Contains("force-brutal", exception.Message, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void CreateConnectionOptions_rejects_force_brutal_without_brutal_up()
    {
        var options = CreateOptions() with
        {
            QuicOptions = new RuntimeQuicOptions
            {
                Congestion = " FORCE-BRUTAL "
            }
        };

        var exception = Assert.Throws<ArgumentException>(() => RuntimeQuicClientConnectionFactory.CreateConnectionOptions(
            options,
            RuntimeInternetStack.Create(RuntimeInternetTransportProtocols.SplitHttp, RuntimeInternetSecurityTypes.Tls),
            new IPEndPoint(IPAddress.Loopback, 443)));

        Assert.Contains("BrutalUp", exception.Message, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void CreateConnectionOptions_rejects_too_small_brutal_bandwidth()
    {
        var options = CreateOptions() with
        {
            QuicOptions = new RuntimeQuicOptions
            {
                BrutalDown = 65_535
            }
        };

        var exception = Assert.Throws<ArgumentOutOfRangeException>(() => RuntimeQuicClientConnectionFactory.CreateConnectionOptions(
            options,
            RuntimeInternetStack.Create(RuntimeInternetTransportProtocols.SplitHttp, RuntimeInternetSecurityTypes.Tls),
            new IPEndPoint(IPAddress.Loopback, 443)));

        Assert.Contains("BrutalDown", exception.Message, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void CreateConnectionOptions_rejects_udp_hop_interval_below_xray_minimum()
    {
        var options = CreateOptions() with
        {
            QuicOptions = new RuntimeQuicOptions
            {
                UdpHop = new RuntimeUdpHopOptions
                {
                    IntervalMinSeconds = 4
                }
            }
        };

        var exception = Assert.Throws<ArgumentOutOfRangeException>(() => RuntimeQuicClientConnectionFactory.CreateConnectionOptions(
            options,
            RuntimeInternetStack.Create(RuntimeInternetTransportProtocols.SplitHttp, RuntimeInternetSecurityTypes.Tls),
            new IPEndPoint(IPAddress.Loopback, 443)));

        Assert.Contains("IntervalMinSeconds", exception.Message, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void CreateConnectionOptions_rejects_supported_congestion_value_when_runtime_cannot_apply_it()
    {
        var options = CreateOptions() with
        {
            QuicOptions = new RuntimeQuicOptions
            {
                Congestion = " reNo "
            }
        };

        var exception = Assert.Throws<NotSupportedException>(() => RuntimeQuicClientConnectionFactory.CreateConnectionOptions(
            options,
            RuntimeInternetStack.Create(RuntimeInternetTransportProtocols.SplitHttp, RuntimeInternetSecurityTypes.Tls),
            new IPEndPoint(IPAddress.Loopback, 443)));

        Assert.Contains("congestion", exception.Message, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void CreateConnectionOptions_rejects_unsupported_udp_hop_configuration()
    {
        var options = CreateOptions() with
        {
            QuicOptions = new RuntimeQuicOptions
            {
                UdpHop = new RuntimeUdpHopOptions
                {
                    Ports = [3000, 4000]
                }
            }
        };

        var exception = Assert.Throws<NotSupportedException>(() => RuntimeQuicClientConnectionFactory.CreateConnectionOptions(
            options,
            RuntimeInternetStack.Create(RuntimeInternetTransportProtocols.SplitHttp, RuntimeInternetSecurityTypes.Tls),
            new IPEndPoint(IPAddress.Loopback, 443)));

        Assert.Contains("UDP hop", exception.Message, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void CreateConnectionOptions_rejects_non_tls13_configuration()
    {
        var options = CreateOptions() with
        {
            EnabledSslProtocolsValue = SslProtocols.Tls12
        };

        var exception = Assert.Throws<NotSupportedException>(() => RuntimeQuicClientConnectionFactory.CreateConnectionOptions(
            options,
            RuntimeInternetStack.Create(RuntimeInternetTransportProtocols.SplitHttp, RuntimeInternetSecurityTypes.Tls),
            new IPEndPoint(IPAddress.Loopback, 443)));

        Assert.Contains("TLS 1.3", exception.Message, StringComparison.OrdinalIgnoreCase);
    }

    private static TestQuicInternetOptions CreateOptions()
        => new()
        {
            ServerHost = "quic.example",
            ServerPort = 443,
            ServerName = "edge.example.com",
            SecurityType = RuntimeInternetSecurityTypes.Tls,
            ApplicationProtocols = ["h3"]
        };

    private sealed record TestQuicInternetOptions : IRuntimeGrpcClientDialOptions
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

        public RuntimeQuicOptions QuicOptions { get; init; } = RuntimeQuicOptions.Empty;

        public string GrpcServiceName => string.Empty;

        public string GrpcAuthority => string.Empty;

        public bool GrpcMultiMode => false;

        public string GrpcUserAgent => string.Empty;

        public int GrpcIdleTimeoutSeconds => 0;

        public int GrpcHealthCheckTimeoutSeconds => 0;

        public bool GrpcPermitWithoutStream => false;

        public int GrpcInitialWindowSize => 0;

        public int ConnectTimeoutSeconds { get; init; } = 10;

        public int HandshakeTimeoutSeconds { get; init; } = 10;

        public bool SkipCertificateValidation => true;

        public RemoteCertificateValidationCallback? CertificateValidationCallback => null;

        public SslProtocols EnabledSslProtocols => EnabledSslProtocolsValue;

        public SslProtocols EnabledSslProtocolsValue { get; init; } = SslProtocols.Tls12 | SslProtocols.Tls13;

        public IRuntimeRealityHandshakeProvider? RealityHandshakeProvider => null;

        public Func<CancellationToken, ValueTask<Stream>>? TransportStreamFactory { get; init; }

        public Func<CancellationToken, ValueTask<Stream>>? SplitHttpDownloadTransportStreamFactory => null;
    }

    private sealed class StubDnsResolver : IDnsResolver
    {
        private readonly IReadOnlyList<IPAddress> _addresses;

        public StubDnsResolver(IReadOnlyList<IPAddress> addresses)
        {
            _addresses = addresses;
        }

        public string LastHost { get; private set; } = string.Empty;

        public ValueTask<IReadOnlyList<IPAddress>> ResolveAsync(string host, CancellationToken cancellationToken)
        {
            LastHost = host;
            return ValueTask.FromResult(_addresses);
        }
    }
}

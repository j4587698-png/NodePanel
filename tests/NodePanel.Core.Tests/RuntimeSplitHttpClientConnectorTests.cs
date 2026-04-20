using System.Net;
using System.Net.Security;
using System.Reflection;
using System.Runtime.Versioning;
using System.Security.Authentication;
using System.Text;
using NodePanel.Core.Runtime;

namespace NodePanel.Core.Tests;

[SupportedOSPlatform("windows")]
[SupportedOSPlatform("linux")]
[SupportedOSPlatform("macos")]
public sealed class RuntimeSplitHttpClientConnectorTests
{
    [Fact]
    public void ResolveHttp3DialOptions_uses_xmux_keepalive_when_quic_keepalive_is_not_configured()
    {
        var options = new TestSplitHttpDialOptions
        {
            SplitHttpXmux = new RuntimeSplitHttpXmuxOptions
            {
                HKeepAlivePeriodSeconds = 19
            }
        };

        var resolved = RuntimeSplitHttpClientConnector.ResolveHttp3DialOptions(options);
        var connectionOptions = RuntimeQuicClientConnectionFactory.CreateConnectionOptions(
            resolved,
            RuntimeInternetStack.Create(RuntimeInternetTransportProtocols.SplitHttp, RuntimeInternetSecurityTypes.Tls),
            new IPEndPoint(IPAddress.Loopback, 443));

        Assert.NotSame(options, resolved);
        Assert.Equal(19, resolved.QuicOptions.KeepAlivePeriodSeconds);
        Assert.Equal(TimeSpan.FromSeconds(19), connectionOptions.KeepAliveInterval);
    }

    [Fact]
    public void ResolveHttp3DialOptions_preserves_explicit_quic_keepalive()
    {
        var options = new TestSplitHttpDialOptions
        {
            SplitHttpXmux = new RuntimeSplitHttpXmuxOptions
            {
                HKeepAlivePeriodSeconds = 19
            },
            QuicOptions = new RuntimeQuicOptions
            {
                KeepAlivePeriodSeconds = 7
            }
        };

        var resolved = RuntimeSplitHttpClientConnector.ResolveHttp3DialOptions(options);
        var connectionOptions = RuntimeQuicClientConnectionFactory.CreateConnectionOptions(
            resolved,
            RuntimeInternetStack.Create(RuntimeInternetTransportProtocols.SplitHttp, RuntimeInternetSecurityTypes.Tls),
            new IPEndPoint(IPAddress.Loopback, 443));

        Assert.Same(options, resolved);
        Assert.Equal(7, resolved.QuicOptions.KeepAlivePeriodSeconds);
        Assert.Equal(TimeSpan.FromSeconds(7), connectionOptions.KeepAliveInterval);
    }

    [Fact]
    public void ResolveHttp3DialOptions_rejects_conflicting_xmux_connection_and_concurrency_limits()
    {
        var options = new TestSplitHttpDialOptions
        {
            SplitHttpXmux = new RuntimeSplitHttpXmuxOptions
            {
                MaxConcurrency = new RuntimeInt32Range
                {
                    From = 1,
                    To = 2
                },
                MaxConnections = new RuntimeInt32Range
                {
                    From = 0,
                    To = 3
                }
            }
        };

        var exception = Assert.Throws<InvalidOperationException>(() => RuntimeSplitHttpClientConnector.ResolveHttp3DialOptions(options));

        Assert.Contains("maxConnections", exception.Message, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("maxConcurrency", exception.Message, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void NormalizeScMinPostsIntervalMs_preserves_explicit_range_when_effective_upper_bound_is_positive()
    {
        var normalized = RuntimeSplitHttpClientConnector.NormalizeScMinPostsIntervalMs(
            new RuntimeInt32Range
            {
                From = 25,
                To = 0
            });

        Assert.Equal(25, normalized.From);
        Assert.Equal(0, normalized.To);
        Assert.False(RuntimeSplitHttpClientConnector.ShouldDelayPacketUploads(normalized));
    }

    [Fact]
    public void NormalizeUplinkChunkSize_uses_effective_range_before_falling_back_to_defaults()
    {
        var normalized = RuntimeSplitHttpClientConnector.NormalizeUplinkChunkSize(
            new RuntimeInt32Range
            {
                From = 128,
                To = 0
            },
            "body",
            new RuntimeInt32Range
            {
                From = 1024,
                To = 2048
            });

        Assert.Equal(64, normalized.From);
        Assert.Equal(128, normalized.To);
    }

    [Fact]
    public void GetRandomRangeValue_matches_xray_core_exclusive_upper_bound()
    {
        var exactUpperBoundRange = new RuntimeInt32Range
        {
            From = 5,
            To = 6
        };
        var swappedRange = new RuntimeInt32Range
        {
            From = 6,
            To = 5
        };

        for (var attempt = 0; attempt < 32; attempt++)
        {
            Assert.Equal(5, RuntimeSplitHttpClientConnector.GetRandomRangeValue(exactUpperBoundRange));
            Assert.Equal(5, RuntimeSplitHttpClientConnector.GetRandomRangeValue(swappedRange));
        }
    }

    [Fact]
    public async Task SplitHttpBufferedUploadPipe_returns_full_buffered_batch_before_runtime_split()
    {
        var pipe = new RuntimeSplitHttpClientConnector.SplitHttpBufferedUploadPipe(maxUploadSize: 6);

        await pipe.WriteAsync(Encoding.ASCII.GetBytes("abcdefghijkl"), CancellationToken.None);
        pipe.Complete();

        var batch = await pipe.ReadAsync(CancellationToken.None);

        Assert.NotNull(batch);
        Assert.Equal("abcdefghijkl", Encoding.ASCII.GetString(batch!));
        Assert.Null(await pipe.ReadAsync(CancellationToken.None));
    }

    [Fact]
    public async Task SplitHttpBufferedUploadPipe_blocks_additional_segments_by_buffered_bytes()
    {
        var pipe = new RuntimeSplitHttpClientConnector.SplitHttpBufferedUploadPipe(maxUploadSize: 9000);

        Assert.Equal(808, pipe.BufferedByteLimit);

        await pipe.WriteAsync(new byte[1000], CancellationToken.None);
        var blockedWrite = pipe.WriteAsync(new byte[10], CancellationToken.None).AsTask();

        await Task.Delay(50);
        Assert.False(blockedWrite.IsCompleted);

        var firstBatch = await pipe.ReadAsync(CancellationToken.None);
        Assert.NotNull(firstBatch);
        Assert.Equal(1000, firstBatch!.Length);

        await blockedWrite;
        pipe.Complete();

        var secondBatch = await pipe.ReadAsync(CancellationToken.None);
        Assert.NotNull(secondBatch);
        Assert.Equal(10, secondBatch!.Length);
        Assert.Null(await pipe.ReadAsync(CancellationToken.None));
    }

    [Fact]
    public async Task SplitHttpBufferedUploadPipe_flush_boundary_separates_following_writes()
    {
        var pipe = new RuntimeSplitHttpClientConnector.SplitHttpBufferedUploadPipe(maxUploadSize: 64);

        await pipe.WriteAsync(Encoding.ASCII.GetBytes("first-packet"), CancellationToken.None);
        var flushTask = pipe.FlushAsync(CancellationToken.None).AsTask();

        var firstBatch = await pipe.ReadAsync(CancellationToken.None);
        Assert.NotNull(firstBatch);
        Assert.Equal("first-packet", Encoding.ASCII.GetString(firstBatch!));

        Assert.False(pipe.TryReadAvailable(out var noBatch, out var encounteredFlushBoundary));
        Assert.Null(noBatch);
        Assert.True(encounteredFlushBoundary);
        await flushTask;

        await pipe.WriteAsync(Encoding.ASCII.GetBytes("second-packet"), CancellationToken.None);
        pipe.Complete();

        var secondBatch = await pipe.ReadAsync(CancellationToken.None);
        Assert.NotNull(secondBatch);
        Assert.Equal("second-packet", Encoding.ASCII.GetString(secondBatch!));
        Assert.Null(await pipe.ReadAsync(CancellationToken.None));
    }

    [Fact]
    public void SerializeRealityOptions_uses_normalized_show_master_key_log_and_spider_profile()
    {
        var serializeRealityOptions = CreateSerializeRealityOptionsDelegate();
        var publicKey = EncodeBase64Url(32, 0x31);
        var serialized = serializeRealityOptions(new RuntimeRealityOptions
        {
            Show = true,
            MasterKeyLog = " logs/master.keys ",
            Fingerprint = " CHROME ",
            Password = publicKey,
            ShortId = " A1B2 ",
            SpiderX = string.Empty
        });

        Assert.Equal(
            string.Join(
                "|",
                "1",
                "logs/master.keys",
                "chrome",
                publicKey,
                "a1b2",
                string.Empty,
                "/",
                "0,0,0,0,0,0,0,0,0,0"),
            serialized);
    }

    [Fact]
    public void SerializeRealityOptions_treats_none_master_key_log_as_empty()
    {
        var serializeRealityOptions = CreateSerializeRealityOptionsDelegate();
        var publicKey = EncodeBase64Url(32, 0x31);
        var emptySerialized = serializeRealityOptions(new RuntimeRealityOptions
        {
            Fingerprint = "chrome",
            Password = publicKey,
            ShortId = "a1b2"
        });
        var noneSerialized = serializeRealityOptions(new RuntimeRealityOptions
        {
            Fingerprint = "chrome",
            Password = publicKey,
            ShortId = "a1b2",
            MasterKeyLog = " none "
        });

        Assert.Equal(emptySerialized, noneSerialized);
    }

    private sealed record TestSplitHttpDialOptions : IRuntimeGrpcClientDialOptions
    {
        public DispatchContext DialContext { get; init; } = new();

        public EndPoint? SourceEndPoint { get; init; }

        public EndPoint? LocalEndPoint { get; init; }

        public string Via { get; init; } = string.Empty;

        public string ViaCidr { get; init; } = string.Empty;

        public string ServerHost { get; init; } = "127.0.0.1";

        public int ServerPort { get; init; } = 443;

        public string ServerName { get; init; } = "edge.example.com";

        public string Fingerprint { get; init; } = string.Empty;

        public string TransportProtocol => RuntimeInternetTransportProtocols.SplitHttp;

        public string SecurityType => RuntimeInternetSecurityTypes.Tls;

        public RuntimeRealityOptions RealityOptions { get; init; } = RuntimeRealityOptions.Empty;

        public string WebSocketPath { get; init; } = "/";

        public IReadOnlyDictionary<string, string> WebSocketHeaders { get; init; }
            = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);

        public int WebSocketEarlyDataBytes { get; init; }

        public int WebSocketHeartbeatPeriodSeconds { get; init; }

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

        public IReadOnlyList<string> ApplicationProtocols { get; init; } = ["h3"];

        public RuntimeQuicOptions QuicOptions { get; init; } = RuntimeQuicOptions.Empty;

        public string GrpcServiceName { get; init; } = string.Empty;

        public string GrpcAuthority { get; init; } = string.Empty;

        public bool GrpcMultiMode { get; init; }

        public string GrpcUserAgent { get; init; } = string.Empty;

        public int GrpcIdleTimeoutSeconds { get; init; }

        public int GrpcHealthCheckTimeoutSeconds { get; init; }

        public bool GrpcPermitWithoutStream { get; init; }

        public int GrpcInitialWindowSize { get; init; }

        public bool SkipCertificateValidation { get; init; } = true;

        public RemoteCertificateValidationCallback? CertificateValidationCallback { get; init; }

        public SslProtocols EnabledSslProtocols { get; init; } = SslProtocols.Tls13;

        public IRuntimeRealityHandshakeProvider? RealityHandshakeProvider { get; init; }

        public int ConnectTimeoutSeconds { get; init; } = 10;

        public int HandshakeTimeoutSeconds { get; init; } = 10;

        public Func<CancellationToken, ValueTask<Stream>>? TransportStreamFactory { get; init; }

        public Func<CancellationToken, ValueTask<Stream>>? SplitHttpDownloadTransportStreamFactory { get; init; }
    }

    private static Func<RuntimeRealityOptions, string> CreateSerializeRealityOptionsDelegate()
    {
        var method = typeof(RuntimeSplitHttpClientConnector).GetMethod(
            "SerializeRealityOptions",
            BindingFlags.Static | BindingFlags.NonPublic);
        Assert.NotNull(method);
        return method!.CreateDelegate<Func<RuntimeRealityOptions, string>>();
    }

    private static string EncodeBase64Url(int length, byte value)
    {
        var bytes = new byte[length];
        Array.Fill(bytes, value);
        return Convert.ToBase64String(bytes)
            .TrimEnd('=')
            .Replace('+', '-')
            .Replace('/', '_');
    }
}

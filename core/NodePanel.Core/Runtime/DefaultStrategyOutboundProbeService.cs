using System.Collections.Concurrent;
using System.Diagnostics;
using System.Net.Security;
using System.Security.Authentication;
using System.Text;

namespace NodePanel.Core.Runtime;

public sealed class DefaultStrategyOutboundProbeService : IStrategyOutboundProbeService, IStrategyOutboundProbeCache
{
    private readonly ConcurrentDictionary<string, ProbeCacheEntry> _cache = new(StringComparer.OrdinalIgnoreCase);
    private readonly RuntimeInternetProfile _internetProfile;
    private readonly ConcurrentDictionary<string, SemaphoreSlim> _locks = new(StringComparer.OrdinalIgnoreCase);
    private readonly IServiceProvider? _serviceProvider;

    public DefaultStrategyOutboundProbeService(IServiceProvider? serviceProvider = null)
        : this(serviceProvider, RuntimeInternetProfile.Default)
    {
    }

    internal DefaultStrategyOutboundProbeService(
        IServiceProvider? serviceProvider,
        RuntimeInternetProfile internetProfile)
    {
        _serviceProvider = serviceProvider;
        _internetProfile = internetProfile;
    }

    public async ValueTask<IReadOnlyList<StrategyCandidateProbeResult>> ProbeAsync(
        StrategyOutboundSettings settings,
        CancellationToken cancellationToken)
    {
        if (TryGetFreshResults(settings, out var cached))
        {
            return cached;
        }

        var gate = _locks.GetOrAdd(settings.Tag, static _ => new SemaphoreSlim(1, 1));
        await gate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            if (TryGetFreshResults(settings, out cached))
            {
                return cached;
            }

            var results = await ProbeCoreAsync(settings, cancellationToken).ConfigureAwait(false);
            _cache[settings.Tag] = new ProbeCacheEntry
            {
                CheckedAt = DateTimeOffset.UtcNow,
                Results = results
            };
            return results;
        }
        finally
        {
            gate.Release();
        }
    }

    public bool TryGetCachedResults(string? tag, out IReadOnlyList<StrategyCandidateProbeResult> results)
    {
        if (!string.IsNullOrWhiteSpace(tag) &&
            _cache.TryGetValue(tag.Trim(), out var entry))
        {
            results = entry.Results;
            return true;
        }

        results = Array.Empty<StrategyCandidateProbeResult>();
        return false;
    }

    public void Invalidate(string? tag)
    {
        if (string.IsNullOrWhiteSpace(tag))
        {
            return;
        }

        _cache.TryRemove(tag.Trim(), out _);
    }

    public void InvalidateAll() => _cache.Clear();

    private bool TryGetFreshResults(StrategyOutboundSettings settings, out IReadOnlyList<StrategyCandidateProbeResult> results)
    {
        if (_cache.TryGetValue(settings.Tag, out var entry) &&
            DateTimeOffset.UtcNow - entry.CheckedAt < TimeSpan.FromSeconds(settings.ProbeIntervalSeconds))
        {
            results = entry.Results;
            return true;
        }

        results = Array.Empty<StrategyCandidateProbeResult>();
        return false;
    }

    private async ValueTask<IReadOnlyList<StrategyCandidateProbeResult>> ProbeCoreAsync(
        StrategyOutboundSettings settings,
        CancellationToken cancellationToken)
    {
        if (!Uri.TryCreate(settings.ProbeUrl, UriKind.Absolute, out var probeUri))
        {
            return settings.CandidateTags
                .Select(static tag => new StrategyCandidateProbeResult
                {
                    Tag = tag,
                    Success = false
                })
                .ToArray();
        }

        var pathAndQuery = string.IsNullOrWhiteSpace(probeUri.PathAndQuery) ? "/" : probeUri.PathAndQuery;
        var port = probeUri.IsDefaultPort
            ? probeUri.Scheme.Equals("https", StringComparison.OrdinalIgnoreCase) ? 443 : 80
            : probeUri.Port;

        var results = new List<StrategyCandidateProbeResult>(settings.CandidateTags.Count);
        foreach (var candidateTag in settings.CandidateTags)
        {
            results.Add(await ProbeCandidateAsync(
                    settings,
                    candidateTag,
                    probeUri,
                    pathAndQuery,
                    port,
                    cancellationToken)
                .ConfigureAwait(false));
        }

        return results;
    }

    private async ValueTask<StrategyCandidateProbeResult> ProbeCandidateAsync(
        StrategyOutboundSettings settings,
        string candidateTag,
        Uri probeUri,
        string pathAndQuery,
        int port,
        CancellationToken cancellationToken)
    {
        var startedAt = Stopwatch.GetTimestamp();
        using var timeoutCts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        timeoutCts.CancelAfter(TimeSpan.FromSeconds(settings.ProbeTimeoutSeconds));

        try
        {
            var destination = new DispatchDestination
            {
                Host = probeUri.Host,
                Port = port,
                Network = DispatchNetwork.Tcp
            };
            var context = new DispatchContext
            {
                OutboundTag = candidateTag,
                ConnectTimeoutSeconds = settings.ProbeTimeoutSeconds,
                OriginalDestinationHost = probeUri.Host,
                OriginalDestinationPort = port
            };

            Stream? stream = null;
            Stream? effectiveStream = null;
            try
            {
                stream = await ResolveDispatcher().DispatchTcpAsync(context, destination, timeoutCts.Token).ConfigureAwait(false);
                effectiveStream = await OpenProbeStreamAsync(stream, probeUri, timeoutCts.Token).ConfigureAwait(false);

                var request =
                    $"HEAD {pathAndQuery} HTTP/1.1\r\nHost: {probeUri.Host}\r\nConnection: close\r\nUser-Agent: NodePanel-StrategyProbe/1.0\r\n\r\n";
                var requestBytes = Encoding.ASCII.GetBytes(request);
                await effectiveStream.WriteAsync(requestBytes, timeoutCts.Token).ConfigureAwait(false);
                await effectiveStream.FlushAsync(timeoutCts.Token).ConfigureAwait(false);

                var buffer = new byte[16];
                var read = await effectiveStream.ReadAsync(buffer.AsMemory(0, buffer.Length), timeoutCts.Token).ConfigureAwait(false);
                return new StrategyCandidateProbeResult
                {
                    Tag = candidateTag,
                    Success = read > 0,
                    LatencyMilliseconds = (long)Stopwatch.GetElapsedTime(startedAt).TotalMilliseconds,
                    CheckedAt = DateTimeOffset.UtcNow
                };
            }
            finally
            {
                if (effectiveStream is not null &&
                    !ReferenceEquals(effectiveStream, stream))
                {
                    await effectiveStream.DisposeAsync().ConfigureAwait(false);
                }

                if (stream is not null)
                {
                    await stream.DisposeAsync().ConfigureAwait(false);
                }
            }
        }
        catch
        {
            return new StrategyCandidateProbeResult
            {
                Tag = candidateTag,
                Success = false,
                CheckedAt = DateTimeOffset.UtcNow
            };
        }
    }

    private async ValueTask<Stream> OpenProbeStreamAsync(
        Stream stream,
        Uri probeUri,
        CancellationToken cancellationToken)
    {
        var stack = RuntimeInternetStack.Create(
            RuntimeInternetTransportProtocols.Tcp,
            probeUri.Scheme.Equals("https", StringComparison.OrdinalIgnoreCase)
                ? RuntimeInternetSecurityTypes.Tls
                : RuntimeInternetSecurityTypes.None);

        var connection = await _internetProfile
            .OpenAsync(
                stream,
                stack,
                new ProbeInternetOptions(probeUri.Host),
                transportInitializationData: null,
                cancellationToken)
            .ConfigureAwait(false);

        return connection.ApplicationStream;
    }

    private IDispatcher ResolveDispatcher()
        => _serviceProvider?.GetService(typeof(IDispatcher)) as IDispatcher
           ?? throw new InvalidOperationException("Strategy outbound probing requires an active dispatcher.");

    private sealed record ProbeInternetOptions(string ServerHost) : IRuntimeInternetOptions
    {
        public string ServerName => ServerHost;

        public string Fingerprint => string.Empty;

        public string TransportProtocol => RuntimeInternetTransportProtocols.Tcp;

        public string SecurityType => RuntimeInternetSecurityTypes.None;

        public RuntimeRealityOptions RealityOptions => RuntimeRealityOptions.Empty;

        public string WebSocketPath => "/";

        public IReadOnlyDictionary<string, string> WebSocketHeaders { get; } = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);

        public int WebSocketHeartbeatPeriodSeconds => 0;

        public string SplitHttpHost => string.Empty;

        public string SplitHttpPath => "/";

        public IReadOnlyDictionary<string, string> SplitHttpHeaders { get; }
            = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);

        public string SplitHttpMode => string.Empty;

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

        public IReadOnlyList<string> ApplicationProtocols { get; } = ["http/1.1"];

        public RuntimeQuicOptions QuicOptions => RuntimeQuicOptions.Empty;

        public string GrpcServiceName => string.Empty;

        public string GrpcAuthority => string.Empty;

        public bool GrpcMultiMode => false;

        public string GrpcUserAgent => string.Empty;

        public int GrpcIdleTimeoutSeconds => 0;

        public int GrpcHealthCheckTimeoutSeconds => 0;

        public bool GrpcPermitWithoutStream => false;

        public int GrpcInitialWindowSize => 0;

        public bool SkipCertificateValidation => true;

        public RemoteCertificateValidationCallback? CertificateValidationCallback => null;

        public SslProtocols EnabledSslProtocols => SslProtocols.Tls12 | SslProtocols.Tls13;
    }

    private sealed record ProbeCacheEntry
    {
        public DateTimeOffset CheckedAt { get; init; }

        public IReadOnlyList<StrategyCandidateProbeResult> Results { get; init; } = Array.Empty<StrategyCandidateProbeResult>();
    }
}

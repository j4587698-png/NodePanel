using System.Collections.Concurrent;
using System.Diagnostics;
using System.Net.Security;
using System.Text;
using NodePanel.Core.Runtime;

namespace NodePanel.Service.Runtime;

public sealed class StrategyOutboundProbeService : IStrategyOutboundProbeService
{
    private readonly ConcurrentDictionary<string, ProbeCacheEntry> _cache = new(StringComparer.OrdinalIgnoreCase);
    private readonly ConcurrentDictionary<string, SemaphoreSlim> _locks = new(StringComparer.OrdinalIgnoreCase);
    private readonly IServiceProvider? _serviceProvider;

    public StrategyOutboundProbeService(IServiceProvider? serviceProvider = null)
    {
        _serviceProvider = serviceProvider;
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

            await using var stream = await ResolveDispatcher().DispatchTcpAsync(context, destination, timeoutCts.Token).ConfigureAwait(false);
            Stream effectiveStream = stream;
            if (probeUri.Scheme.Equals("https", StringComparison.OrdinalIgnoreCase))
            {
                using var sslStream = new SslStream(
                    stream,
                    leaveInnerStreamOpen: false,
                    static (_, _, _, _) => true);
                await sslStream.AuthenticateAsClientAsync(
                    new SslClientAuthenticationOptions
                    {
                        TargetHost = probeUri.Host,
                        EnabledSslProtocols = System.Security.Authentication.SslProtocols.Tls12 |
                                              System.Security.Authentication.SslProtocols.Tls13,
                        CertificateRevocationCheckMode = System.Security.Cryptography.X509Certificates.X509RevocationMode.NoCheck,
                        RemoteCertificateValidationCallback = static (_, _, _, _) => true
                    },
                    timeoutCts.Token).ConfigureAwait(false);
                effectiveStream = sslStream;
            }

            var request =
                $"HEAD {pathAndQuery} HTTP/1.1\r\nHost: {probeUri.Host}\r\nConnection: close\r\nUser-Agent: NodePanel-StrategyProbe/1.0\r\n\r\n";
            var requestBytes = Encoding.ASCII.GetBytes(request);
            await effectiveStream.WriteAsync(requestBytes, timeoutCts.Token).ConfigureAwait(false);
            await effectiveStream.FlushAsync(timeoutCts.Token).ConfigureAwait(false);

            var buffer = new byte[16];
            var read = await effectiveStream.ReadAsync(buffer.AsMemory(0, buffer.Length), timeoutCts.Token).ConfigureAwait(false);
            var success = read > 0;
            return new StrategyCandidateProbeResult
            {
                Tag = candidateTag,
                Success = success,
                LatencyMilliseconds = (long)Stopwatch.GetElapsedTime(startedAt).TotalMilliseconds,
                CheckedAt = DateTimeOffset.UtcNow
            };
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

    private sealed record ProbeCacheEntry
    {
        public DateTimeOffset CheckedAt { get; init; }

        public IReadOnlyList<StrategyCandidateProbeResult> Results { get; init; } = Array.Empty<StrategyCandidateProbeResult>();
    }

    private IDispatcher ResolveDispatcher()
        => _serviceProvider?.GetService(typeof(IDispatcher)) as IDispatcher
           ?? throw new InvalidOperationException("Strategy outbound probing requires an active dispatcher.");
}

using System.Collections.Concurrent;

namespace NodePanel.Core.Runtime;

public abstract class StrategyOutboundHandlerBase : IOutboundHandler
{
    private readonly IStrategyOutboundProbeService _probeService;
    private readonly IServiceProvider? _serviceProvider;
    private readonly IStrategyOutboundSettingsProvider _settingsProvider;

    protected StrategyOutboundHandlerBase(
        IStrategyOutboundSettingsProvider settingsProvider,
        IStrategyOutboundProbeService probeService,
        IServiceProvider? serviceProvider = null)
    {
        _settingsProvider = settingsProvider;
        _probeService = probeService;
        _serviceProvider = serviceProvider;
    }

    public abstract string Protocol { get; }

    public async ValueTask<Stream> OpenTcpAsync(
        DispatchContext context,
        DispatchDestination destination,
        CancellationToken cancellationToken)
    {
        var selectedTag = await ResolveSelectedTagAsync(context, cancellationToken).ConfigureAwait(false);
        if (string.IsNullOrWhiteSpace(selectedTag))
        {
            throw new InvalidOperationException($"Strategy outbound '{Protocol}' did not resolve a candidate outbound.");
        }

        return await ResolveDispatcher().DispatchTcpAsync(
            context with
            {
                OutboundTag = selectedTag
            },
            destination,
            cancellationToken).ConfigureAwait(false);
    }

    public async ValueTask<IOutboundUdpTransport> OpenUdpAsync(
        DispatchContext context,
        CancellationToken cancellationToken)
    {
        var selectedTag = await ResolveSelectedTagAsync(context, cancellationToken).ConfigureAwait(false);
        if (string.IsNullOrWhiteSpace(selectedTag))
        {
            throw new InvalidOperationException($"Strategy outbound '{Protocol}' did not resolve a candidate outbound.");
        }

        return await ResolveDispatcher().DispatchUdpAsync(
            context with
            {
                OutboundTag = selectedTag
            },
            cancellationToken).ConfigureAwait(false);
    }

    private async ValueTask<string> ResolveSelectedTagAsync(DispatchContext context, CancellationToken cancellationToken)
    {
        if (!_settingsProvider.TryResolve(context, out var settings))
        {
            throw new InvalidOperationException($"Strategy outbound settings could not be resolved for protocol '{Protocol}'.");
        }

        if (!string.Equals(settings.Protocol, Protocol, StringComparison.Ordinal))
        {
            throw new InvalidOperationException(
                $"Strategy outbound protocol mismatch. Expected '{Protocol}', got '{settings.Protocol}'.");
        }

        return await SelectTagAsync(settings, cancellationToken).ConfigureAwait(false);
    }

    protected abstract ValueTask<string> SelectTagAsync(
        StrategyOutboundSettings settings,
        CancellationToken cancellationToken);

    protected ValueTask<IReadOnlyList<StrategyCandidateProbeResult>> ProbeAsync(
        StrategyOutboundSettings settings,
        CancellationToken cancellationToken)
        => _probeService.ProbeAsync(settings, cancellationToken);

    private IDispatcher ResolveDispatcher()
        => _serviceProvider?.GetService(typeof(IDispatcher)) as IDispatcher
           ?? throw new InvalidOperationException("Strategy outbound dispatch requires an active dispatcher.");
}

public sealed class SelectorOutboundHandler : StrategyOutboundHandlerBase
{
    public SelectorOutboundHandler(
        IStrategyOutboundSettingsProvider settingsProvider,
        IStrategyOutboundProbeService probeService,
        IServiceProvider? serviceProvider = null)
        : base(settingsProvider, probeService, serviceProvider)
    {
    }

    public override string Protocol => OutboundProtocols.Selector;

    protected override ValueTask<string> SelectTagAsync(
        StrategyOutboundSettings settings,
        CancellationToken cancellationToken)
        => ValueTask.FromResult(
            !string.IsNullOrWhiteSpace(settings.SelectedTag)
                ? settings.SelectedTag
                : settings.CandidateTags.FirstOrDefault(static _ => true) ?? string.Empty);
}

public sealed class LoadBalanceOutboundHandler : StrategyOutboundHandlerBase
{
    private readonly ConcurrentDictionary<string, int> _counters = new(StringComparer.OrdinalIgnoreCase);

    public LoadBalanceOutboundHandler(
        IStrategyOutboundSettingsProvider settingsProvider,
        IStrategyOutboundProbeService probeService,
        IServiceProvider? serviceProvider = null)
        : base(settingsProvider, probeService, serviceProvider)
    {
    }

    public override string Protocol => OutboundProtocols.LoadBalance;

    protected override ValueTask<string> SelectTagAsync(
        StrategyOutboundSettings settings,
        CancellationToken cancellationToken)
    {
        if (settings.CandidateTags.Count == 0)
        {
            return ValueTask.FromResult(string.Empty);
        }

        var next = _counters.AddOrUpdate(settings.Tag, 0, static (_, current) => unchecked(current + 1));
        var index = Math.Abs(next % settings.CandidateTags.Count);
        return ValueTask.FromResult(settings.CandidateTags[index]);
    }
}

public sealed class FallbackOutboundHandler : StrategyOutboundHandlerBase
{
    public FallbackOutboundHandler(
        IStrategyOutboundSettingsProvider settingsProvider,
        IStrategyOutboundProbeService probeService,
        IServiceProvider? serviceProvider = null)
        : base(settingsProvider, probeService, serviceProvider)
    {
    }

    public override string Protocol => OutboundProtocols.Fallback;

    protected override async ValueTask<string> SelectTagAsync(
        StrategyOutboundSettings settings,
        CancellationToken cancellationToken)
    {
        var results = await ProbeAsync(settings, cancellationToken).ConfigureAwait(false);
        if (!string.IsNullOrWhiteSpace(settings.SelectedTag))
        {
            var preferred = results.FirstOrDefault(result =>
                result.Success &&
                string.Equals(result.Tag, settings.SelectedTag, StringComparison.OrdinalIgnoreCase));
            if (preferred is not null)
            {
                return preferred.Tag;
            }
        }

        var firstHealthy = results.FirstOrDefault(static result => result.Success);
        return firstHealthy?.Tag
               ?? settings.CandidateTags.FirstOrDefault(static _ => true)
               ?? string.Empty;
    }
}

public sealed class UrlTestOutboundHandler : StrategyOutboundHandlerBase
{
    public UrlTestOutboundHandler(
        IStrategyOutboundSettingsProvider settingsProvider,
        IStrategyOutboundProbeService probeService,
        IServiceProvider? serviceProvider = null)
        : base(settingsProvider, probeService, serviceProvider)
    {
    }

    public override string Protocol => OutboundProtocols.UrlTest;

    protected override async ValueTask<string> SelectTagAsync(
        StrategyOutboundSettings settings,
        CancellationToken cancellationToken)
    {
        var results = await ProbeAsync(settings, cancellationToken).ConfigureAwait(false);
        var healthy = results
            .Where(static result => result.Success)
            .OrderBy(static result => result.LatencyMilliseconds)
            .ToArray();
        if (healthy.Length == 0)
        {
            return settings.SelectedTag.Length > 0
                ? settings.SelectedTag
                : settings.CandidateTags.FirstOrDefault(static _ => true) ?? string.Empty;
        }

        if (!string.IsNullOrWhiteSpace(settings.SelectedTag))
        {
            var preferred = healthy.FirstOrDefault(result =>
                string.Equals(result.Tag, settings.SelectedTag, StringComparison.OrdinalIgnoreCase));
            if (preferred is not null &&
                preferred.LatencyMilliseconds <= healthy[0].LatencyMilliseconds + settings.ToleranceMilliseconds)
            {
                return preferred.Tag;
            }
        }

        return healthy[0].Tag;
    }
}

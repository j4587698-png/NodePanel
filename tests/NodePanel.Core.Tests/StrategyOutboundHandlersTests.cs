using NodePanel.Core.Runtime;

namespace NodePanel.Core.Tests;

public sealed class StrategyOutboundHandlersTests
{
    [Fact]
    public async Task SelectorOutboundHandler_uses_selected_tag_when_present()
    {
        var dispatcher = new RecordingDispatcher();
        var handler = new SelectorOutboundHandler(
            new StaticStrategySettingsProvider(new StrategyOutboundSettings
            {
                Tag = "auto",
                Protocol = OutboundProtocols.Selector,
                CandidateTags = ["direct", "backup"],
                SelectedTag = "backup"
            }),
            new StaticProbeService([]),
            new DispatcherServiceProvider(dispatcher));

        await using var _ = await handler.OpenTcpAsync(
            new DispatchContext(),
            new DispatchDestination
            {
                Host = "example.com",
                Port = 443
            },
            CancellationToken.None);

        Assert.Equal("backup", Assert.Single(dispatcher.TcpContexts).OutboundTag);
    }

    [Fact]
    public async Task LoadBalanceOutboundHandler_rotates_candidate_tags()
    {
        var dispatcher = new RecordingDispatcher();
        var handler = new LoadBalanceOutboundHandler(
            new StaticStrategySettingsProvider(new StrategyOutboundSettings
            {
                Tag = "auto",
                Protocol = OutboundProtocols.LoadBalance,
                CandidateTags = ["direct", "backup"]
            }),
            new StaticProbeService([]),
            new DispatcherServiceProvider(dispatcher));

        for (var index = 0; index < 3; index++)
        {
            await using var _ = await handler.OpenTcpAsync(
                new DispatchContext(),
                new DispatchDestination
                {
                    Host = "example.com",
                    Port = 443
                },
                CancellationToken.None);
        }

        Assert.Equal(["direct", "backup", "direct"], dispatcher.TcpContexts.Select(static context => context.OutboundTag).ToArray());
    }

    [Fact]
    public async Task UrlTestOutboundHandler_prefers_selected_tag_within_tolerance()
    {
        var dispatcher = new RecordingDispatcher();
        var handler = new UrlTestOutboundHandler(
            new StaticStrategySettingsProvider(new StrategyOutboundSettings
            {
                Tag = "auto",
                Protocol = OutboundProtocols.UrlTest,
                CandidateTags = ["direct", "backup"],
                SelectedTag = "backup",
                ToleranceMilliseconds = 80
            }),
            new StaticProbeService(
            [
                new StrategyCandidateProbeResult
                {
                    Tag = "direct",
                    Success = true,
                    LatencyMilliseconds = 100
                },
                new StrategyCandidateProbeResult
                {
                    Tag = "backup",
                    Success = true,
                    LatencyMilliseconds = 160
                }
            ]),
            new DispatcherServiceProvider(dispatcher));

        await using var _ = await handler.OpenTcpAsync(
            new DispatchContext(),
            new DispatchDestination
            {
                Host = "example.com",
                Port = 443
            },
            CancellationToken.None);

        Assert.Equal("backup", Assert.Single(dispatcher.TcpContexts).OutboundTag);
    }

    [Fact]
    public async Task FallbackOutboundHandler_uses_first_healthy_tag_when_preferred_is_unhealthy()
    {
        var dispatcher = new RecordingDispatcher();
        var handler = new FallbackOutboundHandler(
            new StaticStrategySettingsProvider(new StrategyOutboundSettings
            {
                Tag = "auto",
                Protocol = OutboundProtocols.Fallback,
                CandidateTags = ["backup", "direct"],
                SelectedTag = "backup"
            }),
            new StaticProbeService(
            [
                new StrategyCandidateProbeResult
                {
                    Tag = "backup",
                    Success = false
                },
                new StrategyCandidateProbeResult
                {
                    Tag = "direct",
                    Success = true,
                    LatencyMilliseconds = 120
                }
            ]),
            new DispatcherServiceProvider(dispatcher));

        await using var _ = await handler.OpenTcpAsync(
            new DispatchContext(),
            new DispatchDestination
            {
                Host = "example.com",
                Port = 443
            },
            CancellationToken.None);

        Assert.Equal("direct", Assert.Single(dispatcher.TcpContexts).OutboundTag);
    }

    private sealed class StaticStrategySettingsProvider : IStrategyOutboundSettingsProvider
    {
        private readonly StrategyOutboundSettings _settings;

        public StaticStrategySettingsProvider(StrategyOutboundSettings settings)
        {
            _settings = settings;
        }

        public bool TryResolve(DispatchContext context, out StrategyOutboundSettings settings)
        {
            settings = _settings;
            return true;
        }
    }

    private sealed class StaticProbeService : IStrategyOutboundProbeService
    {
        private readonly IReadOnlyList<StrategyCandidateProbeResult> _results;

        public StaticProbeService(IReadOnlyList<StrategyCandidateProbeResult> results)
        {
            _results = results;
        }

        public ValueTask<IReadOnlyList<StrategyCandidateProbeResult>> ProbeAsync(
            StrategyOutboundSettings settings,
            CancellationToken cancellationToken)
            => ValueTask.FromResult(_results);
    }

    private sealed class DispatcherServiceProvider : IServiceProvider
    {
        private readonly IDispatcher _dispatcher;

        public DispatcherServiceProvider(IDispatcher dispatcher)
        {
            _dispatcher = dispatcher;
        }

        public object? GetService(Type serviceType)
            => serviceType == typeof(IDispatcher) ? _dispatcher : null;
    }

    private sealed class RecordingDispatcher : IDispatcher
    {
        public List<DispatchContext> TcpContexts { get; } = [];

        public ValueTask<Stream> DispatchTcpAsync(
            DispatchContext context,
            DispatchDestination destination,
            CancellationToken cancellationToken)
        {
            TcpContexts.Add(context);
            return ValueTask.FromResult<Stream>(new MemoryStream());
        }

        public ValueTask<IOutboundUdpTransport> DispatchUdpAsync(
            DispatchContext context,
            CancellationToken cancellationToken)
            => ValueTask.FromResult<IOutboundUdpTransport>(new NullOutboundUdpTransport());
    }

    private sealed class NullOutboundUdpTransport : IOutboundUdpTransport
    {
        public ValueTask SendAsync(
            DispatchDestination destination,
            ReadOnlyMemory<byte> payload,
            CancellationToken cancellationToken)
            => ValueTask.CompletedTask;

        public ValueTask<DispatchDatagram?> ReceiveAsync(CancellationToken cancellationToken)
            => ValueTask.FromResult<DispatchDatagram?>(null);

        public ValueTask DisposeAsync() => ValueTask.CompletedTask;
    }
}

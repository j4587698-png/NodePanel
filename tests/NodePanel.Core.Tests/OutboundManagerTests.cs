using NodePanel.Core.Runtime;

namespace NodePanel.Core.Tests;

public sealed class OutboundManagerTests
{
    [Fact]
    public void GetHandler_returns_registered_handler_for_custom_protocol_outbound()
    {
        var freedomHandler = new TestOutboundHandler(OutboundProtocols.Freedom);
        var chainHandler = new TestOutboundHandler("chain");
        var manager = new DefaultOutboundManager(
            [freedomHandler, chainHandler],
            new StaticOutboundRuntimePlanProvider(
                new OutboundRuntimePlan
                {
                    Outbounds =
                    [
                        new OutboundRuntime
                        {
                            Tag = "direct",
                            Protocol = OutboundProtocols.Freedom
                        },
                        new OutboundRuntime
                        {
                            Tag = "chain-proxy",
                            Protocol = "chain"
                        }
                    ],
                    DefaultOutboundTag = "direct"
                }));

        var handler = manager.GetHandler("chain-proxy");

        Assert.Same(chainHandler, handler);
    }

    [Fact]
    public void GetDefaultHandler_falls_back_to_freedom_when_default_protocol_handler_is_missing()
    {
        var freedomHandler = new TestOutboundHandler(OutboundProtocols.Freedom);
        var manager = new DefaultOutboundManager(
            [freedomHandler],
            new StaticOutboundRuntimePlanProvider(
                new OutboundRuntimePlan
                {
                    Outbounds =
                    [
                        new OutboundRuntime
                        {
                            Tag = "mystery",
                            Protocol = "mystery"
                        }
                    ],
                    DefaultOutboundTag = "mystery"
                }));

        var handler = manager.GetDefaultHandler();

        Assert.Same(freedomHandler, handler);
    }

    [Fact]
    public void RemoveHandler_removes_registered_protocol_handler()
    {
        var freedomHandler = new TestOutboundHandler(OutboundProtocols.Freedom);
        var chainHandler = new TestOutboundHandler("chain");
        var manager = new DefaultOutboundManager(
            [freedomHandler, chainHandler],
            new StaticOutboundRuntimePlanProvider(
                new OutboundRuntimePlan
                {
                    Outbounds =
                    [
                        new OutboundRuntime
                        {
                            Tag = "chain-proxy",
                            Protocol = "chain"
                        }
                    ],
                    DefaultOutboundTag = "chain-proxy"
                }));

        var removed = manager.RemoveHandler("chain");

        Assert.True(removed);
        Assert.Null(manager.GetHandler("chain-proxy"));
        Assert.Single(manager.ListHandlers());
    }

    [Fact]
    public async Task Start_starts_registered_handlers_and_new_handlers_when_manager_is_running()
    {
        await using var manager = new DefaultOutboundManager(CreatePlanProvider(("direct", OutboundProtocols.Freedom)));
        var freedomHandler = new TestOutboundHandler(OutboundProtocols.Freedom);
        var chainHandler = new TestOutboundHandler("chain");
        manager.AddHandler(freedomHandler);

        ((IRuntimeStartable)manager).Start();
        manager.AddHandler(chainHandler);

        Assert.Equal(1, freedomHandler.StartCallCount);
        Assert.Equal(1, chainHandler.StartCallCount);
    }

    [Fact]
    public void GetHandler_returns_tag_specific_handler_when_same_protocol_is_registered_multiple_times()
    {
        var manager = new DefaultOutboundManager(
            CreatePlanProvider(
                ("primary", OutboundProtocols.Freedom),
                ("backup", OutboundProtocols.Freedom)));
        var primaryHandler = new TestOutboundHandler(OutboundProtocols.Freedom);
        var backupHandler = new TestOutboundHandler(OutboundProtocols.Freedom);

        manager.AddHandler("primary", primaryHandler);
        manager.AddHandler("backup", backupHandler);

        Assert.Same(primaryHandler, manager.GetHandler("primary"));
        Assert.Same(backupHandler, manager.GetHandler("backup"));
        Assert.Same(primaryHandler, manager.GetDefaultHandler());
    }

    [Fact]
    public async Task DisposeAsync_disposes_registered_async_handlers_once()
    {
        var freedomHandler = new TestOutboundHandler(OutboundProtocols.Freedom);
        var chainHandler = new TestOutboundHandler("chain");
        var manager = new DefaultOutboundManager(
            [freedomHandler, chainHandler],
            CreatePlanProvider(
                ("direct", OutboundProtocols.Freedom),
                ("chain-proxy", "chain")));

        await manager.DisposeAsync();
        await manager.DisposeAsync();

        Assert.Equal(1, freedomHandler.DisposeCallCount);
        Assert.Equal(1, chainHandler.DisposeCallCount);
    }

    [Fact]
    public async Task Start_and_Dispose_deduplicate_shared_handler_registered_under_multiple_tags()
    {
        var manager = new DefaultOutboundManager(
            CreatePlanProvider(
                ("first", OutboundProtocols.Freedom),
                ("second", OutboundProtocols.Freedom)));
        var sharedHandler = new TestOutboundHandler(OutboundProtocols.Freedom);

        manager.AddHandler("first", sharedHandler);
        manager.AddHandler("second", sharedHandler);

        ((IRuntimeStartable)manager).Start();
        await manager.DisposeAsync();

        Assert.Equal(1, sharedHandler.StartCallCount);
        Assert.Equal(1, sharedHandler.DisposeCallCount);
    }

    [Fact]
    public void TryBuild_rejects_unknown_outbound_protocol_when_not_supported()
    {
        var success = OutboundRuntimePlanner.TryBuild(
            [
                new TestOutboundDefinition("mystery", true, "mystery")
            ],
            Array.Empty<IRoutingRuleDefinition>(),
            [OutboundProtocols.Freedom],
            out _,
            out var error);

        Assert.False(success);
        Assert.Equal("Unsupported outbound protocol: mystery.", error);
    }

    private static StaticOutboundRuntimePlanProvider CreatePlanProvider(params (string Tag, string Protocol)[] outbounds)
        => new(
            new OutboundRuntimePlan
            {
                Outbounds = outbounds
                    .Select(outbound => new OutboundRuntime
                    {
                        Tag = outbound.Tag,
                        Protocol = outbound.Protocol
                    })
                    .ToArray(),
                DefaultOutboundTag = outbounds.Length > 0 ? outbounds[0].Tag : string.Empty
            });

    private sealed class StaticOutboundRuntimePlanProvider : IOutboundRuntimePlanProvider
    {
        private readonly OutboundRuntimePlan _plan;

        public StaticOutboundRuntimePlanProvider(OutboundRuntimePlan plan)
        {
            _plan = plan;
        }

        public OutboundRuntimePlan GetCurrentOutboundPlan() => _plan;
    }

    private sealed class TestOutboundDefinition : IOutboundDefinition
    {
        public TestOutboundDefinition(string tag, bool enabled, string protocol)
        {
            Tag = tag;
            Enabled = enabled;
            Protocol = protocol;
        }

        public string Tag { get; }

        public bool Enabled { get; }

        public string Protocol { get; }
    }

    private sealed class TestOutboundHandler : IOutboundHandler, IRuntimeStartable, IAsyncDisposable
    {
        public TestOutboundHandler(string protocol)
        {
            Protocol = protocol;
        }

        public string Protocol { get; }

        public int StartCallCount { get; private set; }

        public int DisposeCallCount { get; private set; }

        public void Start()
        {
            StartCallCount++;
        }

        public ValueTask<Stream> OpenTcpAsync(
            DispatchContext context,
            DispatchDestination destination,
            CancellationToken cancellationToken)
            => ValueTask.FromResult<Stream>(Stream.Null);

        public ValueTask<IOutboundUdpTransport> OpenUdpAsync(
            DispatchContext context,
            CancellationToken cancellationToken)
            => ValueTask.FromResult<IOutboundUdpTransport>(new NullOutboundUdpTransport());

        public ValueTask DisposeAsync()
        {
            DisposeCallCount++;
            return ValueTask.CompletedTask;
        }
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

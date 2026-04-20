using System.Net;
using NodePanel.Core.Runtime;

namespace NodePanel.Core.Tests;

public sealed class LoopbackOutboundHandlerTests
{
    [Fact]
    public async Task OpenTcpAsync_redispatches_with_overridden_inbound_tag_and_skip_dns()
    {
        using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(10));
        var dispatcher = new RecordingDispatcher();
        var serviceProvider = new StaticServiceProvider(dispatcher);
        var handler = new LoopbackOutboundHandler(
            new StaticRuntimeSettingsProvider(
                new RuntimeLoopbackOutboundOptions
                {
                    Tag = "loop",
                    InboundTag = "internal"
                }),
            serviceProvider);

        var context = new DispatchContext
        {
            InboundProtocol = ProxyInboundProtocols.Socks,
            InboundTag = "edge",
            OutboundTag = "loop",
            Content = new DispatchContent
            {
                Protocol = "http/1.1"
            }
        };
        var destination = new DispatchDestination
        {
            Host = "example.org",
            Port = 443,
            Network = DispatchNetwork.Tcp
        };

        var stream = await handler.OpenTcpAsync(context, destination, cts.Token);

        Assert.Same(dispatcher.TcpStream, stream);
        Assert.NotNull(dispatcher.LastTcpContext);
        Assert.Equal("internal", dispatcher.LastTcpContext!.InboundTag);
        Assert.True(dispatcher.LastTcpContext.Content.SkipDnsResolve);
        Assert.Equal("http/1.1", dispatcher.LastTcpContext.Content.Protocol);
        Assert.Equal(destination, dispatcher.LastTcpDestination);
    }

    [Fact]
    public async Task OpenUdpAsync_redispatches_with_overridden_inbound_tag_and_skip_dns()
    {
        using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(10));
        var dispatcher = new RecordingDispatcher();
        var serviceProvider = new StaticServiceProvider(dispatcher);
        var handler = new LoopbackOutboundHandler(
            new StaticRuntimeSettingsProvider(
                new RuntimeLoopbackOutboundOptions
                {
                    Tag = "loop",
                    InboundTag = "internal"
                }),
            serviceProvider);

        var context = new DispatchContext
        {
            InboundProtocol = ProxyInboundProtocols.Socks,
            InboundTag = "edge",
            OutboundTag = "loop"
        };

        var transport = await handler.OpenUdpAsync(context, cts.Token);

        Assert.Same(dispatcher.UdpTransport, transport);
        Assert.NotNull(dispatcher.LastUdpContext);
        Assert.Equal("internal", dispatcher.LastUdpContext!.InboundTag);
        Assert.True(dispatcher.LastUdpContext.Content.SkipDnsResolve);
    }

    [Fact]
    public async Task ResolveAsync_skips_dns_target_strategy_when_flag_is_set()
    {
        var destination = new DispatchDestination
        {
            Host = "example.org",
            Port = 443,
            Network = DispatchNetwork.Tcp
        };

        var resolved = await OutboundTargetStrategyResolver.ResolveAsync(
            new DispatchContext
            {
                Content = new DispatchContent
                {
                    SkipDnsResolve = true
                }
            },
            destination,
            OutboundTargetStrategies.ForceIp,
            new ThrowingDnsResolver(),
            CancellationToken.None);

        Assert.Equal(destination, resolved);
    }

    private sealed class RecordingDispatcher : IDispatcher
    {
        public Stream TcpStream { get; } = Stream.Null;

        public IOutboundUdpTransport UdpTransport { get; } = new NullOutboundUdpTransport();

        public DispatchContext? LastTcpContext { get; private set; }

        public DispatchDestination? LastTcpDestination { get; private set; }

        public DispatchContext? LastUdpContext { get; private set; }

        public ValueTask<Stream> DispatchTcpAsync(
            DispatchContext context,
            DispatchDestination destination,
            CancellationToken cancellationToken)
        {
            LastTcpContext = context;
            LastTcpDestination = destination;
            return ValueTask.FromResult(TcpStream);
        }

        public ValueTask<IOutboundUdpTransport> DispatchUdpAsync(
            DispatchContext context,
            CancellationToken cancellationToken)
        {
            LastUdpContext = context;
            return ValueTask.FromResult(UdpTransport);
        }
    }

    private sealed class StaticServiceProvider : IServiceProvider
    {
        private readonly IDispatcher _dispatcher;

        public StaticServiceProvider(IDispatcher dispatcher)
        {
            _dispatcher = dispatcher;
        }

        public object? GetService(Type serviceType)
            => serviceType == typeof(IDispatcher) ? _dispatcher : null;
    }

    private sealed class StaticRuntimeSettingsProvider : IRuntimeOutboundSettingsProvider
    {
        private readonly IRuntimeOutboundOptions _settings;

        public StaticRuntimeSettingsProvider(IRuntimeOutboundOptions settings)
        {
            _settings = settings;
        }

        public bool TryResolve(DispatchContext context, out IRuntimeOutboundOptions settings)
        {
            settings = _settings;
            return true;
        }

        public bool TryResolve<TOptions>(DispatchContext context, out TOptions settings)
            where TOptions : class, IRuntimeOutboundOptions
        {
            if (_settings is TOptions typed)
            {
                settings = typed;
                return true;
            }

            settings = default!;
            return false;
        }
    }

    private sealed class ThrowingDnsResolver : IDnsResolver
    {
        public ValueTask<IReadOnlyList<IPAddress>> ResolveAsync(string host, CancellationToken cancellationToken = default)
            => throw new InvalidOperationException("DNS resolution should have been skipped.");
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

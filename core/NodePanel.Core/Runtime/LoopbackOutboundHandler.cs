namespace NodePanel.Core.Runtime;

public sealed class LoopbackOutboundHandler : IOutboundHandler
{
    private readonly IRuntimeOutboundSettingsProvider _runtimeSettingsProvider;
    private readonly IServiceProvider? _serviceProvider;

    public LoopbackOutboundHandler(
        IRuntimeOutboundSettingsProvider runtimeSettingsProvider,
        IServiceProvider? serviceProvider = null)
    {
        _runtimeSettingsProvider = runtimeSettingsProvider ?? throw new ArgumentNullException(nameof(runtimeSettingsProvider));
        _serviceProvider = serviceProvider;
    }

    public string Protocol => OutboundProtocols.Loopback;

    public ValueTask<Stream> OpenTcpAsync(
        DispatchContext context,
        DispatchDestination destination,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(destination);
        if (destination.Network != DispatchNetwork.Tcp)
        {
            throw new NotSupportedException($"Loopback outbound does not support TCP open for network '{destination.Network}'.");
        }

        var settings = ResolveSettings(context);
        return ResolveDispatcher().DispatchTcpAsync(
            CreateLoopbackContext(context, settings),
            destination,
            cancellationToken);
    }

    public ValueTask<IOutboundUdpTransport> OpenUdpAsync(
        DispatchContext context,
        CancellationToken cancellationToken)
    {
        var settings = ResolveSettings(context);
        return ResolveDispatcher().DispatchUdpAsync(
            CreateLoopbackContext(context, settings),
            cancellationToken);
    }

    private RuntimeLoopbackOutboundOptions ResolveSettings(DispatchContext context)
    {
        if (!_runtimeSettingsProvider.TryResolve(context, out RuntimeLoopbackOutboundOptions runtimeSettings) ||
            !string.Equals(runtimeSettings.Protocol, OutboundProtocols.Loopback, StringComparison.Ordinal))
        {
            throw new InvalidOperationException("Loopback outbound settings could not be resolved for the current dispatch context.");
        }

        return runtimeSettings;
    }

    private IDispatcher ResolveDispatcher()
        => _serviceProvider?.GetService(typeof(IDispatcher)) as IDispatcher
           ?? throw new InvalidOperationException("Loopback outbound requires an active dispatcher.");

    private static DispatchContext CreateLoopbackContext(
        DispatchContext context,
        RuntimeLoopbackOutboundOptions settings)
        => context with
        {
            InboundTag = settings.InboundTag,
            Content = DispatchDnsResolution.EnableSkipDnsResolve(context.Content)
        };
}

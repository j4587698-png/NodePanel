namespace NodePanel.Core.Runtime;

public sealed class Shadowsocks2022OutboundHandler : IOutboundHandler
{
    private readonly Shadowsocks2022OutboundClient _client;
    private readonly IShadowsocks2022OutboundSettingsProvider? _legacySettingsProvider;
    private readonly IOutboundRuntimePlanProvider? _planProvider;
    private readonly IRuntimeOutboundSettingsProvider? _runtimeSettingsProvider;

    public Shadowsocks2022OutboundHandler(
        Shadowsocks2022OutboundClient client,
        IRuntimeOutboundSettingsProvider settingsProvider,
        IOutboundRuntimePlanProvider planProvider)
    {
        _client = client ?? throw new ArgumentNullException(nameof(client));
        _runtimeSettingsProvider = settingsProvider ?? throw new ArgumentNullException(nameof(settingsProvider));
        _planProvider = planProvider ?? throw new ArgumentNullException(nameof(planProvider));
    }

    public Shadowsocks2022OutboundHandler(
        Shadowsocks2022OutboundClient client,
        IShadowsocks2022OutboundSettingsProvider settingsProvider)
    {
        _client = client ?? throw new ArgumentNullException(nameof(client));
        _legacySettingsProvider = settingsProvider ?? throw new ArgumentNullException(nameof(settingsProvider));
    }

    public string Protocol => OutboundProtocols.Shadowsocks;

    public ValueTask<Stream> OpenTcpAsync(
        DispatchContext context,
        DispatchDestination destination,
        CancellationToken cancellationToken)
        => _client.OpenTcpAsync(ResolveSettings(context), context, destination, cancellationToken);

    public ValueTask<IOutboundUdpTransport> OpenUdpAsync(
        DispatchContext context,
        CancellationToken cancellationToken)
        => _client.OpenUdpAsync(ResolveSettings(context), context, cancellationToken);

    internal Shadowsocks2022OutboundSettings ResolveSettings(DispatchContext context)
    {
        if (_legacySettingsProvider is not null &&
            _legacySettingsProvider.TryResolve(context, out var legacySettings))
        {
            return legacySettings;
        }

        if (_runtimeSettingsProvider is not null &&
            _planProvider is not null &&
            RuntimeOutboundSettingsResolver.TryResolveShadowsocks2022(
                _planProvider,
                _runtimeSettingsProvider,
                context,
                out var settings))
        {
            return settings;
        }

        throw new InvalidOperationException("Shadowsocks 2022 outbound settings could not be resolved for the current dispatch context.");
    }
}

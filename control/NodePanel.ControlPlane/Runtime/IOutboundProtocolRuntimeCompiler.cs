using NodePanel.ControlPlane.Configuration;
using NodePanel.Core.Runtime;

namespace NodePanel.ControlPlane.Runtime;

public interface IOutboundProtocolRuntimeCompiler
{
    IReadOnlyList<string> SupportedProtocols { get; }

    NodeServiceConfig Normalize(NodeServiceConfig config);

    bool TryValidate(NodeServiceConfig config, out string? error);

    IReadOnlyList<IRuntimeOutboundOptions> BuildRuntimeOptions(NodeServiceConfig config);
}

public abstract class OutboundProtocolRuntimeCompilerBase : IOutboundProtocolRuntimeCompiler
{
    private readonly HashSet<string> _supportedProtocols;

    protected OutboundProtocolRuntimeCompilerBase(params string[] supportedProtocols)
    {
        ArgumentNullException.ThrowIfNull(supportedProtocols);

        var normalizedProtocols = supportedProtocols
            .Where(static protocol => !string.IsNullOrWhiteSpace(protocol))
            .Select(OutboundProtocols.Normalize)
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .ToArray();

        if (normalizedProtocols.Length == 0)
        {
            throw new InvalidOperationException("Outbound protocol compiler must declare at least one supported protocol.");
        }

        SupportedProtocols = normalizedProtocols;
        _supportedProtocols = new HashSet<string>(normalizedProtocols, StringComparer.OrdinalIgnoreCase);
    }

    public IReadOnlyList<string> SupportedProtocols { get; }

    public virtual NodeServiceConfig Normalize(NodeServiceConfig config)
    {
        ArgumentNullException.ThrowIfNull(config);
        return config;
    }

    public abstract bool TryValidate(NodeServiceConfig config, out string? error);

    public virtual IReadOnlyList<IRuntimeOutboundOptions> BuildRuntimeOptions(NodeServiceConfig config)
    {
        ArgumentNullException.ThrowIfNull(config);
        return Array.Empty<IRuntimeOutboundOptions>();
    }

    protected IReadOnlyList<OutboundConfig> GetSupportedOutbounds(NodeServiceConfig config)
    {
        ArgumentNullException.ThrowIfNull(config);
        return config.Outbounds
            .Where(outbound => outbound.Enabled && Supports(outbound.Protocol))
            .ToArray();
    }

    protected bool Supports(string? protocol)
        => _supportedProtocols.Contains(OutboundProtocols.Normalize(protocol));
}

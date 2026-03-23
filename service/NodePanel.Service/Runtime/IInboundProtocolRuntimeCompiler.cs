using NodePanel.ControlPlane.Configuration;
using NodePanel.Core.Runtime;

namespace NodePanel.Service.Runtime;

public interface IInboundProtocolRuntimeCompiler
{
    string Protocol { get; }

    NodeServiceConfig Normalize(NodeServiceConfig config);

    bool TryCompile(
        NodeServiceConfig config,
        out InboundProtocolRuntimeCompilation compilation,
        out string? error);
}

public sealed record InboundProtocolRuntimeCompilation
{
    public required IInboundProtocolRuntimePlan Plan { get; init; }

    public IReadOnlyList<IRuntimeUserDefinition> ActiveUsers { get; init; } = Array.Empty<IRuntimeUserDefinition>();

    public bool RequiresCertificate => Plan.RequiresCertificate;
}

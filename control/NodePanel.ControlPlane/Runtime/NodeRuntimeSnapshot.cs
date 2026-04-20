using NodePanel.ControlPlane.Configuration;
using NodePanel.Core.Runtime;
using System.Security.Cryptography.X509Certificates;

namespace NodePanel.ControlPlane.Runtime;

public sealed record NodeRuntimeSnapshot
{
    public static NodeRuntimeSnapshot Empty { get; } = new();

    public int Revision { get; init; }

    public NodeServiceConfig Config { get; init; } = new();

    public NodeRuntimePlan Plan { get; init; } = NodeRuntimePlan.Empty;

    public RuntimeTransportLimits TransportLimits { get; init; } = new();

    public RuntimeSessionPolicyCatalog SessionPolicies { get; init; } = RuntimeSessionPolicyCatalog.Default;

    public DnsRuntimeSettings Dns { get; init; } = DnsRuntimeSettings.Default;

    public ProxyInboundRuntimePlan ProxyInbounds { get; init; } = ProxyInboundRuntimePlan.Empty;

    public RuntimeOutboundSettingsCatalog OutboundSettings { get; init; } = RuntimeOutboundSettingsCatalog.Empty;

    public IReadOnlyList<IRuntimeUserDefinition> ActiveUsers { get; init; } = Array.Empty<IRuntimeUserDefinition>();

    public InboundRuntimePlanCollection InboundPlans => Plan.Inbounds;

    public bool RequiresCertificate => Plan.Inbounds.RequiresCertificate;

    public TrojanInboundRuntimePlan TrojanPlan => Plan.Trojan;

    public OutboundRuntimePlan OutboundPlan => Plan.Outbound;

    public bool TryGetInboundPlan<TPlan>(string protocol, out TPlan plan)
        where TPlan : class, IInboundProtocolRuntimePlan
        => Plan.TryGetInboundPlan(protocol, out plan);

    public TPlan GetInboundPlanOrDefault<TPlan>(string protocol, TPlan fallback)
        where TPlan : class, IInboundProtocolRuntimePlan
        => InboundPlans.GetOrDefault(protocol, fallback);

    public RuntimePlan CreateRuntimePlan(RuntimeTlsOptions? tls = null, bool useCone = true)
        => new()
        {
            Revision = Revision,
            Plan = Plan,
            TransportLimits = TransportLimits,
            SessionPolicies = SessionPolicies,
            Dns = Dns,
            Tls = tls,
            UseCone = useCone,
            ProxyInbounds = ProxyInbounds,
            OutboundSettings = OutboundSettings,
            ActiveUsers = ActiveUsers.ToArray()
        };

    public RuntimePlan CreateRuntimePlan(X509Certificate2? certificate, bool useCone = true)
        => CreateRuntimePlan(CreateTlsOptions(certificate), useCone);

    private RuntimeTlsOptions? CreateTlsOptions(X509Certificate2? certificate)
    {
        if (certificate is null)
        {
            return null;
        }

        return new RuntimeTlsOptions
        {
            Certificate = certificate,
            ServerNamePolicy = new RuntimeTlsServerNamePolicyOptions
            {
                RejectUnknownServerName = Config.Certificate.RejectUnknownSni,
                ConfiguredServerNames = [.. new[] { Config.Certificate.Domain }.Concat(Config.Certificate.AltNames)]
            },
            ClientHelloPolicy = new RuntimeTlsClientHelloPolicyOptions
            {
                Enabled = Config.Certificate.ClientHelloPolicy.Enabled,
                AllowedServerNames = Config.Certificate.ClientHelloPolicy.AllowedServerNames,
                BlockedServerNames = Config.Certificate.ClientHelloPolicy.BlockedServerNames,
                AllowedApplicationProtocols = Config.Certificate.ClientHelloPolicy.AllowedApplicationProtocols,
                BlockedApplicationProtocols = Config.Certificate.ClientHelloPolicy.BlockedApplicationProtocols,
                AllowedJa3 = Config.Certificate.ClientHelloPolicy.AllowedJa3,
                BlockedJa3 = Config.Certificate.ClientHelloPolicy.BlockedJa3
            }
        };
    }
}

using System.Text.Json.Serialization;
using NodePanel.ControlPlane.Configuration;

namespace NodePanel.Service.Runtime;

[JsonSourceGenerationOptions(
    PropertyNamingPolicy = JsonKnownNamingPolicy.CamelCase,
    DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull,
    WriteIndented = false)]
[JsonSerializable(typeof(PersistedNodeConfigDocument))]
[JsonSerializable(typeof(NodeServiceConfig))]
[JsonSerializable(typeof(InboundConfig))]
[JsonSerializable(typeof(InboundSniffingConfig))]
[JsonSerializable(typeof(LocalInboundConfig))]
[JsonSerializable(typeof(OutboundConfig))]
[JsonSerializable(typeof(OutboundMultiplexConfig))]
[JsonSerializable(typeof(RoutingRuleConfig))]
[JsonSerializable(typeof(CertificateOptions))]
[JsonSerializable(typeof(TlsClientHelloPolicyConfig))]
[JsonSerializable(typeof(CertificateEnvironmentVariable))]
[JsonSerializable(typeof(DnsOptions))]
[JsonSerializable(typeof(DnsHttpServerConfig))]
[JsonSerializable(typeof(TelemetryOptions))]
[JsonSerializable(typeof(TrojanInboundLimits))]
[JsonSerializable(typeof(TrojanUserConfig))]
[JsonSerializable(typeof(TrojanFallbackConfig))]
[JsonSerializable(typeof(DistributedCertificateAsset))]
public partial class ServiceRuntimeJsonSerializerContext : JsonSerializerContext
{
}

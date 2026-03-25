using System.Text.Json.Serialization;
using NodePanel.ControlPlane.Configuration;

namespace NodePanel.ControlPlane.Protocol;

[JsonSourceGenerationOptions(
    PropertyNamingPolicy = JsonKnownNamingPolicy.CamelCase,
    DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull,
    WriteIndented = false)]
[JsonSerializable(typeof(ControlPlaneEnvelope))]
[JsonSerializable(typeof(ApplySnapshotPayload))]
[JsonSerializable(typeof(ApplyPatchPayload))]
[JsonSerializable(typeof(ApplyResultPayload))]
[JsonSerializable(typeof(CertificateRenewPayload))]
[JsonSerializable(typeof(NodeHelloPayload))]
[JsonSerializable(typeof(HeartbeatPayload))]
[JsonSerializable(typeof(TelemetryBatchPayload))]
[JsonSerializable(typeof(NodeStatusPayload))]
[JsonSerializable(typeof(NodeInboundStatusPayload))]
[JsonSerializable(typeof(CertificateStatusPayload))]
[JsonSerializable(typeof(UserTrafficDelta))]
[JsonSerializable(typeof(HealthPayload))]
[JsonSerializable(typeof(NodeServiceConfig))]
[JsonSerializable(typeof(InboundConfig))]
[JsonSerializable(typeof(InboundSniffingConfig))]
[JsonSerializable(typeof(LocalInboundConfig))]
[JsonSerializable(typeof(OutboundConfig))]
[JsonSerializable(typeof(OutboundMultiplexConfig))]
[JsonSerializable(typeof(RoutingRuleConfig))]
[JsonSerializable(typeof(CertificateOptions))]
[JsonSerializable(typeof(DistributedCertificateAsset))]
[JsonSerializable(typeof(TlsClientHelloPolicyConfig))]
[JsonSerializable(typeof(CertificateEnvironmentVariable))]
[JsonSerializable(typeof(DnsOptions))]
[JsonSerializable(typeof(DnsHttpServerConfig))]
[JsonSerializable(typeof(TelemetryOptions))]
[JsonSerializable(typeof(TrojanInboundLimits))]
[JsonSerializable(typeof(TrojanUserConfig))]
[JsonSerializable(typeof(TrojanFallbackConfig))]
[JsonSerializable(typeof(Dictionary<string, string>))]
[JsonSerializable(typeof(List<string>))]
[JsonSerializable(typeof(List<UserTrafficDelta>))]
public partial class ControlPlaneJsonSerializerContext : JsonSerializerContext
{
}

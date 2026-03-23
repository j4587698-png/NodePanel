using System.Text.Json;
using NodePanel.ControlPlane.Configuration;

namespace NodePanel.ControlPlane.Protocol;

public static class ControlMessageTypes
{
    public const string ApplyPatch = "apply.patch";
    public const string ApplyResult = "apply.result";
    public const string ApplySnapshot = "apply.snapshot";
    public const string CertificateRenew = "certificate.renew";
    public const string Heartbeat = "heartbeat";
    public const string NodeHello = "node.hello";
    public const string TelemetryBatch = "telemetry.batch";
}

public sealed record ControlPlaneEnvelope
{
    public required string Type { get; init; }

    public string? NodeId { get; init; }

    public int Revision { get; init; }

    public JsonElement Payload { get; init; }
}

public sealed record ApplySnapshotPayload
{
    public required NodeServiceConfig Config { get; init; }
}

public sealed record ApplyPatchPayload
{
    public JsonElement Operations { get; init; }
}

public sealed record ApplyResultPayload
{
    public required int RequestedRevision { get; init; }

    public required bool Success { get; init; }

    public string? Error { get; init; }
}

public sealed record CertificateRenewPayload
{
    public required DateTimeOffset RequestedAt { get; init; }

    public string? RequestedBy { get; init; }
}

public sealed record NodeHelloPayload
{
    public required string NodeId { get; init; }

    public required string Version { get; init; }

    public required IReadOnlyList<string> Capabilities { get; init; }

    public required int AppliedRevision { get; init; }
}

public sealed record HeartbeatPayload
{
    public required DateTimeOffset Timestamp { get; init; }
}

public sealed record TelemetryBatchPayload
{
    public required string NodeId { get; init; }

    public required int AppliedRevision { get; init; }

    public required IReadOnlyList<UserTrafficDelta> Traffic { get; init; }

    public required NodeStatusPayload Status { get; init; }
}

public sealed record UserTrafficDelta
{
    public required string UserId { get; init; }

    public required long UploadBytes { get; init; }

    public required long DownloadBytes { get; init; }
}

public sealed record NodeInboundStatusPayload
{
    public required string Tag { get; init; }

    public required string Protocol { get; init; }

    public required string Transport { get; init; }

    public required string ListenAddress { get; init; }

    public required int Port { get; init; }

    public required bool ReceiveOriginalDestination { get; init; }
}

public sealed record NodeStatusPayload
{
    public required DateTimeOffset Timestamp { get; init; }

    public required int ActiveSessions { get; init; }

    public required int KnownUsers { get; init; }

    public required IReadOnlyList<NodeInboundStatusPayload> Inbounds { get; init; }

    public required CertificateStatusPayload Certificate { get; init; }
}

public sealed record CertificateStatusPayload
{
    public required string Mode { get; init; }

    public required bool Available { get; init; }

    public string? SourcePath { get; init; }

    public string? Domain { get; init; }

    public string? Thumbprint { get; init; }

    public DateTimeOffset? NotBefore { get; init; }

    public DateTimeOffset? NotAfter { get; init; }

    public DateTimeOffset? LastAttemptAt { get; init; }

    public DateTimeOffset? LastSuccessAt { get; init; }

    public string? Error { get; init; }
}

public sealed record HealthPayload
{
    public required string NodeId { get; init; }

    public required int AppliedRevision { get; init; }

    public required int ActiveSessions { get; init; }
}

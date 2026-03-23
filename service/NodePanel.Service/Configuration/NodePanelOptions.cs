using NodePanel.ControlPlane.Configuration;

namespace NodePanel.Service.Configuration;

public sealed class NodePanelOptions
{
    public const string SectionName = "NodePanel";

    public string PanelUrl { get; init; } = string.Empty;

    public string CachedConfigPath { get; init; } = "node-runtime-config.json";

    public NodeIdentityOptions Identity { get; init; } = new();

    public ControlPlaneOptions ControlPlane { get; init; } = new();

    public NodeServiceConfig Bootstrap { get; init; } = new();
}

public sealed class NodeIdentityOptions
{
    public string NodeId { get; init; } = string.Empty;
}

public sealed class ControlPlaneOptions
{
    public bool Enabled { get; init; } = true;

    public string Url { get; init; } = string.Empty;

    public string AccessToken { get; init; } = string.Empty;

    public int ConnectTimeoutSeconds { get; init; } = 10;

    public int HeartbeatIntervalSeconds { get; init; } = 15;

    public int ReconnectDelaySeconds { get; init; } = 5;
}

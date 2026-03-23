namespace NodePanel.Panel.Configuration;

public sealed class PanelOptions
{
    public const string SectionName = "Panel";

    public string AppName { get; init; } = "NodePanel";

    public string DataFilePath { get; init; } = "panel-state.json";

    public bool AutoRegisterUnknownNodes { get; init; } = true;

    public string DbType { get; set; } = string.Empty; // "sqlite" or "mysql"

    public string DbConnectionString { get; set; } = string.Empty;

    public string AdminToken { get; init; } = string.Empty;

    public string PublicBaseUrl { get; init; } = string.Empty;

    public string[] SubscribeUrls { get; init; } = Array.Empty<string>();

    public bool AutoRestartOnHttpsChange { get; init; }
}

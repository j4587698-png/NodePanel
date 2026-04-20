namespace NodePanel.Core.Runtime;

public interface IRuntimeSniffingDefinition
{
    bool Enabled { get; }

    IReadOnlyList<string> DestinationOverride { get; }

    IReadOnlyList<string> DomainsExcluded { get; }

    bool MetadataOnly { get; }

    bool RouteOnly { get; }
}

public sealed record RuntimeSniffingOptions : IRuntimeSniffingDefinition
{
    public static IRuntimeSniffingDefinition Disabled { get; } = new RuntimeSniffingOptions();

    public bool Enabled { get; init; }

    public IReadOnlyList<string> DestinationOverride { get; init; } = Array.Empty<string>();

    public IReadOnlyList<string> DomainsExcluded { get; init; } = Array.Empty<string>();

    public bool MetadataOnly { get; init; }

    public bool RouteOnly { get; init; }
}

public sealed record RuntimeSniffingDecision
{
    public string Protocol { get; init; } = string.Empty;

    public string Domain { get; init; } = string.Empty;

    public DispatchContent Content { get; init; } = DispatchContent.Empty;

    public bool OverrideMatched { get; init; }

    public bool RouteOnly { get; init; }

    public DispatchDestination? OverrideDestination { get; init; }

    public DispatchDestination? RouteTarget { get; init; }
}

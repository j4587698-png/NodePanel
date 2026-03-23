namespace NodePanel.Panel.Models;

public sealed record SubscriptionCatalog
{
    public required PanelUserRecord User { get; init; }

    public required IReadOnlyList<PanelNodeRecord> AssignedNodes { get; init; }

    public required IReadOnlyList<SubscriptionEndpoint> Endpoints { get; init; }
}

public sealed record SubscriptionEndpoint
{
    public required string NodeId { get; init; }

    public required string DisplayName { get; init; }

    public required string Host { get; init; }

    public required int Port { get; init; }

    public required string Sni { get; init; }

    public required string Label { get; init; }

    public string Protocol { get; init; } = "trojan";

    public string Transport { get; init; } = "tcp";

    public string Path { get; init; } = string.Empty;

    public string WsHost { get; init; } = string.Empty;

    public bool SkipCertificateVerification { get; init; }
}

public sealed record RenderedSubscription
{
    public required string Format { get; init; }

    public required string Content { get; init; }

    public string ContentType { get; init; } = "text/plain";

    public string FileName { get; init; } = string.Empty;

    public IReadOnlyDictionary<string, string> Headers { get; init; } = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
}

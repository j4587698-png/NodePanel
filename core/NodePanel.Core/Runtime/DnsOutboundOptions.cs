namespace NodePanel.Core.Runtime;

public sealed record RuntimeDnsOutboundOptions : IRuntimeOutboundOptions
{
    public required string Tag { get; init; }

    public string Protocol => OutboundProtocols.Dns;

    public string ServerNetwork { get; init; } = string.Empty;

    public string ServerHost { get; init; } = string.Empty;

    public int ServerPort { get; init; }

    public string NonIpQuery { get; init; } = DnsOutboundNonIpQueryModes.Reject;

    public IReadOnlyList<int> BlockTypes { get; init; } = Array.Empty<int>();
}

public static class DnsOutboundNonIpQueryModes
{
    public const string Reject = "reject";
    public const string Drop = "drop";
    public const string Forward = "forward";

    public static string Normalize(string? value)
    {
        if (string.IsNullOrWhiteSpace(value))
        {
            return Reject;
        }

        return value.Trim().ToLowerInvariant() switch
        {
            Reject => Reject,
            Drop => Drop,
            _ => Forward
        };
    }
}

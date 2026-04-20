namespace NodePanel.Core.Runtime;

internal static class TrojanFallbackSelector
{
    public static ITrojanFallbackDefinition? Select(
        IReadOnlyList<ITrojanFallbackDefinition> fallbacks,
        string serverName,
        string alpn,
        ReadOnlySpan<byte> initialPayload)
        => RuntimeFallbackSelector.Select(fallbacks, serverName, alpn, initialPayload) as ITrojanFallbackDefinition;
}

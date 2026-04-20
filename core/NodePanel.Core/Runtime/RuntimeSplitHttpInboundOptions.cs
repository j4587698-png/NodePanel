namespace NodePanel.Core.Runtime;

public interface IInboundSplitHttpDefinition
{
    string SplitHttpMode { get; }

    bool SplitHttpNoSseHeader { get; }

    RuntimeInt32Range SplitHttpXPaddingBytes { get; }

    bool SplitHttpXPaddingObfsMode { get; }

    string SplitHttpXPaddingKey { get; }

    string SplitHttpXPaddingHeader { get; }

    string SplitHttpXPaddingPlacement { get; }

    string SplitHttpXPaddingMethod { get; }

    string SplitHttpSessionPlacement { get; }

    string SplitHttpSessionKey { get; }

    string SplitHttpSeqPlacement { get; }

    string SplitHttpSeqKey { get; }

    string SplitHttpUplinkDataPlacement { get; }

    string SplitHttpUplinkDataKey { get; }

    RuntimeInt32Range SplitHttpScMaxEachPostBytes { get; }

    int SplitHttpScMaxBufferedPosts { get; }

    RuntimeInt32Range SplitHttpScStreamUpServerSecs { get; }

    int SplitHttpServerMaxHeaderBytes { get; }
}

public sealed record RuntimeSplitHttpInboundOptions
{
    public static RuntimeSplitHttpInboundOptions Empty { get; } = new();

    public string Host { get; init; } = string.Empty;

    public string Path { get; init; } = "/";

    public string Mode { get; init; } = string.Empty;

    public bool NoSseHeader { get; init; }

    public RuntimeInt32Range XPaddingBytes { get; init; } = RuntimeInt32Range.Empty;

    public bool XPaddingObfsMode { get; init; }

    public string XPaddingKey { get; init; } = string.Empty;

    public string XPaddingHeader { get; init; } = string.Empty;

    public string XPaddingPlacement { get; init; } = string.Empty;

    public string XPaddingMethod { get; init; } = string.Empty;

    public string SessionPlacement { get; init; } = string.Empty;

    public string SessionKey { get; init; } = string.Empty;

    public string SeqPlacement { get; init; } = string.Empty;

    public string SeqKey { get; init; } = string.Empty;

    public string UplinkDataPlacement { get; init; } = string.Empty;

    public string UplinkDataKey { get; init; } = string.Empty;

    public RuntimeInt32Range ScMaxEachPostBytes { get; init; } = RuntimeInt32Range.Empty;

    public int ScMaxBufferedPosts { get; init; }

    public RuntimeInt32Range ScStreamUpServerSecs { get; init; } = RuntimeInt32Range.Empty;

    public int ServerMaxHeaderBytes { get; init; }
}

internal static class RuntimeSplitHttpInboundOptionsNormalizer
{
    public static bool TryNormalize(
        string host,
        string path,
        IInboundSplitHttpDefinition? definition,
        out RuntimeSplitHttpInboundOptions options,
        out string? error)
    {
        if (!RuntimeSplitHttpNormalization.TryNormalizeMode(
                definition?.SplitHttpMode,
                out var mode,
                out error) ||
            !RuntimeSplitHttpNormalization.TryNormalizeXPaddingBytes(
                definition?.SplitHttpXPaddingBytes,
                out var xPaddingBytes,
                out error) ||
            !RuntimeSplitHttpNormalization.TryNormalizeXPaddingPlacement(
                definition?.SplitHttpXPaddingPlacement,
                out var xPaddingPlacement,
                out error) ||
            !RuntimeSplitHttpNormalization.TryNormalizeXPaddingMethod(
                definition?.SplitHttpXPaddingMethod,
                out var xPaddingMethod,
                out error) ||
            !RuntimeSplitHttpNormalization.TryNormalizeSessionPlacement(
                definition?.SplitHttpSessionPlacement,
                out var sessionPlacement,
                out error) ||
            !RuntimeSplitHttpNormalization.TryNormalizeSeqPlacement(
                definition?.SplitHttpSeqPlacement,
                out var seqPlacement,
                out error) ||
            !RuntimeSplitHttpNormalization.TryNormalizeUplinkDataPlacement(
                string.IsNullOrWhiteSpace(definition?.SplitHttpUplinkDataPlacement)
                    ? "body"
                    : definition!.SplitHttpUplinkDataPlacement,
                out var uplinkDataPlacement,
                out error) ||
            !RuntimeSplitHttpNormalization.TryNormalizeServerMaxHeaderBytes(
                definition?.SplitHttpServerMaxHeaderBytes ?? 0,
                out var serverMaxHeaderBytes,
                out error))
        {
            options = RuntimeSplitHttpInboundOptions.Empty;
            return false;
        }

        options = new RuntimeSplitHttpInboundOptions
        {
            Host = string.IsNullOrWhiteSpace(host) ? string.Empty : host.Trim(),
            Path = RuntimeSplitHttpNormalization.NormalizePath(path),
            Mode = mode,
            NoSseHeader = definition?.SplitHttpNoSseHeader ?? false,
            XPaddingBytes = xPaddingBytes,
            XPaddingObfsMode = definition?.SplitHttpXPaddingObfsMode ?? false,
            XPaddingKey = RuntimeSplitHttpNormalization.NormalizeXPaddingKey(definition?.SplitHttpXPaddingKey),
            XPaddingHeader = RuntimeSplitHttpNormalization.NormalizeXPaddingHeader(definition?.SplitHttpXPaddingHeader),
            XPaddingPlacement = xPaddingPlacement,
            XPaddingMethod = xPaddingMethod,
            SessionPlacement = sessionPlacement,
            SessionKey = RuntimeSplitHttpNormalization.ResolveSessionKey(
                sessionPlacement,
                definition?.SplitHttpSessionKey),
            SeqPlacement = seqPlacement,
            SeqKey = RuntimeSplitHttpNormalization.ResolveSeqKey(
                seqPlacement,
                definition?.SplitHttpSeqKey),
            UplinkDataPlacement = uplinkDataPlacement,
            UplinkDataKey = RuntimeSplitHttpNormalization.ResolveUplinkDataKey(
                uplinkDataPlacement,
                definition?.SplitHttpUplinkDataKey),
            ScMaxEachPostBytes = RuntimeSplitHttpNormalization.NormalizeRange(definition?.SplitHttpScMaxEachPostBytes),
            ScMaxBufferedPosts = RuntimeSplitHttpNormalization.NormalizeBufferedPosts(
                definition?.SplitHttpScMaxBufferedPosts ?? 0),
            ScStreamUpServerSecs = RuntimeSplitHttpNormalization.NormalizeRange(
                definition?.SplitHttpScStreamUpServerSecs),
            ServerMaxHeaderBytes = serverMaxHeaderBytes
        };
        error = null;
        return true;
    }
}

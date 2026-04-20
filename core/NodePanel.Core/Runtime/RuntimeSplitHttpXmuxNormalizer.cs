namespace NodePanel.Core.Runtime;

internal static class RuntimeSplitHttpXmuxNormalizer
{
    private static readonly RuntimeSplitHttpXmuxOptions DefaultOptions = new()
    {
        MaxConcurrency = new RuntimeInt32Range
        {
            From = 1,
            To = 1
        },
        HMaxRequestTimes = new RuntimeInt32Range
        {
            From = 600,
            To = 900
        },
        HMaxReusableSecs = new RuntimeInt32Range
        {
            From = 1800,
            To = 3000
        }
    };

    public static bool TryNormalize(
        RuntimeSplitHttpXmuxOptions? value,
        out RuntimeSplitHttpXmuxOptions normalized,
        out string? error)
    {
        if (value is not null &&
            value.MaxConnections.To > 0 &&
            value.MaxConcurrency.To > 0)
        {
            normalized = default!;
            error = "SplitHTTP xmux maxConnections cannot be specified together with maxConcurrency.";
            return false;
        }

        if (value is null || IsUnconfigured(value))
        {
            normalized = DefaultOptions;
            error = null;
            return true;
        }

        normalized = new RuntimeSplitHttpXmuxOptions
        {
            MaxConcurrency = NormalizeRange(value.MaxConcurrency),
            MaxConnections = NormalizeRange(value.MaxConnections),
            CMaxReuseTimes = NormalizeRange(value.CMaxReuseTimes),
            HMaxRequestTimes = NormalizeRange(value.HMaxRequestTimes),
            HMaxReusableSecs = NormalizeRange(value.HMaxReusableSecs),
            HKeepAlivePeriodSeconds = Math.Max(0, value.HKeepAlivePeriodSeconds)
        };
        error = null;
        return true;
    }

    public static RuntimeSplitHttpXmuxOptions NormalizeOrThrow(RuntimeSplitHttpXmuxOptions? value)
    {
        if (!TryNormalize(value, out var normalized, out var error))
        {
            throw new InvalidOperationException(error);
        }

        return normalized;
    }

    private static bool IsUnconfigured(RuntimeSplitHttpXmuxOptions value)
        => value.MaxConcurrency == RuntimeInt32Range.Empty &&
           value.MaxConnections == RuntimeInt32Range.Empty &&
           value.CMaxReuseTimes == RuntimeInt32Range.Empty &&
           value.HMaxRequestTimes == RuntimeInt32Range.Empty &&
           value.HMaxReusableSecs == RuntimeInt32Range.Empty &&
           value.HKeepAlivePeriodSeconds == 0;

    private static RuntimeInt32Range NormalizeRange(RuntimeInt32Range? value)
    {
        if (value is null)
        {
            return RuntimeInt32Range.Empty;
        }

        var from = Math.Max(0, value.From);
        var to = Math.Max(0, value.To);
        if (from == 0 && to == 0)
        {
            return RuntimeInt32Range.Empty;
        }

        if (to < from)
        {
            (from, to) = (to, from);
        }

        return new RuntimeInt32Range
        {
            From = from,
            To = to
        };
    }
}

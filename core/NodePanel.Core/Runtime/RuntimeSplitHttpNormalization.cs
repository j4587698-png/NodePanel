namespace NodePanel.Core.Runtime;

internal static class RuntimeSplitHttpNormalization
{
    public static string NormalizePath(string value)
        => RuntimeSplitHttpRequestMetadata.NormalizePath(value);

    public static bool TryNormalizeMode(
        string? value,
        out string normalized,
        out string? error)
    {
        if (string.IsNullOrWhiteSpace(value))
        {
            normalized = "auto";
            error = null;
            return true;
        }

        normalized = value.Trim().ToLowerInvariant();
        error = normalized switch
        {
            "auto" or "packet-up" or "stream-up" or "stream-one" => null,
            _ => "unsupported mode: " + normalized
        };
        return error is null;
    }

    public static bool TryNormalizeXPaddingBytes(
        RuntimeInt32Range? value,
        out RuntimeInt32Range normalized,
        out string? error)
    {
        if (value is null || (value.From == 0 && value.To == 0))
        {
            normalized = RuntimeInt32Range.Empty;
            error = null;
            return true;
        }

        if (value.From <= 0 || value.To <= 0)
        {
            normalized = RuntimeInt32Range.Empty;
            error = "SplitHTTP xPaddingBytes cannot be disabled.";
            return false;
        }

        var from = value.From;
        var to = value.To;
        if (to < from)
        {
            (from, to) = (to, from);
        }

        normalized = new RuntimeInt32Range
        {
            From = from,
            To = to
        };
        error = null;
        return true;
    }

    public static string NormalizeXPaddingKey(string? value)
        => string.IsNullOrWhiteSpace(value) ? "x_padding" : value.Trim();

    public static string NormalizeXPaddingHeader(string? value)
        => string.IsNullOrWhiteSpace(value) ? "X-Padding" : value.Trim();

    public static bool TryNormalizeXPaddingPlacement(
        string? value,
        out string normalized,
        out string? error)
    {
        if (string.IsNullOrWhiteSpace(value))
        {
            normalized = "queryInHeader";
            error = null;
            return true;
        }

        normalized = value.Trim().ToLowerInvariant() switch
        {
            "cookie" => "cookie",
            "header" => "header",
            "query" => "query",
            "queryinheader" => "queryInHeader",
            _ => string.Empty
        };
        error = normalized.Length == 0
            ? "unsupported padding placement: " + value.Trim()
            : null;
        return error is null;
    }

    public static bool TryNormalizeXPaddingMethod(
        string? value,
        out string normalized,
        out string? error)
    {
        if (string.IsNullOrWhiteSpace(value))
        {
            normalized = "repeat-x";
            error = null;
            return true;
        }

        normalized = value.Trim().ToLowerInvariant();
        error = normalized switch
        {
            "repeat-x" or "tokenish" => null,
            _ => "unsupported padding method: " + value.Trim()
        };
        return error is null;
    }

    public static bool TryNormalizeUplinkDataPlacement(
        string? value,
        out string normalized,
        out string? error)
    {
        if (string.IsNullOrWhiteSpace(value))
        {
            normalized = "auto";
            error = null;
            return true;
        }

        normalized = value.Trim().ToLowerInvariant();
        error = normalized switch
        {
            "auto" or "body" or "header" or "cookie" => null,
            _ => "unsupported uplink data placement: " + normalized
        };
        return error is null;
    }

    public static bool TryNormalizeSessionPlacement(
        string? value,
        out string normalized,
        out string? error)
    {
        if (string.IsNullOrWhiteSpace(value))
        {
            normalized = "path";
            error = null;
            return true;
        }

        normalized = value.Trim().ToLowerInvariant();
        error = normalized switch
        {
            "path" or "query" or "header" or "cookie" => null,
            _ => "unsupported session placement: " + normalized
        };
        return error is null;
    }

    public static string ResolveSessionKey(string placement, string? value)
        => RuntimeSplitHttpRequestMetadata.ResolveSessionKey(
            placement,
            value ?? string.Empty);

    public static bool TryNormalizeSeqPlacement(
        string? value,
        out string normalized,
        out string? error)
    {
        if (string.IsNullOrWhiteSpace(value))
        {
            normalized = "path";
            error = null;
            return true;
        }

        normalized = value.Trim().ToLowerInvariant();
        error = normalized switch
        {
            "path" or "query" or "header" or "cookie" => null,
            _ => "unsupported seq placement: " + normalized
        };
        return error is null;
    }

    public static string ResolveSeqKey(string placement, string? value)
        => RuntimeSplitHttpRequestMetadata.ResolveSeqKey(
            placement,
            value ?? string.Empty);

    public static string ResolveUplinkDataKey(string placement, string? value)
    {
        if (!string.IsNullOrWhiteSpace(value))
        {
            return value.Trim();
        }

        return placement switch
        {
            "cookie" => "x_data",
            "auto" or "header" => "X-Data",
            _ => string.Empty
        };
    }

    public static RuntimeInt32Range NormalizeRange(RuntimeInt32Range? value)
    {
        if (value is null)
        {
            return RuntimeInt32Range.Empty;
        }

        var from = value.From;
        var to = value.To;
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

    public static int NormalizeBufferedPosts(int value)
        => Math.Max(0, value);

    public static bool TryNormalizeServerMaxHeaderBytes(
        int value,
        out int normalized,
        out string? error)
    {
        if (value < 0)
        {
            normalized = 0;
            error = "SplitHTTP serverMaxHeaderBytes cannot be negative.";
            return false;
        }

        normalized = value;
        error = null;
        return true;
    }
}

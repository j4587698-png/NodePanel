namespace NodePanel.Core.Runtime;

public sealed record RuntimeRealityOptions
{
    public static RuntimeRealityOptions Empty { get; } = new();

    public bool Show { get; init; }

    public string MasterKeyLog { get; init; } = string.Empty;

    public string Fingerprint { get; init; } = string.Empty;

    public string Password { get; init; } = string.Empty;

    public string PublicKey { get; init; } = string.Empty;

    public string ShortId { get; init; } = string.Empty;

    public string Mldsa65Verify { get; init; } = string.Empty;

    public string SpiderX { get; init; } = string.Empty;

    public IReadOnlyList<long> SpiderY { get; init; } = Array.Empty<long>();

    public bool IsEmpty =>
        !Show &&
        NormalizeMasterKeyLog(MasterKeyLog).Length == 0 &&
        string.IsNullOrWhiteSpace(Fingerprint) &&
        string.IsNullOrWhiteSpace(Password) &&
        string.IsNullOrWhiteSpace(PublicKey) &&
        string.IsNullOrWhiteSpace(ShortId) &&
        string.IsNullOrWhiteSpace(Mldsa65Verify) &&
        string.IsNullOrWhiteSpace(SpiderX) &&
        SpiderY.Count == 0;

    public RuntimeRealityOptions Normalize(bool applyRealityDefaults = false)
    {
        var normalizedPassword = NormalizeOptionalValue(Password);
        var normalizedPublicKey = normalizedPassword.Length > 0
            ? normalizedPassword
            : NormalizeOptionalValue(PublicKey);
        var normalizedSpiderX = NormalizeOptionalValue(SpiderX);
        if (applyRealityDefaults &&
            normalizedSpiderX.Length == 0)
        {
            normalizedSpiderX = "/";
        }

        var spiderY = NormalizeSpiderProfile(
            normalizedSpiderX,
            NormalizeSpiderY(SpiderY),
            out normalizedSpiderX);
        return this with
        {
            Show = Show,
            MasterKeyLog = NormalizeMasterKeyLog(MasterKeyLog),
            Fingerprint = NormalizeOptionalLowerValue(Fingerprint),
            Password = normalizedPassword,
            PublicKey = normalizedPublicKey,
            ShortId = NormalizeOptionalLowerValue(ShortId),
            Mldsa65Verify = NormalizeOptionalValue(Mldsa65Verify),
            SpiderX = normalizedSpiderX,
            SpiderY = spiderY
        };
    }

    public bool TryValidateForReality(out RuntimeRealityOptions normalized, out string? error)
    {
        normalized = Normalize(applyRealityDefaults: true);

        if (normalized.Fingerprint is "unsafe" or "hellogolang")
        {
            error = $"REALITY fingerprint does not support '{normalized.Fingerprint}'.";
            return false;
        }

        if (!RuntimeRealityFingerprintCatalog.IsKnown(normalized.Fingerprint))
        {
            error = $"REALITY fingerprint '{normalized.Fingerprint}' is unknown.";
            return false;
        }

        if (normalized.PublicKey.Length == 0)
        {
            error = "REALITY requires a public key or password.";
            return false;
        }

        if (!TryDecodeBase64Url(normalized.PublicKey, out var publicKeyBytes) ||
            publicKeyBytes.Length != 32)
        {
            error = "REALITY public key or password is invalid.";
            return false;
        }

        if (normalized.ShortId.Length > 16)
        {
            error = "REALITY short ID must be 16 hex characters or fewer.";
            return false;
        }

        if (normalized.ShortId.Length > 0 &&
            !TryDecodeHex(normalized.ShortId, out _))
        {
            error = "REALITY short ID is invalid.";
            return false;
        }

        if (normalized.Mldsa65Verify.Length > 0 &&
            (!TryDecodeBase64Url(normalized.Mldsa65Verify, out var verifyBytes) ||
             verifyBytes.Length != 1952))
        {
            error = "REALITY ML-DSA-65 verify key is invalid.";
            return false;
        }

        if (normalized.SpiderX.Length == 0 ||
            normalized.SpiderX[0] != '/')
        {
            error = "REALITY spider path must start with '/'.";
            return false;
        }

        error = null;
        return true;
    }

    public static RuntimeRealityOptions Normalize(
        RuntimeRealityOptions? options,
        bool applyRealityDefaults = false)
        => (options ?? Empty).Normalize(applyRealityDefaults);

    private static IReadOnlyList<long> NormalizeSpiderProfile(
        string spiderX,
        IReadOnlyList<long> currentSpiderY,
        out string normalizedSpiderX)
    {
        normalizedSpiderX = spiderX;
        if (spiderX.Length == 0)
        {
            return currentSpiderY.Count == 0
                ? Array.Empty<long>()
                : currentSpiderY;
        }

        var fragmentIndex = spiderX.IndexOf('#', StringComparison.Ordinal);
        var pathAndQuery = fragmentIndex >= 0 ? spiderX[..fragmentIndex] : spiderX;
        var fragment = fragmentIndex >= 0 ? spiderX[fragmentIndex..] : string.Empty;
        var queryIndex = pathAndQuery.IndexOf('?', StringComparison.Ordinal);
        if (queryIndex < 0)
        {
            return currentSpiderY.Count == 0
                ? new long[10]
                : currentSpiderY;
        }

        var path = pathAndQuery[..queryIndex];
        var query = queryIndex == pathAndQuery.Length - 1
            ? string.Empty
            : pathAndQuery[(queryIndex + 1)..];
        var spiderY = new long[10];
        if (query.Length == 0)
        {
            normalizedSpiderX = path + fragment;
            return spiderY;
        }

        var remainingParameters = new List<KeyValuePair<string, string>>();
        var hasParsedSpiderRange = false;
        var seenSpiderRangeIndexes = new HashSet<int>();
        foreach (var segment in query.Split('&', StringSplitOptions.RemoveEmptyEntries))
        {
            var separatorIndex = segment.IndexOf('=', StringComparison.Ordinal);
            var rawName = separatorIndex >= 0 ? segment[..separatorIndex] : segment;
            var rawValue = separatorIndex >= 0 && separatorIndex < segment.Length - 1
                ? segment[(separatorIndex + 1)..]
                : string.Empty;
            var name = DecodeQueryComponent(rawName);
            var decodedValue = DecodeQueryComponent(rawValue);

            if (TryResolveSpiderRangeIndex(name, out var spiderRangeIndex))
            {
                if (seenSpiderRangeIndexes.Add(spiderRangeIndex))
                {
                    ApplySpiderRange(decodedValue, spiderRangeIndex, spiderY);
                }

                hasParsedSpiderRange = true;
                continue;
            }

            remainingParameters.Add(new KeyValuePair<string, string>(name, decodedValue));
        }

        var encodedQuery = EncodeQueryParameters(remainingParameters);
        normalizedSpiderX = encodedQuery.Length == 0
            ? path + fragment
            : path + "?" + encodedQuery + fragment;
        return !hasParsedSpiderRange && currentSpiderY.Count > 0
            ? currentSpiderY
            : spiderY;
    }

    private static IReadOnlyList<long> NormalizeSpiderY(IReadOnlyList<long>? values)
    {
        if (values is null || values.Count == 0)
        {
            return Array.Empty<long>();
        }

        var normalized = new long[10];
        var count = Math.Min(normalized.Length, values.Count);
        for (var index = 0; index < count; index++)
        {
            normalized[index] = values[index];
        }

        return normalized;
    }

    private static bool TryResolveSpiderRangeIndex(string name, out int index)
    {
        index = name switch
        {
            "p" => 0,
            "c" => 2,
            "t" => 4,
            "i" => 6,
            "r" => 8,
            _ => -1
        };
        return index >= 0;
    }

    private static void ApplySpiderRange(string value, int index, long[] spiderY)
    {
        ArgumentNullException.ThrowIfNull(spiderY);

        if (value.Length == 0)
        {
            return;
        }

        var parts = value.Split('-', StringSplitOptions.None);
        spiderY[index] = TryParseSpiderPart(parts[0], out var firstValue) ? firstValue : 0;
        spiderY[index + 1] = parts.Length == 1
            ? spiderY[index]
            : TryParseSpiderPart(parts[1], out var secondValue)
                ? secondValue
                : 0;
    }

    private static bool TryParseSpiderPart(string value, out long parsed)
        => long.TryParse(
            value.Trim(),
            System.Globalization.NumberStyles.Integer,
            System.Globalization.CultureInfo.InvariantCulture,
            out parsed);

    private static string DecodeQueryComponent(string value)
        => Uri.UnescapeDataString(value.Replace("+", " ", StringComparison.Ordinal));

    private static string EncodeQueryParameters(IReadOnlyList<KeyValuePair<string, string>> parameters)
    {
        if (parameters.Count == 0)
        {
            return string.Empty;
        }

        var builder = new System.Text.StringBuilder();
        foreach (var parameter in parameters.OrderBy(static pair => pair.Key, StringComparer.Ordinal))
        {
            if (builder.Length > 0)
            {
                builder.Append('&');
            }

            builder.Append(EncodeQueryComponent(parameter.Key));
            builder.Append('=');
            builder.Append(EncodeQueryComponent(parameter.Value));
        }

        return builder.ToString();
    }

    private static string EncodeQueryComponent(string value)
        => Uri.EscapeDataString(value).Replace("%20", "+", StringComparison.Ordinal);

    internal static bool TryDecodeHex(string input, out byte[] bytes)
    {
        try
        {
            bytes = Convert.FromHexString(input);
            return true;
        }
        catch (FormatException)
        {
            bytes = Array.Empty<byte>();
            return false;
        }
    }

    internal static bool TryDecodeBase64Url(string input, out byte[] bytes)
    {
        try
        {
            var normalized = input
                .Replace('-', '+')
                .Replace('_', '/');
            var paddingLength = normalized.Length % 4;
            if (paddingLength == 1)
            {
                bytes = Array.Empty<byte>();
                return false;
            }

            if (paddingLength > 0)
            {
                normalized = normalized.PadRight(normalized.Length + (4 - paddingLength), '=');
            }

            bytes = Convert.FromBase64String(normalized);
            return true;
        }
        catch (FormatException)
        {
            bytes = Array.Empty<byte>();
            return false;
        }
    }

    private static string NormalizeOptionalValue(string? value)
        => string.IsNullOrWhiteSpace(value) ? string.Empty : value.Trim();

    private static string NormalizeMasterKeyLog(string? value)
    {
        var normalized = NormalizeOptionalValue(value);
        return string.Equals(normalized, "none", StringComparison.OrdinalIgnoreCase)
            ? string.Empty
            : normalized;
    }

    private static string NormalizeOptionalLowerValue(string? value)
        => string.IsNullOrWhiteSpace(value) ? string.Empty : value.Trim().ToLowerInvariant();
}

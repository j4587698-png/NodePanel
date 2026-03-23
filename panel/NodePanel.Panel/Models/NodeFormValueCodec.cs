using NodePanel.ControlPlane.Configuration;

namespace NodePanel.Panel.Models;

internal static class NodeFormValueCodec
{
    public static IReadOnlyList<string> ParseCsv(string value)
        => value
            .Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
            .Where(static item => !string.IsNullOrWhiteSpace(item))
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .ToArray();

    public static string JoinCsv(IEnumerable<string> values)
        => string.Join(", ", values.Where(static value => !string.IsNullOrWhiteSpace(value)));

    public static bool TryParseEnvironmentVariables(
        string value,
        out IReadOnlyList<CertificateEnvironmentVariable> environmentVariables,
        out string error)
    {
        if (!TryParseKeyValueLines(value, out var entries, out error))
        {
            environmentVariables = Array.Empty<CertificateEnvironmentVariable>();
            return false;
        }

        environmentVariables = entries
            .Select(static pair => new CertificateEnvironmentVariable
            {
                Name = pair.Key,
                Value = pair.Value
            })
            .ToArray();
        error = string.Empty;
        return true;
    }

    public static string FormatEnvironmentVariables(IReadOnlyList<CertificateEnvironmentVariable> values)
        => string.Join(
            Environment.NewLine,
            values
                .Where(static item => !string.IsNullOrWhiteSpace(item.Name))
                .Select(static item => $"{item.Name}={item.Value}"));

    public static bool TryParseHeaderLines(
        string value,
        out IReadOnlyDictionary<string, string> headers,
        out string error)
    {
        if (!TryParseKeyValueLines(value, out var entries, out error))
        {
            headers = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
            return false;
        }

        headers = new Dictionary<string, string>(entries, StringComparer.OrdinalIgnoreCase);
        error = string.Empty;
        return true;
    }

    public static string FormatHeaderLines(IReadOnlyDictionary<string, string> headers)
        => string.Join(
            Environment.NewLine,
            headers.Select(static pair => $"{pair.Key}={pair.Value}"));

    private static bool TryParseKeyValueLines(
        string value,
        out IReadOnlyDictionary<string, string> entries,
        out string error)
    {
        var result = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        if (string.IsNullOrWhiteSpace(value))
        {
            entries = result;
            error = string.Empty;
            return true;
        }

        var lines = value.Split(new[] { "\r\n", "\n" }, StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
        for (var index = 0; index < lines.Length; index++)
        {
            var line = lines[index];
            var separatorIndex = line.IndexOf('=', StringComparison.Ordinal);
            if (separatorIndex <= 0)
            {
                entries = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
                error = $"第 {index + 1} 行必须使用 KEY=VALUE 格式。";
                return false;
            }

            var key = line[..separatorIndex].Trim();
            if (string.IsNullOrWhiteSpace(key))
            {
                entries = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
                error = $"第 {index + 1} 行的 KEY 不能为空。";
                return false;
            }

            result[key] = line[(separatorIndex + 1)..].Trim();
        }

        entries = result;
        error = string.Empty;
        return true;
    }
}

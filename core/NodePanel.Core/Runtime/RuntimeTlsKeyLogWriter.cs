namespace NodePanel.Core.Runtime;

internal static class RuntimeTlsKeyLogWriter
{
    public static void TryAppendTls13Secrets(
        string path,
        ReadOnlySpan<byte> clientRandom,
        ReadOnlySpan<byte> clientHandshakeTrafficSecret,
        ReadOnlySpan<byte> serverHandshakeTrafficSecret,
        ReadOnlySpan<byte> clientApplicationTrafficSecret,
        ReadOnlySpan<byte> serverApplicationTrafficSecret,
        bool show)
    {
        if (string.IsNullOrWhiteSpace(path) ||
            string.Equals(path.Trim(), "none", StringComparison.OrdinalIgnoreCase))
        {
            return;
        }

        try
        {
            var normalizedPath = path.Trim();
            var directory = Path.GetDirectoryName(normalizedPath);
            if (!string.IsNullOrWhiteSpace(directory))
            {
                Directory.CreateDirectory(directory);
            }

            using var stream = new FileStream(
                normalizedPath,
                FileMode.Append,
                FileAccess.Write,
                FileShare.ReadWrite);
            using var writer = new StreamWriter(stream);
            writer.WriteLine(CreateKeyLogLine(
                "CLIENT_HANDSHAKE_TRAFFIC_SECRET",
                clientRandom,
                clientHandshakeTrafficSecret));
            writer.WriteLine(CreateKeyLogLine(
                "SERVER_HANDSHAKE_TRAFFIC_SECRET",
                clientRandom,
                serverHandshakeTrafficSecret));
            writer.WriteLine(CreateKeyLogLine(
                "CLIENT_TRAFFIC_SECRET_0",
                clientRandom,
                clientApplicationTrafficSecret));
            writer.WriteLine(CreateKeyLogLine(
                "SERVER_TRAFFIC_SECRET_0",
                clientRandom,
                serverApplicationTrafficSecret));
            writer.Flush();
        }
        catch (Exception ex) when (
            ex is IOException or
            UnauthorizedAccessException or
            NotSupportedException or
            ArgumentException)
        {
            if (show)
            {
                Console.Error.WriteLine($"REALITY masterKeyLog write failed: {ex.Message}");
            }
        }
    }

    private static string CreateKeyLogLine(
        string label,
        ReadOnlySpan<byte> clientRandom,
        ReadOnlySpan<byte> secret)
    {
        return string.Create(
            System.Globalization.CultureInfo.InvariantCulture,
            $"{label} {Convert.ToHexString(clientRandom)} {Convert.ToHexString(secret)}");
    }
}

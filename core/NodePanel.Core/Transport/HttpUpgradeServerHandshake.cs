using System.Text;
using NodePanel.Core.Runtime;

namespace NodePanel.Core.Transport;

public sealed record HttpUpgradeServerHandshakeOptions
{
    public string Host { get; init; } = string.Empty;

    public string Path { get; init; } = "/";
}

public static class HttpUpgradeServerHandshake
{
    public static async Task<Stream> AcceptAsync(
        Stream stream,
        HttpUpgradeServerHandshakeOptions options,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(stream);
        ArgumentNullException.ThrowIfNull(options);

        var expectedPath = RuntimeInternetHttpUtilities.NormalizePath(options.Path);
        var requestLine = await RuntimeInternetHttpUtilities
            .ReadHttpLineAsync(
                stream,
                "Unexpected end of stream during HTTP Upgrade handshake.",
                cancellationToken)
            .ConfigureAwait(false);
        if (string.IsNullOrWhiteSpace(requestLine))
        {
            throw new InvalidDataException("HTTP Upgrade request line is empty.");
        }

        var parts = requestLine.Split(' ', StringSplitOptions.RemoveEmptyEntries);
        if (parts.Length < 3 || !string.Equals(parts[0], "GET", StringComparison.OrdinalIgnoreCase))
        {
            throw new InvalidDataException("HTTP Upgrade handshake must start with a GET request.");
        }

        var requestedPath = parts[1].Split('?', 2)[0];
        if (!string.Equals(requestedPath, expectedPath, StringComparison.Ordinal))
        {
            await WriteHttpErrorAsync(stream, 404, "Not Found", cancellationToken).ConfigureAwait(false);
            throw new InvalidDataException($"Unexpected HTTP Upgrade path: {requestedPath}.");
        }

        var headers = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        while (true)
        {
            var line = await RuntimeInternetHttpUtilities
                .ReadHttpLineAsync(
                    stream,
                    "Unexpected end of stream during HTTP Upgrade handshake.",
                    cancellationToken)
                .ConfigureAwait(false);
            if (line.Length == 0)
            {
                break;
            }

            var separator = line.IndexOf(':');
            if (separator <= 0)
            {
                continue;
            }

            headers[line[..separator].Trim()] = line[(separator + 1)..].Trim();
        }

        if (!string.IsNullOrWhiteSpace(options.Host) &&
            (!headers.TryGetValue("Host", out var requestHost) ||
             !WebSocketServerHandshake.IsValidHttpHost(requestHost, options.Host)))
        {
            await WriteHttpErrorAsync(stream, 404, "Not Found", cancellationToken).ConfigureAwait(false);
            throw new InvalidDataException("HTTP Upgrade Host header validation failed.");
        }

        if (!headers.TryGetValue("Upgrade", out var upgrade) ||
            !string.Equals(upgrade, "websocket", StringComparison.OrdinalIgnoreCase))
        {
            throw new InvalidDataException("Missing Upgrade: websocket header.");
        }

        if (!headers.TryGetValue("Connection", out var connection) ||
            connection.IndexOf("Upgrade", StringComparison.OrdinalIgnoreCase) < 0)
        {
            throw new InvalidDataException("Missing Connection: Upgrade header.");
        }

        var responseLines = new List<string>
        {
            "HTTP/1.1 101 Switching Protocols",
            "Upgrade: websocket",
            "Connection: Upgrade",
            string.Empty,
            string.Empty
        };

        var responseBytes = Encoding.ASCII.GetBytes(string.Join("\r\n", responseLines));
        await stream.WriteAsync(responseBytes.AsMemory(0, responseBytes.Length), cancellationToken).ConfigureAwait(false);
        await stream.FlushAsync(cancellationToken).ConfigureAwait(false);

        // httpupgrade uses a fake WebSocket Upgrade handshake, but the payload is raw bytes (no WebSocket frames).
        return stream;
    }

    private static async Task WriteHttpErrorAsync(
        Stream stream,
        int statusCode,
        string reasonPhrase,
        CancellationToken cancellationToken)
    {
        var payload = Encoding.ASCII.GetBytes($"HTTP/1.1 {statusCode} {reasonPhrase}\r\nContent-Length: 0\r\n\r\n");
        await stream.WriteAsync(payload.AsMemory(0, payload.Length), cancellationToken).ConfigureAwait(false);
        await stream.FlushAsync(cancellationToken).ConfigureAwait(false);
    }
}


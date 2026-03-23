using System.Security.Cryptography;
using System.Text;
using System.Net.WebSockets;
using NodePanel.Core.Runtime;

namespace NodePanel.Core.Transport;

public sealed record WebSocketServerHandshakeOptions
{
    public string Host { get; init; } = string.Empty;

    public string Path { get; init; } = "/";

    public int EarlyDataBytes { get; init; }

    public int HeartbeatPeriodSeconds { get; init; }
}

public static class WebSocketServerHandshake
{
    private const int MaxHeaderBytes = 8 * 1024;
    private const string WebSocketGuid = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";

    public static async Task<Stream> AcceptAsync(
        Stream stream,
        WebSocketServerHandshakeOptions options,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(stream);
        ArgumentNullException.ThrowIfNull(options);

        var expectedPath = NormalizePath(options.Path);
        var requestLine = await ReadLineAsync(stream, cancellationToken).ConfigureAwait(false);
        if (string.IsNullOrWhiteSpace(requestLine))
        {
            throw new InvalidDataException("WebSocket request line is empty.");
        }

        var parts = requestLine.Split(' ', StringSplitOptions.RemoveEmptyEntries);
        if (parts.Length < 3 || !string.Equals(parts[0], "GET", StringComparison.OrdinalIgnoreCase))
        {
            throw new InvalidDataException("WebSocket handshake must start with a GET request.");
        }

        var requestedPath = parts[1].Split('?', 2)[0];
        if (!string.Equals(requestedPath, expectedPath, StringComparison.Ordinal))
        {
            await WriteHttpErrorAsync(stream, 404, "Not Found", cancellationToken).ConfigureAwait(false);
            throw new InvalidDataException($"Unexpected WebSocket path: {requestedPath}.");
        }

        var headers = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        while (true)
        {
            var line = await ReadLineAsync(stream, cancellationToken).ConfigureAwait(false);
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
            (!headers.TryGetValue("Host", out var requestHost) || !IsValidHttpHost(requestHost, options.Host)))
        {
            await WriteHttpErrorAsync(stream, 404, "Not Found", cancellationToken).ConfigureAwait(false);
            throw new InvalidDataException("WebSocket Host header validation failed.");
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

        if (!headers.TryGetValue("Sec-WebSocket-Key", out var webSocketKey) || string.IsNullOrWhiteSpace(webSocketKey))
        {
            throw new InvalidDataException("Missing Sec-WebSocket-Key header.");
        }

        if (!headers.TryGetValue("Sec-WebSocket-Version", out var version) || version != "13")
        {
            throw new InvalidDataException("Unsupported Sec-WebSocket-Version.");
        }

        var earlyData = Array.Empty<byte>();
        var acceptKey = ComputeAcceptKey(webSocketKey);
        var responseLines = new List<string>
        {
            "HTTP/1.1 101 Switching Protocols",
            "Upgrade: websocket",
            "Connection: Upgrade",
            $"Sec-WebSocket-Accept: {acceptKey}"
        };

        if (options.EarlyDataBytes > 0 &&
            headers.TryGetValue("Sec-WebSocket-Protocol", out var protocolHeader) &&
            TryDecodeEarlyData(protocolHeader, out var decodedEarlyData) &&
            decodedEarlyData.Length > 0)
        {
            earlyData = decodedEarlyData;
            responseLines.Add($"Sec-WebSocket-Protocol: {protocolHeader}");
        }

        responseLines.Add(string.Empty);
        responseLines.Add(string.Empty);

        var bytes = Encoding.ASCII.GetBytes(string.Join("\r\n", responseLines));
        await stream.WriteAsync(bytes.AsMemory(0, bytes.Length), cancellationToken).ConfigureAwait(false);
        await stream.FlushAsync(cancellationToken).ConfigureAwait(false);

        var keepAliveInterval = options.HeartbeatPeriodSeconds > 0
            ? TimeSpan.FromSeconds(options.HeartbeatPeriodSeconds)
            : Timeout.InfiniteTimeSpan;

        Stream result = new WebSocketDuplexStream(
            WebSocket.CreateFromStream(
                stream,
                isServer: true,
                subProtocol: null,
                keepAliveInterval: keepAliveInterval));

        if (earlyData.Length > 0)
        {
            result = new PrefixedReadStream(result, earlyData);
        }

        return result;
    }

    internal static bool IsValidHttpHost(string requestHost, string configuredHost)
    {
        var requested = requestHost.Trim().ToLowerInvariant();
        var expected = configuredHost.Trim().ToLowerInvariant();

        if (requested.Contains(':', StringComparison.Ordinal))
        {
            return TrySplitHostPort(requested, out var host)
                ? string.Equals(host, expected, StringComparison.Ordinal)
                : string.Equals(requested, expected, StringComparison.Ordinal);
        }

        return string.Equals(requested, expected, StringComparison.Ordinal);
    }

    private static async Task WriteHttpErrorAsync(Stream stream, int statusCode, string reasonPhrase, CancellationToken cancellationToken)
    {
        var payload = Encoding.ASCII.GetBytes($"HTTP/1.1 {statusCode} {reasonPhrase}\r\nContent-Length: 0\r\n\r\n");
        await stream.WriteAsync(payload.AsMemory(0, payload.Length), cancellationToken).ConfigureAwait(false);
        await stream.FlushAsync(cancellationToken).ConfigureAwait(false);
    }

    private static bool TryDecodeEarlyData(string value, out byte[] payload)
    {
        payload = Array.Empty<byte>();
        if (string.IsNullOrWhiteSpace(value))
        {
            return false;
        }

        var normalized = value.Trim()
            .Replace("+", "-", StringComparison.Ordinal)
            .Replace("/", "_", StringComparison.Ordinal)
            .Replace("=", string.Empty, StringComparison.Ordinal);

        var paddingLength = (4 - (normalized.Length % 4)) % 4;
        normalized = normalized.PadRight(normalized.Length + paddingLength, '=')
            .Replace('-', '+')
            .Replace('_', '/');

        try
        {
            payload = Convert.FromBase64String(normalized);
            return payload.Length > 0;
        }
        catch (FormatException)
        {
            payload = Array.Empty<byte>();
            return false;
        }
    }

    private static string NormalizePath(string value)
    {
        if (string.IsNullOrWhiteSpace(value))
        {
            return "/";
        }

        var normalized = value.Trim();
        return normalized.StartsWith("/", StringComparison.Ordinal) ? normalized : "/" + normalized;
    }

    private static bool TrySplitHostPort(string value, out string host)
    {
        host = string.Empty;
        if (value.Length == 0)
        {
            return false;
        }

        if (value[0] == '[')
        {
            var end = value.IndexOf(']');
            if (end <= 1 || end == value.Length - 1 || value[end + 1] != ':')
            {
                return false;
            }

            host = value[1..end];
            return true;
        }

        var separator = value.LastIndexOf(':');
        if (separator <= 0 || separator == value.Length - 1)
        {
            return false;
        }

        host = value[..separator];
        return true;
    }

    private static string ComputeAcceptKey(string webSocketKey)
    {
        var input = Encoding.ASCII.GetBytes(webSocketKey + WebSocketGuid);
        var hash = SHA1.HashData(input);
        return Convert.ToBase64String(hash);
    }

    private static async Task<string> ReadLineAsync(Stream stream, CancellationToken cancellationToken)
    {
        using var buffer = new MemoryStream(128);
        var oneByte = new byte[1];

        while (buffer.Length < MaxHeaderBytes)
        {
            var read = await stream.ReadAsync(oneByte.AsMemory(0, 1), cancellationToken).ConfigureAwait(false);
            if (read == 0)
            {
                throw new EndOfStreamException("Unexpected end of stream during WebSocket handshake.");
            }

            if (oneByte[0] == '\n')
            {
                var bytes = buffer.ToArray();
                if (bytes.Length > 0 && bytes[^1] == '\r')
                {
                    Array.Resize(ref bytes, bytes.Length - 1);
                }

                return Encoding.ASCII.GetString(bytes);
            }

            buffer.WriteByte(oneByte[0]);
        }

        throw new InvalidDataException("WebSocket header exceeds the configured maximum size.");
    }
}

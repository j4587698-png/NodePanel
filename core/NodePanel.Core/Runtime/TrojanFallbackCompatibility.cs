using System.Net;
using System.Net.Sockets;

namespace NodePanel.Core.Runtime;

public static class TrojanFallbackCompatibility
{
    private const int LinuxUnixDomainSocketPathLength = 108;

    public const string DefaultNetworkType = "tcp";
    public const string ServeNetworkType = "serve";
    public const string ServeWsNoneDestination = "serve-ws-none";

    public static string NormalizePath(string value)
    {
        if (string.IsNullOrWhiteSpace(value))
        {
            return string.Empty;
        }

        var normalized = value.Trim();
        return normalized.StartsWith("/", StringComparison.Ordinal) ? normalized : "/" + normalized;
    }

    public static string NormalizeType(string value, string destination)
    {
        if (!string.IsNullOrWhiteSpace(value))
        {
            return value.Trim().ToLowerInvariant();
        }

        if (string.IsNullOrWhiteSpace(destination))
        {
            return string.Empty;
        }

        var trimmedDestination = destination.Trim();
        if (string.Equals(trimmedDestination, ServeWsNoneDestination, StringComparison.Ordinal))
        {
            return ServeNetworkType;
        }

        if (IsUnixDestination(trimmedDestination))
        {
            return "unix";
        }

        return TryNormalizeTcpDestination(trimmedDestination, out _)
            ? DefaultNetworkType
            : string.Empty;
    }

    public static string NormalizeDestination(string networkType, string destination)
    {
        if (string.IsNullOrWhiteSpace(destination))
        {
            return string.Empty;
        }

        var normalizedNetworkType = string.IsNullOrWhiteSpace(networkType)
            ? DefaultNetworkType
            : networkType.Trim().ToLowerInvariant();
        var trimmedDestination = destination.Trim();

        return normalizedNetworkType switch
        {
            "tcp" or "tcp4" or "tcp6" => TryNormalizeTcpDestination(trimmedDestination, out var normalizedTcp)
                ? normalizedTcp
                : trimmedDestination,
            _ => trimmedDestination
        };
    }

    public static int NormalizeProxyProtocolVersion(int value)
        => value is 1 or 2 ? value : 0;

    public static bool IsSupportedTransportType(string value)
        => value is "tcp" or "tcp4" or "tcp6" or "unix" or ServeNetworkType;

    public static bool IsValidDestination(string networkType, string destination)
    {
        if (string.IsNullOrWhiteSpace(destination))
        {
            return false;
        }

        var normalizedNetworkType = string.IsNullOrWhiteSpace(networkType)
            ? DefaultNetworkType
            : networkType.Trim().ToLowerInvariant();
        var trimmedDestination = destination.Trim();

        return normalizedNetworkType switch
        {
            "unix" => trimmedDestination.Length > 0,
            ServeNetworkType => string.Equals(trimmedDestination, ServeWsNoneDestination, StringComparison.Ordinal),
            "tcp" or "tcp4" or "tcp6" => TryNormalizeTcpDestination(trimmedDestination, out _),
            _ => false
        };
    }

    public static EndPoint CreateUnixEndPoint(string destination)
    {
        return new UnixDomainSocketEndPoint(
            NormalizeUnixSocketPath(
                destination,
                OperatingSystem.IsLinux() || OperatingSystem.IsAndroid()));
    }

    internal static string NormalizeUnixSocketPath(string destination, bool linuxLikePlatform)
    {
        if (string.IsNullOrWhiteSpace(destination))
        {
            throw new InvalidDataException("Trojan fallback destination is empty.");
        }

        var trimmed = destination.Trim();
        if (!linuxLikePlatform || !trimmed.StartsWith("@", StringComparison.Ordinal))
        {
            return trimmed;
        }

        if (trimmed.StartsWith("@@", StringComparison.Ordinal))
        {
            return CreatePaddedAbstractUnixSocketPath(trimmed[2..]);
        }

        var abstractName = trimmed[1..];
        if (abstractName.Length == 0)
        {
            throw new InvalidDataException("Trojan fallback abstract UNIX destination is empty.");
        }

        return "\0" + abstractName;
    }

    private static bool IsUnixDestination(string destination)
        => destination.StartsWith("@", StringComparison.Ordinal) || Path.IsPathRooted(destination);

    private static string CreatePaddedAbstractUnixSocketPath(string abstractName)
    {
        if (abstractName.Length == 0)
        {
            throw new InvalidDataException("Trojan fallback abstract UNIX destination is empty.");
        }

        var socketPath = new char[LinuxUnixDomainSocketPathLength];
        socketPath[0] = '\0';
        abstractName
            .AsSpan(0, Math.Min(abstractName.Length, socketPath.Length - 1))
            .CopyTo(socketPath.AsSpan(1));
        return new string(socketPath);
    }

    private static bool TryNormalizeTcpDestination(string destination, out string normalized)
    {
        normalized = string.Empty;
        if (string.IsNullOrWhiteSpace(destination))
        {
            return false;
        }

        var trimmed = destination.Trim();
        if (int.TryParse(trimmed, out var port) && port is > 0 and <= 65535)
        {
            normalized = $"localhost:{port}";
            return true;
        }

        if (Uri.TryCreate($"{DefaultNetworkType}://{trimmed}", UriKind.Absolute, out var uri) &&
            uri.Port > 0 &&
            !string.IsNullOrWhiteSpace(uri.Host))
        {
            normalized = trimmed;
            return true;
        }

        return false;
    }
}

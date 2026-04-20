using System.Net;
using System.Security.Cryptography;
using System.Text;
using Blake3;

namespace NodePanel.Core.Runtime;

internal static class XudpGlobalId
{
    internal const string BaseKeyEnvironmentName = "xray.xudp.basekey";
    internal const string BaseKeyAlternateEnvironmentName = "XRAY_XUDP_BASEKEY";

    private const int BaseKeyLength = 32;
    private const int GlobalIdLength = 8;

    private static readonly byte[] DefaultBaseKey = CreateRandomBaseKey();

    public static byte[] Create(DispatchContext context)
    {
        ArgumentNullException.ThrowIfNull(context);
        return Create(context, ResolveBaseKey(Environment.GetEnvironmentVariable));
    }

    internal static byte[] Create(DispatchContext context, ReadOnlySpan<byte> baseKey)
    {
        ArgumentNullException.ThrowIfNull(context);

        if (!ShouldDerive(context))
        {
            return new byte[GlobalIdLength];
        }

        var sourceIdentity = BuildSourceIdentity(context.SourceEndPoint!);
        Span<byte> globalId = stackalloc byte[GlobalIdLength];
        using var hasher = Hasher.NewKeyed(baseKey);
        hasher.Update(Encoding.ASCII.GetBytes(sourceIdentity));
        hasher.Finalize(globalId);
        return globalId.ToArray();
    }

    internal static byte[] ResolveBaseKey(Func<string, string?> getEnvironmentVariable)
    {
        ArgumentNullException.ThrowIfNull(getEnvironmentVariable);

        var configured = getEnvironmentVariable(BaseKeyEnvironmentName);
        if (string.IsNullOrWhiteSpace(configured))
        {
            configured = getEnvironmentVariable(BaseKeyAlternateEnvironmentName);
        }

        return string.IsNullOrWhiteSpace(configured)
            ? DefaultBaseKey
            : DecodeConfiguredBaseKey(configured);
    }

    internal static byte[] DecodeConfiguredBaseKey(string rawValue)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(rawValue);

        var normalized = rawValue
            .Trim()
            .Replace('-', '+')
            .Replace('_', '/');

        normalized = (normalized.Length % 4) switch
        {
            0 => normalized,
            2 => normalized + "==",
            3 => normalized + "=",
            _ => throw new InvalidOperationException(
                $"{BaseKeyEnvironmentName}: invalid value (BaseKey must be 32 bytes).")
        };

        byte[] key;
        try
        {
            key = Convert.FromBase64String(normalized);
        }
        catch (FormatException ex)
        {
            throw new InvalidOperationException(
                $"{BaseKeyEnvironmentName}: invalid value (BaseKey must be 32 bytes).",
                ex);
        }

        if (key.Length != BaseKeyLength)
        {
            throw new InvalidOperationException(
                $"{BaseKeyEnvironmentName}: invalid value (BaseKey must be 32 bytes).");
        }

        return key;
    }

    private static bool ShouldDerive(DispatchContext context)
        => context.UseCone &&
           string.Equals(
               RoutingNetworks.Normalize(context.InboundSourceNetwork),
               RoutingNetworks.Udp,
               StringComparison.Ordinal) &&
           context.SourceEndPoint is not null &&
           IsSupportedInboundKind(context.InboundKind);

    private static bool IsSupportedInboundKind(string? inboundKind)
        => !string.IsNullOrWhiteSpace(inboundKind) &&
           inboundKind.Trim().ToLowerInvariant() switch
           {
               "dokodemo-door" => true,
               ProxyInboundProtocols.Socks => true,
               "shadowsocks" => true,
               "tun" => true,
               _ => false
           };

    private static string BuildSourceIdentity(EndPoint sourceEndPoint)
        => RoutingNetworks.Udp + ":" + sourceEndPoint;

    private static byte[] CreateRandomBaseKey()
    {
        var key = new byte[BaseKeyLength];
        RandomNumberGenerator.Fill(key);
        return key;
    }
}

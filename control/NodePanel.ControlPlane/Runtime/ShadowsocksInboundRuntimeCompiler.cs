using NodePanel.ControlPlane.Configuration;
using NodePanel.Core.Runtime;

namespace NodePanel.ControlPlane.Runtime;

public sealed class ShadowsocksInboundRuntimeCompiler : IInboundProtocolRuntimeCompiler
{
    public string Protocol => InboundProtocols.Shadowsocks;

    public NodeServiceConfig Normalize(NodeServiceConfig config)
    {
        ArgumentNullException.ThrowIfNull(config);

        return config with
        {
            Inbounds = config.Inbounds
                .Select(NormalizeInbound)
                .ToArray()
        };
    }

    public bool TryCompile(
        NodeServiceConfig config,
        out InboundProtocolRuntimeCompilation compilation,
        out string? error)
    {
        ArgumentNullException.ThrowIfNull(config);

        if (!ShadowsocksInboundRuntimePlanner.TryBuild(
                config.Inbounds.Cast<IShadowsocksInboundDefinition>().ToArray(),
                out var plan,
                out error))
        {
            compilation = new InboundProtocolRuntimeCompilation
            {
                Plan = ShadowsocksInboundRuntimePlan.Empty
            };
            return false;
        }

        compilation = new InboundProtocolRuntimeCompilation
        {
            Plan = plan,
            ActiveUsers = plan.Inbounds
                .SelectMany(static inbound => inbound.Users)
                .Cast<IRuntimeUserDefinition>()
                .Concat(plan.Inbounds2022.SelectMany(static inbound => inbound.Users))
                .Cast<IRuntimeUserDefinition>()
                .ToArray()
        };
        error = null;
        return true;
    }

    private static InboundConfig NormalizeInbound(InboundConfig inbound)
    {
        var protocol = InboundProtocols.Normalize(inbound.Protocol);
        if (!string.Equals(protocol, InboundProtocols.Shadowsocks, StringComparison.Ordinal))
        {
            return inbound;
        }

        return inbound with
        {
            Tag = inbound.Tag.Trim(),
            Protocol = protocol,
            ListenAddress = NormalizeListenAddress(inbound.ListenAddress),
            Port = NormalizeListenerPort(inbound.Port, 8388),
            HandshakeTimeoutSeconds = NormalizePositive(inbound.HandshakeTimeoutSeconds, 60),
            Security = NormalizeCipher(inbound.Security),
            Password = inbound.Password.Trim(),
            Networks = NormalizeNetworks(inbound.Networks),
            Sniffing = NormalizeSniffing(inbound.Sniffing),
            Users = NormalizeUsers(inbound.Users),
            ShadowsocksUsers = NormalizeShadowsocksUsers(inbound.ShadowsocksUsers)
        };
    }

    private static InboundSniffingConfig NormalizeSniffing(InboundSniffingConfig sniffing)
        => sniffing with
        {
            DestinationOverride = NormalizeStringList(sniffing.DestinationOverride)
                .Select(RoutingProtocols.Normalize)
                .Where(static value => !string.IsNullOrWhiteSpace(value))
                .Distinct(StringComparer.OrdinalIgnoreCase)
                .ToArray(),
            DomainsExcluded = NormalizeStringList(sniffing.DomainsExcluded)
                .Select(static value => value.ToLowerInvariant())
                .ToArray()
        };

    private static IReadOnlyList<TrojanUserConfig> NormalizeUsers(IReadOnlyList<TrojanUserConfig> users)
        => users
            .Where(static user => user is not null)
            .Select(static user => user with
            {
                UserId = user.UserId.Trim(),
                Level = Math.Max(0, user.Level),
                Cipher = NormalizeCipher(user.Cipher),
                Password = user.Password.Trim(),
                BytesPerSecond = Math.Max(0, user.BytesPerSecond),
                DeviceLimit = Math.Max(0, user.DeviceLimit)
            })
            .ToArray();

    private static IReadOnlyList<ShadowsocksUserConfig> NormalizeShadowsocksUsers(IReadOnlyList<ShadowsocksUserConfig> users)
        => users
            .Where(static user => user is not null)
            .Select(static user => user with
            {
                UserId = user.UserId.Trim(),
                Level = Math.Max(0, user.Level),
                Cipher = NormalizeCipher(user.Cipher),
                Password = user.Password.Trim(),
                Address = string.IsNullOrWhiteSpace(user.Address) ? string.Empty : user.Address.Trim(),
                Port = user.Port is > 0 and <= 65535 ? user.Port : 0,
                BytesPerSecond = Math.Max(0, user.BytesPerSecond),
                DeviceLimit = Math.Max(0, user.DeviceLimit)
            })
            .ToArray();

    private static IReadOnlyList<string> NormalizeNetworks(IReadOnlyList<string> values)
        => NormalizeStringList(values)
            .Select(RoutingNetworks.Normalize)
            .ToArray();

    private static IReadOnlyList<string> NormalizeStringList(IReadOnlyList<string> values)
        => values
            .Where(static value => !string.IsNullOrWhiteSpace(value))
            .Select(static value => value.Trim())
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .ToArray();

    private static string NormalizeCipher(string? value)
        => string.IsNullOrWhiteSpace(value)
            ? string.Empty
            : ShadowsocksCipherTypes.Normalize(value);

    private static string NormalizeListenAddress(string value)
        => string.IsNullOrWhiteSpace(value) ? "0.0.0.0" : value.Trim();

    private static int NormalizeListenerPort(int value, int fallback)
        => value is > 0 and <= 65535 ? value : fallback;

    private static int NormalizePositive(int value, int fallback)
        => value > 0 ? value : fallback;
}

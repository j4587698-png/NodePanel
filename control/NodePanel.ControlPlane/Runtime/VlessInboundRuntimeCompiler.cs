using NodePanel.ControlPlane.Configuration;
using NodePanel.Core.Runtime;

namespace NodePanel.ControlPlane.Runtime;

public sealed class VlessInboundRuntimeCompiler : IInboundProtocolRuntimeCompiler
{
    public string Protocol => InboundProtocols.Vless;

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

        if (!VlessInboundRuntimePlanner.TryBuild(
                config.Inbounds.Cast<IVlessInboundDefinition>().ToArray(),
                out var plan,
                out error))
        {
            compilation = new InboundProtocolRuntimeCompilation
            {
                Plan = VlessInboundRuntimePlan.Empty
            };
            return false;
        }

        compilation = new InboundProtocolRuntimeCompilation
        {
            Plan = plan,
            ActiveUsers = GetActiveUsers(config.Inbounds)
        };
        error = null;
        return true;
    }

    private static InboundConfig NormalizeInbound(InboundConfig inbound)
    {
        var protocol = InboundProtocols.Normalize(inbound.Protocol);
        if (!string.Equals(protocol, InboundProtocols.Vless, StringComparison.Ordinal))
        {
            return inbound;
        }

        var resolvedStack = TryResolveInboundInternetStack(inbound, out var internetStack)
            ? internetStack
            : default;
        var transport = !string.IsNullOrWhiteSpace(resolvedStack.Transport)
            ? resolvedStack.Transport
            : InboundTransports.Normalize(inbound.Transport);
        var transportProtocol = !string.IsNullOrWhiteSpace(resolvedStack.TransportProtocol)
            ? resolvedStack.TransportProtocol
            : NormalizeOptionalTransportProtocol(inbound.TransportProtocol);
        var transportSecurity = !string.IsNullOrWhiteSpace(resolvedStack.SecurityType)
            ? resolvedStack.SecurityType
            : NormalizeOptionalTransportSecurity(inbound.TransportSecurity);
        var isWebSocketTransport = IsWebSocketTransport(transport, transportProtocol);
        var isHttpUpgradeTransport = IsHttpUpgradeTransport(transportProtocol);
        var isGrpcTransport = IsGrpcTransport(transportProtocol);
        var isSplitHttpTransport = IsSplitHttpTransport(transportProtocol);
        var flow = NormalizeInboundFlow(inbound.Flow);
        var testSeed = NormalizeVlessTestSeed(inbound.TestSeed);
        var users = NormalizeUsers(inbound.Users, flow, testSeed);

        return inbound with
        {
            Tag = inbound.Tag.Trim(),
            Protocol = protocol,
            Transport = transport,
            TransportProtocol = transportProtocol,
            TransportSecurity = transportSecurity,
            ListenAddress = NormalizeListenAddress(inbound.ListenAddress),
            Port = NormalizeListenerPort(inbound.Port, isWebSocketTransport || isHttpUpgradeTransport ? 8443 : 443),
            HandshakeTimeoutSeconds = NormalizePositive(inbound.HandshakeTimeoutSeconds, 60),
            Host = inbound.Host.Trim(),
            Path = isWebSocketTransport || isHttpUpgradeTransport
                ? NormalizePath(inbound.Path)
                : isSplitHttpTransport
                    ? RuntimeSplitHttpNormalization.NormalizePath(inbound.Path)
                    : string.Empty,
            EarlyDataBytes = Math.Max(0, inbound.EarlyDataBytes),
            HeartbeatPeriodSeconds = Math.Max(0, inbound.HeartbeatPeriodSeconds),
            ApplicationProtocols = NormalizeInboundApplicationProtocols(transportProtocol, transport, inbound.ApplicationProtocols),
            GrpcServiceName = isGrpcTransport ? RuntimeGrpcUtilities.NormalizeServiceName(inbound.GrpcServiceName) : string.Empty,
            GrpcAuthority = isGrpcTransport ? RuntimeGrpcUtilities.NormalizeAuthority(inbound.GrpcAuthority) : string.Empty,
            GrpcMultiMode = isGrpcTransport && inbound.GrpcMultiMode,
            GrpcUserAgent = isGrpcTransport ? RuntimeGrpcUtilities.NormalizeUserAgent(inbound.GrpcUserAgent) : string.Empty,
            GrpcIdleTimeoutSeconds = isGrpcTransport ? Math.Max(0, inbound.GrpcIdleTimeoutSeconds) : 0,
            GrpcHealthCheckTimeoutSeconds = isGrpcTransport ? Math.Max(0, inbound.GrpcHealthCheckTimeoutSeconds) : 0,
            GrpcPermitWithoutStream = isGrpcTransport && inbound.GrpcPermitWithoutStream,
            GrpcInitialWindowSize = isGrpcTransport ? Math.Max(0, inbound.GrpcInitialWindowSize) : 0,
            Flow = flow,
            TestSeed = testSeed,
            Sniffing = NormalizeSniffing(inbound.Sniffing),
            Users = users
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

    private static IReadOnlyList<TrojanUserConfig> NormalizeUsers(
        IReadOnlyList<TrojanUserConfig> users,
        string defaultFlow,
        IReadOnlyList<uint> defaultTestSeed)
        => users
            .Where(static user => !string.IsNullOrWhiteSpace(user.UserId) && TryNormalizeUuid(user.Uuid, out _))
            .Select(user => user with
            {
                UserId = user.UserId.Trim(),
                Uuid = NormalizeUuid(user.Uuid),
                Flow = NormalizeUserFlow(user.Flow, defaultFlow),
                ReverseTag = NormalizeReverseTag(user.ReverseTag),
                TestSeed = NormalizeUserTestSeed(user.TestSeed, defaultTestSeed),
                Password = string.IsNullOrWhiteSpace(user.Password) ? string.Empty : user.Password.Trim(),
                Level = Math.Max(0, user.Level),
                BytesPerSecond = Math.Max(0, user.BytesPerSecond),
                DeviceLimit = Math.Max(0, user.DeviceLimit)
            })
            .ToArray();

    private static IReadOnlyList<IRuntimeUserDefinition> GetActiveUsers(IReadOnlyList<InboundConfig> inbounds)
        => inbounds
            .Where(static inbound => inbound.Enabled &&
                                     (NodeServiceConfigInbounds.IsProtocolTransport(inbound, InboundProtocols.Vless, InboundTransports.Tls) ||
                                      NodeServiceConfigInbounds.IsProtocolTransport(inbound, InboundProtocols.Vless, InboundTransports.Wss) ||
                                      NodeServiceConfigInbounds.IsProtocolTransport(inbound, InboundProtocols.Vless, RuntimeInternetTransportProtocols.HttpUpgrade) ||
                                      NodeServiceConfigInbounds.IsProtocolTransport(inbound, InboundProtocols.Vless, InboundTransports.Grpc) ||
                                      NodeServiceConfigInbounds.IsProtocolTransport(inbound, InboundProtocols.Vless, InboundTransports.SplitHttp)))
            .SelectMany(static inbound => inbound.Users
                .Where(static user => !string.IsNullOrWhiteSpace(user.UserId) && TryNormalizeUuid(user.Uuid, out _))
                .Select(user => new VlessUser
                {
                    UserId = user.UserId.Trim(),
                    Uuid = NormalizeUuid(user.Uuid),
                    Flow = NormalizeUserFlow(user.Flow, inbound.Flow),
                    ReverseTag = NormalizeReverseTag(user.ReverseTag),
                    TestSeed = NormalizeUserTestSeed(user.TestSeed, inbound.TestSeed),
                    RuntimeKey = RuntimeUserKeys.Create(InboundProtocols.Vless, inbound.Tag, user.UserId),
                    Level = Math.Max(0, user.Level),
                    BytesPerSecond = Math.Max(0, user.BytesPerSecond),
                    DeviceLimit = Math.Max(0, user.DeviceLimit)
                }))
            .Cast<IRuntimeUserDefinition>()
            .ToArray();

    private static string NormalizeListenAddress(string value)
        => string.IsNullOrWhiteSpace(value) ? "0.0.0.0" : value.Trim();

    private static int NormalizeListenerPort(int value, int fallback)
        => value is >= 0 and <= 65535 ? value : fallback;

    private static int NormalizePositive(int value, int fallback)
        => value > 0 ? value : fallback;

    private static string NormalizeInboundFlow(string? value)
        => VlessFlowTypes.IsVision(value)
            ? VlessFlowTypes.Vision
            : string.Empty;

    private static string NormalizeUserFlow(string? userFlow, string? defaultFlow)
    {
        var normalizedUserFlow = NormalizeInboundFlow(userFlow);
        return normalizedUserFlow.Length > 0
            ? normalizedUserFlow
            : NormalizeInboundFlow(defaultFlow);
    }

    private static string NormalizeReverseTag(string? value)
        => string.IsNullOrWhiteSpace(value) ? string.Empty : value.Trim();

    private static IReadOnlyList<uint> NormalizeUserTestSeed(
        IReadOnlyList<uint>? userTestSeed,
        IReadOnlyList<uint>? defaultTestSeed)
    {
        var normalizedUserTestSeed = NormalizeVlessTestSeed(userTestSeed);
        return normalizedUserTestSeed.Count > 0
            ? normalizedUserTestSeed
            : NormalizeVlessTestSeed(defaultTestSeed);
    }

    private static IReadOnlyList<uint> NormalizeVlessTestSeed(IReadOnlyList<uint>? values)
        => values is { Count: >= 4 }
            ? values.Take(4).ToArray()
            : Array.Empty<uint>();

    private static string NormalizePath(string value)
    {
        if (string.IsNullOrWhiteSpace(value))
        {
            return "/ws";
        }

        var normalized = value.Trim();
        return normalized.StartsWith("/", StringComparison.Ordinal) ? normalized : "/" + normalized;
    }

    private static IReadOnlyList<string> NormalizeStringList(IReadOnlyList<string> values)
        => values
            .Where(static value => !string.IsNullOrWhiteSpace(value))
            .Select(static value => value.Trim())
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .ToArray();

    private static IReadOnlyList<string> NormalizeInboundApplicationProtocols(
        string transportProtocol,
        string transport,
        IReadOnlyList<string> values)
        => IsWebSocketTransport(transport, transportProtocol) || IsHttpUpgradeTransport(transportProtocol)
            ? ["http/1.1"]
            : RuntimeInternetTransportProtocols.Normalize(transportProtocol) switch
        {
            RuntimeInternetTransportProtocols.Tcp => NormalizeStringList(values),
            RuntimeInternetTransportProtocols.Grpc => ["h2"],
            RuntimeInternetTransportProtocols.SplitHttp => ["http/1.1", "h2"],
            _ => Array.Empty<string>()
        };

    private static bool TryResolveInboundInternetStack(InboundConfig inbound, out InboundInternetStack stack)
        => InboundInternetStackResolver.TryResolve(
            inbound.Transport,
            inbound.TransportProtocol,
            inbound.TransportSecurity,
            out stack,
            out _);

    private static bool IsWebSocketTransport(string transport, string transportProtocol)
        => string.Equals(InboundTransports.Normalize(transport), InboundTransports.Wss, StringComparison.Ordinal) ||
           string.Equals(RuntimeInternetTransportProtocols.Normalize(transportProtocol), RuntimeInternetTransportProtocols.Ws, StringComparison.Ordinal);

    private static bool IsGrpcTransport(string transportProtocol)
        => string.Equals(
            RuntimeInternetTransportProtocols.Normalize(transportProtocol),
            RuntimeInternetTransportProtocols.Grpc,
            StringComparison.Ordinal);

    private static bool IsHttpUpgradeTransport(string transportProtocol)
        => string.Equals(
            RuntimeInternetTransportProtocols.Normalize(transportProtocol),
            RuntimeInternetTransportProtocols.HttpUpgrade,
            StringComparison.Ordinal);

    private static bool IsSplitHttpTransport(string transportProtocol)
        => string.Equals(
            RuntimeInternetTransportProtocols.Normalize(transportProtocol),
            RuntimeInternetTransportProtocols.SplitHttp,
            StringComparison.Ordinal);

    private static string NormalizeOptionalTransportProtocol(string value)
        => string.IsNullOrWhiteSpace(value)
            ? string.Empty
            : RuntimeInternetTransportProtocols.Normalize(value);

    private static string NormalizeOptionalTransportSecurity(string value)
        => string.IsNullOrWhiteSpace(value)
            ? string.Empty
            : RuntimeInternetSecurityTypes.Normalize(value);

    private static bool TryNormalizeUuid(string? value, out string normalized)
    {
        if (Guid.TryParse(value?.Trim(), out var uuid))
        {
            normalized = uuid.ToString("D");
            return true;
        }

        normalized = string.Empty;
        return false;
    }

    private static string NormalizeUuid(string? value)
        => TryNormalizeUuid(value, out var normalized) ? normalized : string.Empty;
}

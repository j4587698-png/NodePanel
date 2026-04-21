using NodePanel.ControlPlane.Configuration;
using NodePanel.Core.Runtime;

namespace NodePanel.ControlPlane.Runtime;

public sealed class BuiltinOutboundRuntimeCompiler : OutboundProtocolRuntimeCompilerBase
{
    public BuiltinOutboundRuntimeCompiler()
        : base(
            OutboundProtocols.Freedom,
            OutboundProtocols.Blackhole,
            OutboundProtocols.Selector,
            OutboundProtocols.UrlTest,
            OutboundProtocols.Fallback,
            OutboundProtocols.LoadBalance)
    {
    }

    public override bool TryValidate(NodeServiceConfig config, out string? error)
    {
        foreach (var outbound in GetSupportedOutbounds(config))
        {
            var protocol = OutboundProtocols.Normalize(outbound.Protocol);
            if (protocol is not (
                OutboundProtocols.Selector or
                OutboundProtocols.UrlTest or
                OutboundProtocols.Fallback or
                OutboundProtocols.LoadBalance))
            {
                continue;
            }

            if (!OutboundRuntimeCompilerUtilities.TryValidateStrategyOutbound(outbound, out error))
            {
                return false;
            }
        }

        error = null;
        return true;
    }
}

public sealed class TrojanOutboundRuntimeCompiler : OutboundProtocolRuntimeCompilerBase
{
    public TrojanOutboundRuntimeCompiler()
        : base(OutboundProtocols.Trojan)
    {
    }

    public override bool TryValidate(NodeServiceConfig config, out string? error)
    {
        foreach (var outbound in GetSupportedOutbounds(config))
        {
            if (!OutboundRuntimeCompilerUtilities.TryValidateProxyOutbound(outbound, OutboundProtocols.Trojan, out error))
            {
                return false;
            }
        }

        error = null;
        return true;
    }

    public override IReadOnlyList<IRuntimeOutboundOptions> BuildRuntimeOptions(NodeServiceConfig config)
        => GetSupportedOutbounds(config)
            .Select(static outbound => (IRuntimeOutboundOptions)OutboundRuntimeCompilerUtilities.CreateTrojanOptions(outbound))
            .ToArray();
}

public sealed class ShadowsocksOutboundRuntimeCompiler : OutboundProtocolRuntimeCompilerBase
{
    public ShadowsocksOutboundRuntimeCompiler()
        : base(OutboundProtocols.Shadowsocks)
    {
    }

    public override bool TryValidate(NodeServiceConfig config, out string? error)
    {
        foreach (var outbound in GetSupportedOutbounds(config))
        {
            if (!OutboundRuntimeCompilerUtilities.TryValidateShadowsocksOutbound(outbound, out error))
            {
                return false;
            }
        }

        error = null;
        return true;
    }

    public override IReadOnlyList<IRuntimeOutboundOptions> BuildRuntimeOptions(NodeServiceConfig config)
        => GetSupportedOutbounds(config)
            .Select(static outbound => (IRuntimeOutboundOptions)OutboundRuntimeCompilerUtilities.CreateShadowsocksOptions(outbound))
            .ToArray();
}

public sealed class SocksOutboundRuntimeCompiler : OutboundProtocolRuntimeCompilerBase
{
    public SocksOutboundRuntimeCompiler()
        : base(OutboundProtocols.Socks)
    {
    }

    public override bool TryValidate(NodeServiceConfig config, out string? error)
    {
        foreach (var outbound in GetSupportedOutbounds(config))
        {
            if (!OutboundRuntimeCompilerUtilities.TryValidateSocksOutbound(outbound, out error))
            {
                return false;
            }
        }

        error = null;
        return true;
    }

    public override IReadOnlyList<IRuntimeOutboundOptions> BuildRuntimeOptions(NodeServiceConfig config)
        => GetSupportedOutbounds(config)
            .Select(static outbound => (IRuntimeOutboundOptions)OutboundRuntimeCompilerUtilities.CreateSocksOptions(outbound))
            .ToArray();
}

public sealed class HttpOutboundRuntimeCompiler : OutboundProtocolRuntimeCompilerBase
{
    public HttpOutboundRuntimeCompiler()
        : base(OutboundProtocols.Http)
    {
    }

    public override bool TryValidate(NodeServiceConfig config, out string? error)
    {
        foreach (var outbound in GetSupportedOutbounds(config))
        {
            if (!OutboundRuntimeCompilerUtilities.TryValidateHttpOutbound(outbound, out error))
            {
                return false;
            }
        }

        error = null;
        return true;
    }

    public override IReadOnlyList<IRuntimeOutboundOptions> BuildRuntimeOptions(NodeServiceConfig config)
        => GetSupportedOutbounds(config)
            .Select(static outbound => (IRuntimeOutboundOptions)OutboundRuntimeCompilerUtilities.CreateHttpOptions(outbound))
            .ToArray();
}

public sealed class VlessOutboundRuntimeCompiler : OutboundProtocolRuntimeCompilerBase
{
    public VlessOutboundRuntimeCompiler()
        : base(OutboundProtocols.Vless)
    {
    }

    public override bool TryValidate(NodeServiceConfig config, out string? error)
    {
        foreach (var outbound in GetSupportedOutbounds(config))
        {
            if (!OutboundRuntimeCompilerUtilities.TryValidateProxyOutbound(outbound, OutboundProtocols.Vless, out error))
            {
                return false;
            }
        }

        error = null;
        return true;
    }

    public override IReadOnlyList<IRuntimeOutboundOptions> BuildRuntimeOptions(NodeServiceConfig config)
        => GetSupportedOutbounds(config)
            .Select(static outbound => (IRuntimeOutboundOptions)OutboundRuntimeCompilerUtilities.CreateVlessOptions(outbound))
            .ToArray();
}

public sealed class VmessOutboundRuntimeCompiler : OutboundProtocolRuntimeCompilerBase
{
    public VmessOutboundRuntimeCompiler()
        : base(OutboundProtocols.Vmess)
    {
    }

    public override bool TryValidate(NodeServiceConfig config, out string? error)
    {
        foreach (var outbound in GetSupportedOutbounds(config))
        {
            if (!OutboundRuntimeCompilerUtilities.TryValidateProxyOutbound(outbound, OutboundProtocols.Vmess, out error))
            {
                return false;
            }
        }

        error = null;
        return true;
    }

    public override IReadOnlyList<IRuntimeOutboundOptions> BuildRuntimeOptions(NodeServiceConfig config)
        => GetSupportedOutbounds(config)
            .Select(static outbound => (IRuntimeOutboundOptions)OutboundRuntimeCompilerUtilities.CreateVmessOptions(outbound))
            .ToArray();
}

internal static class OutboundRuntimeCompilerUtilities
{
    public static OutboundConfig Normalize(OutboundConfig outbound)
    {
        ArgumentNullException.ThrowIfNull(outbound);

        var protocol = OutboundProtocols.Normalize(outbound.Protocol);
        var isProxyTransportProtocol = protocol is OutboundProtocols.Trojan or OutboundProtocols.Vless or OutboundProtocols.Vmess;
        var isShadowsocksProtocol = protocol == OutboundProtocols.Shadowsocks;
        var isSocksProtocol = protocol == OutboundProtocols.Socks;
        var isHttpProtocol = protocol == OutboundProtocols.Http;
        ProxyInternetStack? resolvedProxyInternetStack = null;
        if (isProxyTransportProtocol &&
            ProxyInternetStackResolver.TryResolve(
                outbound.Transport,
                outbound.TransportSecurity,
                out var proxyInternetStack,
                out _))
        {
            resolvedProxyInternetStack = proxyInternetStack;
        }

        var transport = resolvedProxyInternetStack is { } normalizedProxyInternetStack
            ? normalizedProxyInternetStack.Transport
            : NormalizeSenderTransport(protocol, outbound.Transport);
        var transportSecurity = isProxyTransportProtocol
            ? resolvedProxyInternetStack is { } normalizedTransportStack
                ? normalizedTransportStack.SecurityType
                : RuntimeInternetSecurityTypes.Normalize(outbound.TransportSecurity)
            : string.Empty;
        var useRealityDefaults = isProxyTransportProtocol &&
                                 string.Equals(transportSecurity, RuntimeInternetSecurityTypes.Reality, StringComparison.Ordinal);
        var realityOptions = isProxyTransportProtocol
            ? RuntimeRealityOptions.Normalize(outbound.RealityOptions, applyRealityDefaults: useRealityDefaults)
            : RuntimeRealityOptions.Empty;
        var isGrpcProxyTransport = resolvedProxyInternetStack is { } grpcProxyInternetStack
            ? grpcProxyInternetStack.IsGrpcTransport
            : string.Equals(transport, TrojanOutboundTransports.Grpc, StringComparison.Ordinal);
        var isPathBasedProxyTransport = resolvedProxyInternetStack is { } pathBasedProxyInternetStack
            ? pathBasedProxyInternetStack.UsesPathBasedTransport
            : IsPathBasedTransport(transport);

        return outbound with
        {
            Tag = NormalizeOptionalValue(outbound.Tag),
            Protocol = protocol,
            Via = NormalizeOptionalValue(outbound.Via),
            ViaCidr = NormalizeViaCidr(outbound.ViaCidr),
            TargetStrategy = OutboundTargetStrategies.Normalize(outbound.TargetStrategy),
            ProxyOutboundTag = NormalizeOptionalValue(outbound.ProxyOutboundTag),
            MultiplexSettings = NormalizeMultiplexSettings(outbound.MultiplexSettings),
            Transport = transport,
            TransportSecurity = transportSecurity,
            ServerHost = NormalizeOptionalValue(outbound.ServerHost),
            ServerPort = isProxyTransportProtocol
                ? outbound.ServerPort
                : isShadowsocksProtocol
                    ? outbound.ServerPort
                : isSocksProtocol
                    ? NormalizePort(outbound.ServerPort, 1080)
                    : isHttpProtocol
                        ? NormalizePort(outbound.ServerPort, 8080)
                    : outbound.ServerPort,
            ServerName = NormalizeOptionalValue(outbound.ServerName),
            Fingerprint = NormalizeOptionalValue(outbound.Fingerprint),
            RealityOptions = realityOptions,
            WebSocketPath = isProxyTransportProtocol && isPathBasedProxyTransport
                ? NormalizeOutboundWebSocketPath(outbound.WebSocketPath)
                : NormalizeOptionalValue(outbound.WebSocketPath),
            WebSocketHeaders = NormalizeHeaderDictionary(outbound.WebSocketHeaders),
            HttpHeaders = NormalizeHeaderDictionary(outbound.HttpHeaders),
            WebSocketEarlyDataBytes = Math.Max(0, outbound.WebSocketEarlyDataBytes),
            WebSocketHeartbeatPeriodSeconds = Math.Max(0, outbound.WebSocketHeartbeatPeriodSeconds),
            ApplicationProtocols = NormalizeOutboundApplicationProtocols(
                protocol,
                transport,
                transportSecurity,
                outbound.ApplicationProtocols),
            GrpcServiceName = RuntimeGrpcUtilities.NormalizeServiceName(outbound.GrpcServiceName),
            GrpcAuthority = RuntimeGrpcUtilities.NormalizeAuthority(outbound.GrpcAuthority),
            GrpcMultiMode = isGrpcProxyTransport && outbound.GrpcMultiMode,
            GrpcUserAgent = RuntimeGrpcUtilities.NormalizeUserAgent(outbound.GrpcUserAgent),
            GrpcIdleTimeoutSeconds = isGrpcProxyTransport
                ? Math.Max(0, outbound.GrpcIdleTimeoutSeconds)
                : 0,
            GrpcHealthCheckTimeoutSeconds = isGrpcProxyTransport
                ? Math.Max(0, outbound.GrpcHealthCheckTimeoutSeconds)
                : 0,
            GrpcPermitWithoutStream = isGrpcProxyTransport && outbound.GrpcPermitWithoutStream,
            GrpcInitialWindowSize = isGrpcProxyTransport
                ? Math.Max(0, outbound.GrpcInitialWindowSize)
                : 0,
            Uuid = isProxyTransportProtocol
                ? NormalizeOptionalValue(outbound.Uuid)
                : NormalizeOptionalValue(outbound.Uuid),
            Flow = string.Equals(protocol, OutboundProtocols.Vless, StringComparison.Ordinal)
                ? VlessFlowTypes.Normalize(outbound.Flow)
                : NormalizeOptionalValue(outbound.Flow),
            TestSeed = string.Equals(protocol, OutboundProtocols.Vless, StringComparison.Ordinal)
                ? NormalizeVlessTestSeed(outbound.TestSeed)
                : Array.Empty<uint>(),
            ReverseTag = string.Equals(protocol, OutboundProtocols.Vless, StringComparison.Ordinal)
                ? NormalizeOptionalValue(outbound.ReverseTag)
                : string.Empty,
            Username = NormalizeOptionalValue(outbound.Username),
            Security = string.Equals(protocol, OutboundProtocols.Vmess, StringComparison.Ordinal)
                ? VmessOutboundSecurityTypes.Normalize(outbound.Security)
                : string.Equals(protocol, OutboundProtocols.Shadowsocks, StringComparison.Ordinal)
                    ? ShadowsocksCipherTypes.Normalize(outbound.Security)
                : NormalizeOptionalValue(outbound.Security),
            AuthenticatedLength = outbound.AuthenticatedLength,
            NoTerminationSignal = outbound.NoTerminationSignal,
            Password = NormalizeOptionalValue(outbound.Password),
            UdpOverTcp = isShadowsocksProtocol && outbound.UdpOverTcp,
            UdpOverTcpVersion = isShadowsocksProtocol ? Math.Max(0, outbound.UdpOverTcpVersion) : 0,
            ConnectTimeoutSeconds = Math.Max(0, outbound.ConnectTimeoutSeconds),
            HandshakeTimeoutSeconds = Math.Max(0, outbound.HandshakeTimeoutSeconds),
            CandidateTags = NormalizeStringList(outbound.CandidateTags),
            SelectedTag = NormalizeOptionalValue(outbound.SelectedTag),
            ProbeUrl = string.IsNullOrWhiteSpace(outbound.ProbeUrl)
                ? StrategyOutboundDefaults.ProbeUrl
                : outbound.ProbeUrl.Trim(),
            ProbeIntervalSeconds = NormalizePositive(
                outbound.ProbeIntervalSeconds,
                StrategyOutboundDefaults.ProbeIntervalSeconds),
            ProbeTimeoutSeconds = NormalizePositive(
                outbound.ProbeTimeoutSeconds,
                StrategyOutboundDefaults.ProbeTimeoutSeconds),
            ToleranceMilliseconds = Math.Max(0, outbound.ToleranceMilliseconds)
        };
    }

    public static bool TryValidateStrategyOutbound(OutboundConfig outbound, out string? error)
    {
        if (!Uri.TryCreate(outbound.ProbeUrl, UriKind.Absolute, out var probeUri) ||
            probeUri.Scheme is not ("http" or "https"))
        {
            error = $"Strategy outbound '{outbound.Tag}' requires a valid probe URL.";
            return false;
        }

        error = null;
        return true;
    }

    public static bool TryValidateSocksOutbound(OutboundConfig outbound, out string? error)
    {
        ArgumentNullException.ThrowIfNull(outbound);

        if (string.IsNullOrWhiteSpace(outbound.ServerHost))
        {
            error = $"SOCKS outbound '{outbound.Tag}' requires a server host.";
            return false;
        }

        if (outbound.ServerPort is <= 0 or > 65535)
        {
            error = $"SOCKS outbound '{outbound.Tag}' has an invalid server port: {outbound.ServerPort}.";
            return false;
        }

        var hasUsername = !string.IsNullOrWhiteSpace(outbound.Username);
        var hasPassword = !string.IsNullOrWhiteSpace(outbound.Password);
        if (hasUsername != hasPassword)
        {
            error = $"SOCKS outbound '{outbound.Tag}' must provide both username and password when authentication is enabled.";
            return false;
        }

        error = null;
        return true;
    }

    public static bool TryValidateShadowsocksOutbound(OutboundConfig outbound, out string? error)
    {
        ArgumentNullException.ThrowIfNull(outbound);

        return ShadowsocksOutboundOptionsCompiler.TryCompile(
            new RuntimeShadowsocksOutboundOptions
            {
                Tag = outbound.Tag,
                ServerHost = outbound.ServerHost,
                ServerPort = outbound.ServerPort,
                Cipher = outbound.Security,
                Password = outbound.Password,
                UdpOverTcp = outbound.UdpOverTcp,
                UdpOverTcpVersion = outbound.UdpOverTcpVersion,
                ConnectTimeoutSeconds = outbound.ConnectTimeoutSeconds
            },
            out _,
            out error);
    }

    public static bool TryValidateHttpOutbound(OutboundConfig outbound, out string? error)
    {
        ArgumentNullException.ThrowIfNull(outbound);

        if (string.IsNullOrWhiteSpace(outbound.ServerHost))
        {
            error = $"HTTP outbound '{outbound.Tag}' requires a server host.";
            return false;
        }

        if (outbound.ServerPort is <= 0 or > 65535)
        {
            error = $"HTTP outbound '{outbound.Tag}' has an invalid server port: {outbound.ServerPort}.";
            return false;
        }

        var hasUsername = !string.IsNullOrWhiteSpace(outbound.Username);
        var hasPassword = !string.IsNullOrWhiteSpace(outbound.Password);
        if (hasUsername != hasPassword)
        {
            error = $"HTTP outbound '{outbound.Tag}' must provide both username and password when authentication is enabled.";
            return false;
        }

        if (HttpOutboundTransports.Normalize(outbound.Transport) is not
            (HttpOutboundTransports.Tcp or HttpOutboundTransports.Tls))
        {
            error = $"HTTP outbound '{outbound.Tag}' uses an unsupported transport: {outbound.Transport}.";
            return false;
        }

        error = null;
        return true;
    }

    public static bool TryValidateProxyOutbound(OutboundConfig outbound, string protocol, out string? error)
    {
        ArgumentNullException.ThrowIfNull(outbound);

        return OutboundProtocols.Normalize(protocol) switch
        {
            OutboundProtocols.Trojan => ProxyOutboundOptionsCompiler.TryCompileTrojan(
                CreateRawTrojanOptions(outbound),
                out _,
                out error),
            OutboundProtocols.Vless => ProxyOutboundOptionsCompiler.TryCompileVless(
                CreateRawVlessOptions(outbound),
                out _,
                out error),
            OutboundProtocols.Vmess => ProxyOutboundOptionsCompiler.TryCompileVmess(
                CreateRawVmessOptions(outbound),
                out _,
                out error),
            _ => throw new NotSupportedException($"Unsupported proxy outbound protocol: {protocol}.")
        };
    }

    public static RuntimeTrojanOutboundOptions CreateTrojanOptions(OutboundConfig outbound)
        => ProxyOutboundOptionsCompiler.CompileTrojan(CreateRawTrojanOptions(outbound));

    private static RuntimeTrojanOutboundOptions CreateRawTrojanOptions(OutboundConfig outbound)
        => new()
        {
            Tag = outbound.Tag,
            ServerHost = outbound.ServerHost,
            ServerPort = outbound.ServerPort,
            ServerName = outbound.ServerName,
            Fingerprint = outbound.Fingerprint,
            Transport = outbound.Transport,
            TransportSecurity = outbound.TransportSecurity,
            RealityOptions = outbound.RealityOptions ?? RuntimeRealityOptions.Empty,
            WebSocketPath = outbound.WebSocketPath,
            WebSocketHeaders = CloneHeaders(outbound.WebSocketHeaders),
            WebSocketEarlyDataBytes = outbound.WebSocketEarlyDataBytes,
            WebSocketHeartbeatPeriodSeconds = outbound.WebSocketHeartbeatPeriodSeconds,
            ApplicationProtocols = outbound.ApplicationProtocols?.ToArray() ?? Array.Empty<string>(),
            GrpcServiceName = outbound.GrpcServiceName,
            GrpcAuthority = outbound.GrpcAuthority,
            GrpcMultiMode = outbound.GrpcMultiMode,
            GrpcUserAgent = outbound.GrpcUserAgent,
            GrpcIdleTimeoutSeconds = outbound.GrpcIdleTimeoutSeconds,
            GrpcHealthCheckTimeoutSeconds = outbound.GrpcHealthCheckTimeoutSeconds,
            GrpcPermitWithoutStream = outbound.GrpcPermitWithoutStream,
            GrpcInitialWindowSize = outbound.GrpcInitialWindowSize,
            Password = outbound.Password,
            ConnectTimeoutSeconds = outbound.ConnectTimeoutSeconds,
            HandshakeTimeoutSeconds = outbound.HandshakeTimeoutSeconds,
            SkipCertificateValidation = outbound.SkipCertificateValidation
        };

    public static RuntimeSocksOutboundOptions CreateSocksOptions(OutboundConfig outbound)
        => new()
        {
            Tag = outbound.Tag,
            ServerHost = outbound.ServerHost,
            ServerPort = outbound.ServerPort,
            Username = outbound.Username,
            Password = outbound.Password,
            ConnectTimeoutSeconds = outbound.ConnectTimeoutSeconds,
            HandshakeTimeoutSeconds = outbound.HandshakeTimeoutSeconds
        };

    public static IRuntimeOutboundOptions CreateShadowsocksOptions(OutboundConfig outbound)
        => ShadowsocksOutboundOptionsCompiler.Compile(
            new RuntimeShadowsocksOutboundOptions
            {
                Tag = outbound.Tag,
                ServerHost = outbound.ServerHost,
                ServerPort = outbound.ServerPort,
                Cipher = outbound.Security,
                Password = outbound.Password,
                UdpOverTcp = outbound.UdpOverTcp,
                UdpOverTcpVersion = outbound.UdpOverTcpVersion,
                ConnectTimeoutSeconds = outbound.ConnectTimeoutSeconds
            });

    public static RuntimeHttpOutboundOptions CreateHttpOptions(OutboundConfig outbound)
        => new()
        {
            Tag = outbound.Tag,
            ServerHost = outbound.ServerHost,
            ServerPort = outbound.ServerPort,
            ServerName = outbound.ServerName,
            Fingerprint = outbound.Fingerprint,
            Transport = outbound.Transport,
            Username = outbound.Username,
            Password = outbound.Password,
            Headers = CloneHeaders(outbound.HttpHeaders),
            ApplicationProtocols = outbound.ApplicationProtocols?.ToArray() ?? Array.Empty<string>(),
            ConnectTimeoutSeconds = outbound.ConnectTimeoutSeconds,
            HandshakeTimeoutSeconds = outbound.HandshakeTimeoutSeconds,
            SkipCertificateValidation = outbound.SkipCertificateValidation
        };

    public static RuntimeVlessOutboundOptions CreateVlessOptions(OutboundConfig outbound)
        => ProxyOutboundOptionsCompiler.CompileVless(CreateRawVlessOptions(outbound));

    private static RuntimeVlessOutboundOptions CreateRawVlessOptions(OutboundConfig outbound)
        => new()
        {
            Tag = outbound.Tag,
            ServerHost = outbound.ServerHost,
            ServerPort = outbound.ServerPort,
            ServerName = outbound.ServerName,
            Fingerprint = outbound.Fingerprint,
            Transport = outbound.Transport,
            TransportSecurity = outbound.TransportSecurity,
            RealityOptions = outbound.RealityOptions ?? RuntimeRealityOptions.Empty,
            WebSocketPath = outbound.WebSocketPath,
            WebSocketHeaders = CloneHeaders(outbound.WebSocketHeaders),
            WebSocketEarlyDataBytes = outbound.WebSocketEarlyDataBytes,
            WebSocketHeartbeatPeriodSeconds = outbound.WebSocketHeartbeatPeriodSeconds,
            ApplicationProtocols = outbound.ApplicationProtocols?.ToArray() ?? Array.Empty<string>(),
            GrpcServiceName = outbound.GrpcServiceName,
            GrpcAuthority = outbound.GrpcAuthority,
            GrpcMultiMode = outbound.GrpcMultiMode,
            GrpcUserAgent = outbound.GrpcUserAgent,
            GrpcIdleTimeoutSeconds = outbound.GrpcIdleTimeoutSeconds,
            GrpcHealthCheckTimeoutSeconds = outbound.GrpcHealthCheckTimeoutSeconds,
            GrpcPermitWithoutStream = outbound.GrpcPermitWithoutStream,
            GrpcInitialWindowSize = outbound.GrpcInitialWindowSize,
            Version = 0,
            UserUuid = outbound.Uuid,
            Flow = outbound.Flow,
            Encryption = outbound.Encryption,
            XorMode = outbound.XorMode,
            Seconds = Math.Max(0, outbound.Seconds),
            Padding = outbound.Padding,
            TestSeed = outbound.TestSeed?.ToArray() ?? Array.Empty<uint>(),
            TestPre = Math.Max(0, outbound.TestPre),
            ReverseTag = outbound.ReverseTag,
            ConnectTimeoutSeconds = outbound.ConnectTimeoutSeconds,
            HandshakeTimeoutSeconds = outbound.HandshakeTimeoutSeconds,
            SkipCertificateValidation = outbound.SkipCertificateValidation
        };

    public static RuntimeVmessOutboundOptions CreateVmessOptions(OutboundConfig outbound)
        => ProxyOutboundOptionsCompiler.CompileVmess(CreateRawVmessOptions(outbound));

    private static RuntimeVmessOutboundOptions CreateRawVmessOptions(OutboundConfig outbound)
        => new()
        {
            Tag = outbound.Tag,
            ServerHost = outbound.ServerHost,
            ServerPort = outbound.ServerPort,
            ServerName = outbound.ServerName,
            Fingerprint = outbound.Fingerprint,
            Transport = outbound.Transport,
            TransportSecurity = outbound.TransportSecurity,
            RealityOptions = outbound.RealityOptions ?? RuntimeRealityOptions.Empty,
            WebSocketPath = outbound.WebSocketPath,
            WebSocketHeaders = CloneHeaders(outbound.WebSocketHeaders),
            WebSocketEarlyDataBytes = outbound.WebSocketEarlyDataBytes,
            WebSocketHeartbeatPeriodSeconds = outbound.WebSocketHeartbeatPeriodSeconds,
            ApplicationProtocols = outbound.ApplicationProtocols?.ToArray() ?? Array.Empty<string>(),
            GrpcServiceName = outbound.GrpcServiceName,
            GrpcAuthority = outbound.GrpcAuthority,
            GrpcMultiMode = outbound.GrpcMultiMode,
            GrpcUserAgent = outbound.GrpcUserAgent,
            GrpcIdleTimeoutSeconds = outbound.GrpcIdleTimeoutSeconds,
            GrpcHealthCheckTimeoutSeconds = outbound.GrpcHealthCheckTimeoutSeconds,
            GrpcPermitWithoutStream = outbound.GrpcPermitWithoutStream,
            GrpcInitialWindowSize = outbound.GrpcInitialWindowSize,
            UserUuid = outbound.Uuid,
            Security = outbound.Security,
            AuthenticatedLength = outbound.AuthenticatedLength,
            NoTerminationSignal = outbound.NoTerminationSignal,
            ConnectTimeoutSeconds = outbound.ConnectTimeoutSeconds,
            HandshakeTimeoutSeconds = outbound.HandshakeTimeoutSeconds,
            SkipCertificateValidation = outbound.SkipCertificateValidation
        };

    private static OutboundMultiplexConfig NormalizeMultiplexSettings(OutboundMultiplexConfig? settings)
    {
        var normalized = settings ?? new OutboundMultiplexConfig();
        return normalized with
        {
            Concurrency = normalized.Concurrency,
            XudpConcurrency = normalized.XudpConcurrency,
            XudpProxyUdp443 = OutboundXudpProxyModes.Normalize(normalized.XudpProxyUdp443)
        };
    }

    private static string NormalizeSenderTransport(string protocol, string transport)
        => protocol switch
        {
            OutboundProtocols.Http => HttpOutboundTransports.Normalize(transport),
            OutboundProtocols.Trojan => TrojanOutboundTransports.Normalize(transport),
            OutboundProtocols.Vless => VlessOutboundTransports.Normalize(transport),
            OutboundProtocols.Vmess => VmessOutboundTransports.Normalize(transport),
            _ => NormalizeOptionalValue(transport)
        };

    private static IReadOnlyList<string> NormalizeOutboundApplicationProtocols(
        string protocol,
        string transport,
        string transportSecurity,
        IReadOnlyList<string>? values)
    {
        if (protocol == OutboundProtocols.Http)
        {
            return HttpOutboundTransports.Normalize(transport) switch
            {
                HttpOutboundTransports.Tls => NormalizeStringList(values),
                _ => Array.Empty<string>()
            };
        }

        if (protocol is not (OutboundProtocols.Trojan or OutboundProtocols.Vless or OutboundProtocols.Vmess))
        {
            return NormalizeStringList(values);
        }

        if (!ProxyInternetStackResolver.TryResolve(transport, transportSecurity, out var proxyInternetStack, out _))
        {
            return transport switch
            {
                TrojanOutboundTransports.Tls => NormalizeStringList(values),
                TrojanOutboundTransports.Grpc => ["h2"],
                TrojanOutboundTransports.Wss or TrojanOutboundTransports.HttpUpgradeTls => ["http/1.1"],
                _ => Array.Empty<string>()
            };
        }

        return proxyInternetStack.TransportProtocol switch
        {
            TrojanOutboundTransports.Tcp
                when RuntimeInternetSecurityTypes.IsSecure(proxyInternetStack.SecurityType)
                    => NormalizeStringList(values),
            TrojanOutboundTransports.Grpc => ["h2"],
            TrojanOutboundTransports.Ws or TrojanOutboundTransports.HttpUpgrade
                when RuntimeInternetSecurityTypes.IsSecure(proxyInternetStack.SecurityType)
                    => ["http/1.1"],
            _ => Array.Empty<string>()
        };
    }

    private static string NormalizeViaCidr(string value)
        => string.IsNullOrWhiteSpace(value) ? string.Empty : value.Trim().TrimStart('/');

    private static bool IsPathBasedTransport(string transport)
        => TrojanOutboundTransports.Normalize(transport) is
            TrojanOutboundTransports.Ws or
            TrojanOutboundTransports.Wss or
            TrojanOutboundTransports.HttpUpgrade or
            TrojanOutboundTransports.HttpUpgradeTls;

    private static string NormalizeOutboundWebSocketPath(string value)
    {
        if (string.IsNullOrWhiteSpace(value))
        {
            return "/";
        }

        var normalized = value.Trim();
        return normalized.StartsWith("/", StringComparison.Ordinal) ? normalized : "/" + normalized;
    }

    private static IReadOnlyDictionary<string, string> NormalizeHeaderDictionary(IReadOnlyDictionary<string, string>? headers)
    {
        var normalized = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        if (headers is null)
        {
            return normalized;
        }

        foreach (var (name, value) in headers)
        {
            if (string.IsNullOrWhiteSpace(name) || string.IsNullOrWhiteSpace(value))
            {
                continue;
            }

            normalized[name.Trim()] = value.Trim();
        }

        return normalized;
    }

    private static IReadOnlyDictionary<string, string> CloneHeaders(IReadOnlyDictionary<string, string>? headers)
    {
        if (headers is null)
        {
            return new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        }

        return headers.ToDictionary(
            static pair => pair.Key,
            static pair => pair.Value,
            StringComparer.OrdinalIgnoreCase);
    }

    private static IReadOnlyList<string> NormalizeStringList(IReadOnlyList<string>? values)
        => (values ?? Array.Empty<string>())
            .Where(static value => !string.IsNullOrWhiteSpace(value))
            .Select(static value => value.Trim())
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .ToArray();

    private static IReadOnlyList<uint> NormalizeVlessTestSeed(IReadOnlyList<uint>? values)
    {
        if (values is null || values.Count < 4)
        {
            return Array.Empty<uint>();
        }

        var normalized = new uint[4];
        for (var index = 0; index < normalized.Length; index++)
        {
            normalized[index] = values[index];
        }

        return normalized;
    }

    private static int NormalizePort(int value, int fallback)
        => value is > 0 and <= 65535 ? value : fallback;

    private static int NormalizePositive(int value, int fallback)
        => value > 0 ? value : fallback;

    private static string NormalizeOptionalValue(string? value)
        => string.IsNullOrWhiteSpace(value) ? string.Empty : value.Trim();
}

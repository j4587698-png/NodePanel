using NodePanel.Core.Protocol;

namespace NodePanel.Core.Runtime;

public static class ProxyOutboundOptionsCompiler
{
    public static RuntimeTrojanOutboundOptions CompileTrojan(RuntimeTrojanOutboundOptions options)
    {
        ArgumentNullException.ThrowIfNull(options);

        if (!TryCompileTrojan(options, out var compiled, out var error))
        {
            throw new InvalidOperationException(error);
        }

        return compiled;
    }

    public static RuntimeVlessOutboundOptions CompileVless(RuntimeVlessOutboundOptions options)
    {
        ArgumentNullException.ThrowIfNull(options);

        if (!TryCompileVless(options, out var compiled, out var error))
        {
            throw new InvalidOperationException(error);
        }

        return compiled;
    }

    public static RuntimeVmessOutboundOptions CompileVmess(RuntimeVmessOutboundOptions options)
    {
        ArgumentNullException.ThrowIfNull(options);

        if (!TryCompileVmess(options, out var compiled, out var error))
        {
            throw new InvalidOperationException(error);
        }

        return compiled;
    }

    public static bool TryCompileTrojan(
        RuntimeTrojanOutboundOptions options,
        out RuntimeTrojanOutboundOptions compiled,
        out string? error)
    {
        ArgumentNullException.ThrowIfNull(options);

        if (!TryCompileCommon(
                options.ServerHost,
                options.ServerPort,
                options.Transport,
                options.TransportSecurity,
                options.ServerName,
                options.Fingerprint,
                options.RealityOptions,
                options.WebSocketPath,
                options.WebSocketHeaders,
                options.WebSocketEarlyDataBytes,
                options.WebSocketHeartbeatPeriodSeconds,
                options.SplitHttpHost,
                options.SplitHttpPath,
                options.SplitHttpHeaders,
                options.SplitHttpMode,
                options.SplitHttpNoGrpcHeader,
                options.SplitHttpNoSseHeader,
                options.SplitHttpXPaddingBytes,
                options.SplitHttpXPaddingObfsMode,
                options.SplitHttpXPaddingKey,
                options.SplitHttpXPaddingHeader,
                options.SplitHttpXPaddingPlacement,
                options.SplitHttpXPaddingMethod,
                options.SplitHttpUplinkHttpMethod,
                options.SplitHttpSessionPlacement,
                options.SplitHttpSessionKey,
                options.SplitHttpSeqPlacement,
                options.SplitHttpSeqKey,
                options.SplitHttpUplinkDataPlacement,
                options.SplitHttpUplinkDataKey,
                options.SplitHttpUplinkChunkSize,
                options.SplitHttpScMaxEachPostBytes,
                options.SplitHttpScMinPostsIntervalMs,
                options.SplitHttpScMaxBufferedPosts,
                options.SplitHttpScStreamUpServerSecs,
                options.SplitHttpServerMaxHeaderBytes,
                options.SplitHttpXmux,
                options.SplitHttpDownloadSettings,
                options.SkipCertificateValidation,
                options.ApplicationProtocols,
                options.QuicOptions,
                options.GrpcServiceName,
                options.GrpcAuthority,
                options.GrpcMultiMode,
                options.GrpcUserAgent,
                options.GrpcIdleTimeoutSeconds,
                options.GrpcHealthCheckTimeoutSeconds,
                options.GrpcPermitWithoutStream,
                options.GrpcInitialWindowSize,
                options.ConnectTimeoutSeconds,
                options.HandshakeTimeoutSeconds,
                "Trojan",
                out var common,
                out error))
        {
            compiled = default!;
            return false;
        }

        var password = options.Password?.Trim() ?? string.Empty;
        if (password.Length == 0)
        {
            compiled = default!;
            error = "Trojan password is not specified.";
            return false;
        }

        compiled = new RuntimeTrojanOutboundOptions
        {
            Tag = options.Tag?.Trim() ?? string.Empty,
            ServerHost = common.ServerHost,
            ServerPort = common.ServerPort,
            ServerName = common.ServerName,
            Fingerprint = common.Fingerprint,
            Transport = common.Transport,
            TransportSecurity = common.TransportSecurity,
            RealityOptions = common.RealityOptions,
            WebSocketPath = common.WebSocketPath,
            WebSocketHeaders = common.WebSocketHeaders,
            WebSocketEarlyDataBytes = common.WebSocketEarlyDataBytes,
            WebSocketHeartbeatPeriodSeconds = common.WebSocketHeartbeatPeriodSeconds,
            SplitHttpHost = common.SplitHttpHost,
            SplitHttpPath = common.SplitHttpPath,
            SplitHttpHeaders = common.SplitHttpHeaders,
            SplitHttpMode = common.SplitHttpMode,
            SplitHttpNoGrpcHeader = common.SplitHttpNoGrpcHeader,
            SplitHttpNoSseHeader = common.SplitHttpNoSseHeader,
            SplitHttpXPaddingBytes = common.SplitHttpXPaddingBytes,
            SplitHttpXPaddingObfsMode = common.SplitHttpXPaddingObfsMode,
            SplitHttpXPaddingKey = common.SplitHttpXPaddingKey,
            SplitHttpXPaddingHeader = common.SplitHttpXPaddingHeader,
            SplitHttpXPaddingPlacement = common.SplitHttpXPaddingPlacement,
            SplitHttpXPaddingMethod = common.SplitHttpXPaddingMethod,
            SplitHttpUplinkHttpMethod = common.SplitHttpUplinkHttpMethod,
            SplitHttpSessionPlacement = common.SplitHttpSessionPlacement,
            SplitHttpSessionKey = common.SplitHttpSessionKey,
            SplitHttpSeqPlacement = common.SplitHttpSeqPlacement,
            SplitHttpSeqKey = common.SplitHttpSeqKey,
            SplitHttpUplinkDataPlacement = common.SplitHttpUplinkDataPlacement,
            SplitHttpUplinkDataKey = common.SplitHttpUplinkDataKey,
            SplitHttpUplinkChunkSize = common.SplitHttpUplinkChunkSize,
            SplitHttpScMaxEachPostBytes = common.SplitHttpScMaxEachPostBytes,
            SplitHttpScMinPostsIntervalMs = common.SplitHttpScMinPostsIntervalMs,
            SplitHttpScMaxBufferedPosts = common.SplitHttpScMaxBufferedPosts,
            SplitHttpScStreamUpServerSecs = common.SplitHttpScStreamUpServerSecs,
            SplitHttpServerMaxHeaderBytes = common.SplitHttpServerMaxHeaderBytes,
            SplitHttpXmux = common.SplitHttpXmux,
            SplitHttpDownloadSettings = common.SplitHttpDownloadSettings,
            ApplicationProtocols = common.ApplicationProtocols,
            QuicOptions = common.QuicOptions,
            GrpcServiceName = common.GrpcServiceName,
            GrpcAuthority = common.GrpcAuthority,
            GrpcMultiMode = common.GrpcMultiMode,
            GrpcUserAgent = common.GrpcUserAgent,
            GrpcIdleTimeoutSeconds = common.GrpcIdleTimeoutSeconds,
            GrpcHealthCheckTimeoutSeconds = common.GrpcHealthCheckTimeoutSeconds,
            GrpcPermitWithoutStream = common.GrpcPermitWithoutStream,
            GrpcInitialWindowSize = common.GrpcInitialWindowSize,
            Password = password,
            ConnectTimeoutSeconds = common.ConnectTimeoutSeconds,
            HandshakeTimeoutSeconds = common.HandshakeTimeoutSeconds,
            EnableTlsSessionResumption = options.EnableTlsSessionResumption,
            SkipCertificateValidation = options.SkipCertificateValidation
        };
        error = null;
        return true;
    }

    public static bool TryCompileVless(
        RuntimeVlessOutboundOptions options,
        out RuntimeVlessOutboundOptions compiled,
        out string? error)
    {
        ArgumentNullException.ThrowIfNull(options);

        if (!TryCompileCommon(
                options.ServerHost,
                options.ServerPort,
                options.Transport,
                options.TransportSecurity,
                options.ServerName,
                options.Fingerprint,
                options.RealityOptions,
                options.WebSocketPath,
                options.WebSocketHeaders,
                options.WebSocketEarlyDataBytes,
                options.WebSocketHeartbeatPeriodSeconds,
                options.SplitHttpHost,
                options.SplitHttpPath,
                options.SplitHttpHeaders,
                options.SplitHttpMode,
                options.SplitHttpNoGrpcHeader,
                options.SplitHttpNoSseHeader,
                options.SplitHttpXPaddingBytes,
                options.SplitHttpXPaddingObfsMode,
                options.SplitHttpXPaddingKey,
                options.SplitHttpXPaddingHeader,
                options.SplitHttpXPaddingPlacement,
                options.SplitHttpXPaddingMethod,
                options.SplitHttpUplinkHttpMethod,
                options.SplitHttpSessionPlacement,
                options.SplitHttpSessionKey,
                options.SplitHttpSeqPlacement,
                options.SplitHttpSeqKey,
                options.SplitHttpUplinkDataPlacement,
                options.SplitHttpUplinkDataKey,
                options.SplitHttpUplinkChunkSize,
                options.SplitHttpScMaxEachPostBytes,
                options.SplitHttpScMinPostsIntervalMs,
                options.SplitHttpScMaxBufferedPosts,
                options.SplitHttpScStreamUpServerSecs,
                options.SplitHttpServerMaxHeaderBytes,
                options.SplitHttpXmux,
                options.SplitHttpDownloadSettings,
                options.SkipCertificateValidation,
                options.ApplicationProtocols,
                options.QuicOptions,
                options.GrpcServiceName,
                options.GrpcAuthority,
                options.GrpcMultiMode,
                options.GrpcUserAgent,
                options.GrpcIdleTimeoutSeconds,
                options.GrpcHealthCheckTimeoutSeconds,
                options.GrpcPermitWithoutStream,
                options.GrpcInitialWindowSize,
                options.ConnectTimeoutSeconds,
                options.HandshakeTimeoutSeconds,
                "VLESS",
                out var common,
                out error))
        {
            compiled = default!;
            return false;
        }

        if (!ProtocolUuid.TryNormalize(options.UserUuid, out var normalizedUuid))
        {
            compiled = default!;
            error = "VLESS user UUID is invalid.";
            return false;
        }

        var normalizedFlow = VlessFlowTypes.Normalize(options.Flow);
        if (!VlessFlowTypes.IsSupported(normalizedFlow))
        {
            compiled = default!;
            error = $"VLESS flow does not support '{options.Flow?.Trim() ?? string.Empty}'.";
            return false;
        }

        var normalizedEncryption = VlessTransportEncryption.NormalizeEncryption(options.Encryption);
        var normalizedPadding = options.Padding?.Trim() ?? string.Empty;
        if (VlessTransportEncryption.IsEnabled(normalizedEncryption) &&
            common.WebSocketEarlyDataBytes > 0)
        {
            compiled = default!;
            error = "VLESS transport encryption does not support websocket early-data.";
            return false;
        }

        if (!VlessTransportEncryption.TryValidateConfiguration(normalizedEncryption, normalizedPadding, out error))
        {
            compiled = default!;
            return false;
        }

        compiled = new RuntimeVlessOutboundOptions
        {
            Tag = options.Tag?.Trim() ?? string.Empty,
            ServerHost = common.ServerHost,
            ServerPort = common.ServerPort,
            ServerName = common.ServerName,
            Fingerprint = common.Fingerprint,
            Transport = common.Transport,
            TransportSecurity = common.TransportSecurity,
            RealityOptions = common.RealityOptions,
            WebSocketPath = common.WebSocketPath,
            WebSocketHeaders = common.WebSocketHeaders,
            WebSocketEarlyDataBytes = common.WebSocketEarlyDataBytes,
            WebSocketHeartbeatPeriodSeconds = common.WebSocketHeartbeatPeriodSeconds,
            SplitHttpHost = common.SplitHttpHost,
            SplitHttpPath = common.SplitHttpPath,
            SplitHttpHeaders = common.SplitHttpHeaders,
            SplitHttpMode = common.SplitHttpMode,
            SplitHttpNoGrpcHeader = common.SplitHttpNoGrpcHeader,
            SplitHttpNoSseHeader = common.SplitHttpNoSseHeader,
            SplitHttpXPaddingBytes = common.SplitHttpXPaddingBytes,
            SplitHttpXPaddingObfsMode = common.SplitHttpXPaddingObfsMode,
            SplitHttpXPaddingKey = common.SplitHttpXPaddingKey,
            SplitHttpXPaddingHeader = common.SplitHttpXPaddingHeader,
            SplitHttpXPaddingPlacement = common.SplitHttpXPaddingPlacement,
            SplitHttpXPaddingMethod = common.SplitHttpXPaddingMethod,
            SplitHttpUplinkHttpMethod = common.SplitHttpUplinkHttpMethod,
            SplitHttpSessionPlacement = common.SplitHttpSessionPlacement,
            SplitHttpSessionKey = common.SplitHttpSessionKey,
            SplitHttpSeqPlacement = common.SplitHttpSeqPlacement,
            SplitHttpSeqKey = common.SplitHttpSeqKey,
            SplitHttpUplinkDataPlacement = common.SplitHttpUplinkDataPlacement,
            SplitHttpUplinkDataKey = common.SplitHttpUplinkDataKey,
            SplitHttpUplinkChunkSize = common.SplitHttpUplinkChunkSize,
            SplitHttpScMaxEachPostBytes = common.SplitHttpScMaxEachPostBytes,
            SplitHttpScMinPostsIntervalMs = common.SplitHttpScMinPostsIntervalMs,
            SplitHttpScMaxBufferedPosts = common.SplitHttpScMaxBufferedPosts,
            SplitHttpScStreamUpServerSecs = common.SplitHttpScStreamUpServerSecs,
            SplitHttpServerMaxHeaderBytes = common.SplitHttpServerMaxHeaderBytes,
            SplitHttpXmux = common.SplitHttpXmux,
            SplitHttpDownloadSettings = common.SplitHttpDownloadSettings,
            ApplicationProtocols = common.ApplicationProtocols,
            QuicOptions = common.QuicOptions,
            GrpcServiceName = common.GrpcServiceName,
            GrpcAuthority = common.GrpcAuthority,
            GrpcMultiMode = common.GrpcMultiMode,
            GrpcUserAgent = common.GrpcUserAgent,
            GrpcIdleTimeoutSeconds = common.GrpcIdleTimeoutSeconds,
            GrpcHealthCheckTimeoutSeconds = common.GrpcHealthCheckTimeoutSeconds,
            GrpcPermitWithoutStream = common.GrpcPermitWithoutStream,
            GrpcInitialWindowSize = common.GrpcInitialWindowSize,
            Version = options.Version,
            UserUuid = normalizedUuid,
            Flow = normalizedFlow,
            Encryption = normalizedEncryption,
            XorMode = options.XorMode,
            Seconds = Math.Max(0, options.Seconds),
            Padding = normalizedPadding,
            TestSeed = NormalizeVlessTestSeed(options.TestSeed),
            TestPre = Math.Max(0, options.TestPre),
            ReverseTag = NormalizeOptionalValue(options.ReverseTag),
            ConnectTimeoutSeconds = common.ConnectTimeoutSeconds,
            HandshakeTimeoutSeconds = common.HandshakeTimeoutSeconds,
            EnableTlsSessionResumption = options.EnableTlsSessionResumption,
            SkipCertificateValidation = options.SkipCertificateValidation
        };
        error = null;
        return true;
    }

    public static bool TryCompileVmess(
        RuntimeVmessOutboundOptions options,
        out RuntimeVmessOutboundOptions compiled,
        out string? error)
    {
        ArgumentNullException.ThrowIfNull(options);

        if (!TryCompileCommon(
                options.ServerHost,
                options.ServerPort,
                options.Transport,
                options.TransportSecurity,
                options.ServerName,
                options.Fingerprint,
                options.RealityOptions,
                options.WebSocketPath,
                options.WebSocketHeaders,
                options.WebSocketEarlyDataBytes,
                options.WebSocketHeartbeatPeriodSeconds,
                options.SplitHttpHost,
                options.SplitHttpPath,
                options.SplitHttpHeaders,
                options.SplitHttpMode,
                options.SplitHttpNoGrpcHeader,
                options.SplitHttpNoSseHeader,
                options.SplitHttpXPaddingBytes,
                options.SplitHttpXPaddingObfsMode,
                options.SplitHttpXPaddingKey,
                options.SplitHttpXPaddingHeader,
                options.SplitHttpXPaddingPlacement,
                options.SplitHttpXPaddingMethod,
                options.SplitHttpUplinkHttpMethod,
                options.SplitHttpSessionPlacement,
                options.SplitHttpSessionKey,
                options.SplitHttpSeqPlacement,
                options.SplitHttpSeqKey,
                options.SplitHttpUplinkDataPlacement,
                options.SplitHttpUplinkDataKey,
                options.SplitHttpUplinkChunkSize,
                options.SplitHttpScMaxEachPostBytes,
                options.SplitHttpScMinPostsIntervalMs,
                options.SplitHttpScMaxBufferedPosts,
                options.SplitHttpScStreamUpServerSecs,
                options.SplitHttpServerMaxHeaderBytes,
                options.SplitHttpXmux,
                options.SplitHttpDownloadSettings,
                options.SkipCertificateValidation,
                options.ApplicationProtocols,
                options.QuicOptions,
                options.GrpcServiceName,
                options.GrpcAuthority,
                options.GrpcMultiMode,
                options.GrpcUserAgent,
                options.GrpcIdleTimeoutSeconds,
                options.GrpcHealthCheckTimeoutSeconds,
                options.GrpcPermitWithoutStream,
                options.GrpcInitialWindowSize,
                options.ConnectTimeoutSeconds,
                options.HandshakeTimeoutSeconds,
                "VMess",
                out var common,
                out error))
        {
            compiled = default!;
            return false;
        }

        if (!ProtocolUuid.TryNormalize(options.UserUuid, out var normalizedUuid))
        {
            compiled = default!;
            error = "VMess user UUID is invalid.";
            return false;
        }

        compiled = new RuntimeVmessOutboundOptions
        {
            Tag = options.Tag?.Trim() ?? string.Empty,
            ServerHost = common.ServerHost,
            ServerPort = common.ServerPort,
            ServerName = common.ServerName,
            Fingerprint = common.Fingerprint,
            Transport = common.Transport,
            TransportSecurity = common.TransportSecurity,
            RealityOptions = common.RealityOptions,
            WebSocketPath = common.WebSocketPath,
            WebSocketHeaders = common.WebSocketHeaders,
            WebSocketEarlyDataBytes = common.WebSocketEarlyDataBytes,
            WebSocketHeartbeatPeriodSeconds = common.WebSocketHeartbeatPeriodSeconds,
            SplitHttpHost = common.SplitHttpHost,
            SplitHttpPath = common.SplitHttpPath,
            SplitHttpHeaders = common.SplitHttpHeaders,
            SplitHttpMode = common.SplitHttpMode,
            SplitHttpNoGrpcHeader = common.SplitHttpNoGrpcHeader,
            SplitHttpNoSseHeader = common.SplitHttpNoSseHeader,
            SplitHttpXPaddingBytes = common.SplitHttpXPaddingBytes,
            SplitHttpXPaddingObfsMode = common.SplitHttpXPaddingObfsMode,
            SplitHttpXPaddingKey = common.SplitHttpXPaddingKey,
            SplitHttpXPaddingHeader = common.SplitHttpXPaddingHeader,
            SplitHttpXPaddingPlacement = common.SplitHttpXPaddingPlacement,
            SplitHttpXPaddingMethod = common.SplitHttpXPaddingMethod,
            SplitHttpUplinkHttpMethod = common.SplitHttpUplinkHttpMethod,
            SplitHttpSessionPlacement = common.SplitHttpSessionPlacement,
            SplitHttpSessionKey = common.SplitHttpSessionKey,
            SplitHttpSeqPlacement = common.SplitHttpSeqPlacement,
            SplitHttpSeqKey = common.SplitHttpSeqKey,
            SplitHttpUplinkDataPlacement = common.SplitHttpUplinkDataPlacement,
            SplitHttpUplinkDataKey = common.SplitHttpUplinkDataKey,
            SplitHttpUplinkChunkSize = common.SplitHttpUplinkChunkSize,
            SplitHttpScMaxEachPostBytes = common.SplitHttpScMaxEachPostBytes,
            SplitHttpScMinPostsIntervalMs = common.SplitHttpScMinPostsIntervalMs,
            SplitHttpScMaxBufferedPosts = common.SplitHttpScMaxBufferedPosts,
            SplitHttpScStreamUpServerSecs = common.SplitHttpScStreamUpServerSecs,
            SplitHttpServerMaxHeaderBytes = common.SplitHttpServerMaxHeaderBytes,
            SplitHttpXmux = common.SplitHttpXmux,
            SplitHttpDownloadSettings = common.SplitHttpDownloadSettings,
            ApplicationProtocols = common.ApplicationProtocols,
            QuicOptions = common.QuicOptions,
            GrpcServiceName = common.GrpcServiceName,
            GrpcAuthority = common.GrpcAuthority,
            GrpcMultiMode = common.GrpcMultiMode,
            GrpcUserAgent = common.GrpcUserAgent,
            GrpcIdleTimeoutSeconds = common.GrpcIdleTimeoutSeconds,
            GrpcHealthCheckTimeoutSeconds = common.GrpcHealthCheckTimeoutSeconds,
            GrpcPermitWithoutStream = common.GrpcPermitWithoutStream,
            GrpcInitialWindowSize = common.GrpcInitialWindowSize,
            UserUuid = normalizedUuid,
            Security = VmessOutboundSecurityTypes.Normalize(options.Security),
            AuthenticatedLength = options.AuthenticatedLength,
            NoTerminationSignal = options.NoTerminationSignal,
            ConnectTimeoutSeconds = common.ConnectTimeoutSeconds,
            HandshakeTimeoutSeconds = common.HandshakeTimeoutSeconds,
            EnableTlsSessionResumption = options.EnableTlsSessionResumption,
            SkipCertificateValidation = options.SkipCertificateValidation
        };
        error = null;
        return true;
    }

    private static bool TryCompileCommon(
        string serverHost,
        int serverPort,
        string transport,
        string transportSecurity,
        string serverName,
        string fingerprint,
        RuntimeRealityOptions realityOptions,
        string webSocketPath,
        IReadOnlyDictionary<string, string> webSocketHeaders,
        int webSocketEarlyDataBytes,
        int webSocketHeartbeatPeriodSeconds,
        string splitHttpHost,
        string splitHttpPath,
        IReadOnlyDictionary<string, string> splitHttpHeaders,
        string splitHttpMode,
        bool splitHttpNoGrpcHeader,
        bool splitHttpNoSseHeader,
        RuntimeInt32Range splitHttpXPaddingBytes,
        bool splitHttpXPaddingObfsMode,
        string splitHttpXPaddingKey,
        string splitHttpXPaddingHeader,
        string splitHttpXPaddingPlacement,
        string splitHttpXPaddingMethod,
        string splitHttpUplinkHttpMethod,
        string splitHttpSessionPlacement,
        string splitHttpSessionKey,
        string splitHttpSeqPlacement,
        string splitHttpSeqKey,
        string splitHttpUplinkDataPlacement,
        string splitHttpUplinkDataKey,
        RuntimeInt32Range splitHttpUplinkChunkSize,
        RuntimeInt32Range splitHttpScMaxEachPostBytes,
        RuntimeInt32Range splitHttpScMinPostsIntervalMs,
        int splitHttpScMaxBufferedPosts,
        RuntimeInt32Range splitHttpScStreamUpServerSecs,
        int splitHttpServerMaxHeaderBytes,
        RuntimeSplitHttpXmuxOptions splitHttpXmux,
        RuntimeSplitHttpDownloadOptions? splitHttpDownloadSettings,
        bool skipCertificateValidation,
        IReadOnlyList<string> applicationProtocols,
        RuntimeQuicOptions quicOptions,
        string grpcServiceName,
        string grpcAuthority,
        bool grpcMultiMode,
        string grpcUserAgent,
        int grpcIdleTimeoutSeconds,
        int grpcHealthCheckTimeoutSeconds,
        bool grpcPermitWithoutStream,
        int grpcInitialWindowSize,
        int connectTimeoutSeconds,
        int handshakeTimeoutSeconds,
        string protocolName,
        out CompiledProxyCommon common,
        out string? error)
    {
        var normalizedHost = serverHost?.Trim() ?? string.Empty;
        if (normalizedHost.Length == 0)
        {
            common = default!;
            error = protocolName switch
            {
                "VLESS" => "VLESS vnext: \"address\" is not set",
                "VMess" => "VMess vnext: \"address\" is not set",
                _ => "Trojan server address is not set."
            };
            return false;
        }

        var hasValidPort = protocolName switch
        {
            "Trojan" => serverPort is > 0 and <= 65535,
            _ => serverPort is >= 0 and <= 65535
        };

        if (!hasValidPort)
        {
            common = default!;
            error = protocolName switch
            {
                "VLESS" => "Invalid VLESS port.",
                "VMess" => "Invalid VMess port.",
                _ => "Invalid Trojan port."
            };
            return false;
        }

        if (!ProxyInternetStackResolver.TryResolve(
                transport,
                transportSecurity,
                out var internetStack,
                out error))
        {
            common = default!;
            return false;
        }

        var normalizedRealityOptions = RuntimeRealityOptions.Normalize(realityOptions);
        if (string.Equals(internetStack.SecurityType, RuntimeInternetSecurityTypes.Reality, StringComparison.Ordinal) &&
            !normalizedRealityOptions.TryValidateForReality(out normalizedRealityOptions, out error))
        {
            common = default!;
            return false;
        }

        var normalizedFingerprint = string.Empty;
        if (string.Equals(internetStack.SecurityType, RuntimeInternetSecurityTypes.Tls, StringComparison.Ordinal) &&
            !TryNormalizeNormalFingerprint(fingerprint, out normalizedFingerprint, out error))
        {
            common = default!;
            return false;
        }

        var normalizedSplitHttpHost = string.Empty;
        var normalizedSplitHttpPath = "/";
        IReadOnlyDictionary<string, string> normalizedSplitHttpHeaders =
            new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        var normalizedSplitHttpMode = string.Empty;
        var normalizedSplitHttpNoGrpcHeader = false;
        var normalizedSplitHttpNoSseHeader = false;
        var normalizedSplitHttpXPaddingBytes = RuntimeInt32Range.Empty;
        var normalizedSplitHttpXPaddingObfsMode = false;
        var normalizedSplitHttpXPaddingKey = string.Empty;
        var normalizedSplitHttpXPaddingHeader = string.Empty;
        var normalizedSplitHttpXPaddingPlacement = string.Empty;
        var normalizedSplitHttpXPaddingMethod = string.Empty;
        var normalizedSplitHttpUplinkHttpMethod = string.Empty;
        var normalizedSplitHttpSessionPlacement = string.Empty;
        var normalizedSplitHttpSessionKey = string.Empty;
        var normalizedSplitHttpSeqPlacement = string.Empty;
        var normalizedSplitHttpSeqKey = string.Empty;
        var normalizedSplitHttpUplinkDataPlacement = string.Empty;
        var normalizedSplitHttpUplinkDataKey = string.Empty;
        var normalizedSplitHttpUplinkChunkSize = RuntimeInt32Range.Empty;
        var normalizedSplitHttpScMaxEachPostBytes = RuntimeInt32Range.Empty;
        var normalizedSplitHttpScMinPostsIntervalMs = RuntimeInt32Range.Empty;
        var normalizedSplitHttpScMaxBufferedPosts = 0;
        var normalizedSplitHttpScStreamUpServerSecs = RuntimeInt32Range.Empty;
        var normalizedSplitHttpServerMaxHeaderBytes = 0;
        var normalizedSplitHttpXmux = RuntimeSplitHttpXmuxOptions.Empty;
        RuntimeSplitHttpDownloadOptions? normalizedSplitHttpDownloadSettings = null;

        var isSplitHttpTransport = string.Equals(
            internetStack.TransportProtocol,
            RuntimeInternetTransportProtocols.SplitHttp,
            StringComparison.Ordinal);
        var usesSplitHttpLikeRequestSettings = isSplitHttpTransport ||
                                               string.Equals(
                                                   internetStack.TransportProtocol,
                                                   RuntimeInternetTransportProtocols.HttpUpgrade,
                                                   StringComparison.Ordinal);

        if (usesSplitHttpLikeRequestSettings)
        {
            normalizedSplitHttpHost = splitHttpHost?.Trim() ?? string.Empty;
            normalizedSplitHttpPath = isSplitHttpTransport
                ? NormalizeSenderSplitHttpPath(splitHttpPath)
                : NormalizeSenderHttpUpgradePath(splitHttpPath);
            normalizedSplitHttpHeaders = NormalizeHeaders(splitHttpHeaders);
            if (normalizedSplitHttpHeaders.ContainsKey("Host"))
            {
                common = default!;
                error = "\"headers\" can't contain \"host\"";
                return false;
            }
        }

        if (isSplitHttpTransport)
        {
            if (!TryNormalizeSplitHttpMode(splitHttpMode, out normalizedSplitHttpMode, out error))
            {
                common = default!;
                return false;
            }

            normalizedSplitHttpNoGrpcHeader = splitHttpNoGrpcHeader;
            normalizedSplitHttpNoSseHeader = splitHttpNoSseHeader;
            if (!TryNormalizeSplitHttpXPaddingBytes(
                    splitHttpXPaddingBytes,
                    out normalizedSplitHttpXPaddingBytes,
                    out error))
            {
                common = default!;
                return false;
            }

            normalizedSplitHttpXPaddingObfsMode = splitHttpXPaddingObfsMode;
            normalizedSplitHttpXPaddingKey = NormalizeSplitHttpXPaddingKey(splitHttpXPaddingKey);
            normalizedSplitHttpXPaddingHeader = NormalizeSplitHttpXPaddingHeader(splitHttpXPaddingHeader);

            if (!TryNormalizeSplitHttpXPaddingPlacement(
                    splitHttpXPaddingPlacement,
                    out normalizedSplitHttpXPaddingPlacement,
                    out error))
            {
                common = default!;
                return false;
            }

            if (!TryNormalizeSplitHttpXPaddingMethod(
                    splitHttpXPaddingMethod,
                    out normalizedSplitHttpXPaddingMethod,
                    out error))
            {
                common = default!;
                return false;
            }

            normalizedSplitHttpUplinkHttpMethod = NormalizeSplitHttpUplinkHttpMethod(splitHttpUplinkHttpMethod);
            if (string.Equals(normalizedSplitHttpUplinkHttpMethod, "GET", StringComparison.Ordinal) &&
                !string.Equals(normalizedSplitHttpMode, "packet-up", StringComparison.Ordinal))
            {
                common = default!;
                error = "SplitHTTP uplinkHTTPMethod can be GET only in packet-up mode.";
                return false;
            }

            if (!TryNormalizeSplitHttpSessionPlacement(
                    splitHttpSessionPlacement,
                    out normalizedSplitHttpSessionPlacement,
                    out error))
            {
                common = default!;
                return false;
            }

            normalizedSplitHttpSessionKey = NormalizeSplitHttpSessionKey(
                normalizedSplitHttpSessionPlacement,
                splitHttpSessionKey);

            if (!TryNormalizeSplitHttpSeqPlacement(
                    splitHttpSeqPlacement,
                    out normalizedSplitHttpSeqPlacement,
                    out error))
            {
                common = default!;
                return false;
            }

            normalizedSplitHttpSeqKey = NormalizeSplitHttpSeqKey(
                normalizedSplitHttpSeqPlacement,
                splitHttpSeqKey);

            if (!TryNormalizeSplitHttpUplinkDataPlacement(
                    splitHttpUplinkDataPlacement,
                    out normalizedSplitHttpUplinkDataPlacement,
                    out error))
            {
                common = default!;
                return false;
            }

            if ((string.Equals(normalizedSplitHttpUplinkDataPlacement, "header", StringComparison.Ordinal) ||
                 string.Equals(normalizedSplitHttpUplinkDataPlacement, "cookie", StringComparison.Ordinal)) &&
                !string.Equals(normalizedSplitHttpMode, "packet-up", StringComparison.Ordinal))
            {
                common = default!;
                error = "SplitHTTP uplinkDataPlacement can be " + normalizedSplitHttpUplinkDataPlacement + " only in packet-up mode.";
                return false;
            }

            normalizedSplitHttpUplinkDataKey = NormalizeSplitHttpUplinkDataKey(
                normalizedSplitHttpUplinkDataPlacement,
                splitHttpUplinkDataKey);
            normalizedSplitHttpScMaxEachPostBytes = NormalizeSplitHttpRange(splitHttpScMaxEachPostBytes);
            normalizedSplitHttpUplinkChunkSize = NormalizeSplitHttpRange(splitHttpUplinkChunkSize);
            normalizedSplitHttpScMinPostsIntervalMs = NormalizeSplitHttpRange(splitHttpScMinPostsIntervalMs);
            normalizedSplitHttpScMaxBufferedPosts = splitHttpScMaxBufferedPosts;
            normalizedSplitHttpScStreamUpServerSecs = NormalizeSplitHttpRange(splitHttpScStreamUpServerSecs);
            if (!TryNormalizeSplitHttpServerMaxHeaderBytes(
                    splitHttpServerMaxHeaderBytes,
                    out normalizedSplitHttpServerMaxHeaderBytes,
                    out error))
            {
                common = default!;
                return false;
            }
            if (!RuntimeSplitHttpXmuxNormalizer.TryNormalize(
                    splitHttpXmux,
                    out normalizedSplitHttpXmux,
                    out error))
            {
                common = default!;
                return false;
            }

            if (!TryNormalizeSplitHttpDownloadSettings(
                    splitHttpDownloadSettings,
                    normalizedHost,
                    serverPort,
                    serverName?.Trim() ?? string.Empty,
                    normalizedFingerprint,
                    internetStack.SecurityType,
                    normalizedRealityOptions,
                    normalizedSplitHttpHost,
                    normalizedSplitHttpPath,
                    normalizedSplitHttpHeaders,
                    connectTimeoutSeconds,
                    handshakeTimeoutSeconds,
                    skipCertificateValidation,
                    out normalizedSplitHttpDownloadSettings,
                    out error))
            {
                common = default!;
                return false;
            }

            if (normalizedSplitHttpDownloadSettings is not null &&
                string.Equals(normalizedSplitHttpMode, "stream-one", StringComparison.Ordinal))
            {
                common = default!;
                error = "SplitHTTP downloadSettings cannot be used in stream-one mode.";
                return false;
            }
        }

        common = new CompiledProxyCommon
        {
            ServerHost = normalizedHost,
            ServerPort = serverPort,
            ServerName = serverName?.Trim() ?? string.Empty,
            Fingerprint = normalizedFingerprint,
            Transport = internetStack.Transport,
            TransportSecurity = internetStack.SecurityType,
            RealityOptions = normalizedRealityOptions,
            WebSocketPath = NormalizeSenderWebSocketPath(webSocketPath),
            WebSocketHeaders = NormalizeHeaders(webSocketHeaders),
            WebSocketEarlyDataBytes = Math.Max(0, webSocketEarlyDataBytes),
            WebSocketHeartbeatPeriodSeconds = Math.Max(0, webSocketHeartbeatPeriodSeconds),
            SplitHttpHost = normalizedSplitHttpHost,
            SplitHttpPath = normalizedSplitHttpPath,
            SplitHttpHeaders = normalizedSplitHttpHeaders,
            SplitHttpMode = normalizedSplitHttpMode,
            SplitHttpNoGrpcHeader = normalizedSplitHttpNoGrpcHeader,
            SplitHttpNoSseHeader = normalizedSplitHttpNoSseHeader,
            SplitHttpXPaddingBytes = normalizedSplitHttpXPaddingBytes,
            SplitHttpXPaddingObfsMode = normalizedSplitHttpXPaddingObfsMode,
            SplitHttpXPaddingKey = normalizedSplitHttpXPaddingKey,
            SplitHttpXPaddingHeader = normalizedSplitHttpXPaddingHeader,
            SplitHttpXPaddingPlacement = normalizedSplitHttpXPaddingPlacement,
            SplitHttpXPaddingMethod = normalizedSplitHttpXPaddingMethod,
            SplitHttpUplinkHttpMethod = normalizedSplitHttpUplinkHttpMethod,
            SplitHttpSessionPlacement = normalizedSplitHttpSessionPlacement,
            SplitHttpSessionKey = normalizedSplitHttpSessionKey,
            SplitHttpSeqPlacement = normalizedSplitHttpSeqPlacement,
            SplitHttpSeqKey = normalizedSplitHttpSeqKey,
            SplitHttpUplinkDataPlacement = normalizedSplitHttpUplinkDataPlacement,
            SplitHttpUplinkDataKey = normalizedSplitHttpUplinkDataKey,
            SplitHttpUplinkChunkSize = normalizedSplitHttpUplinkChunkSize,
            SplitHttpScMaxEachPostBytes = normalizedSplitHttpScMaxEachPostBytes,
            SplitHttpScMinPostsIntervalMs = normalizedSplitHttpScMinPostsIntervalMs,
            SplitHttpScMaxBufferedPosts = normalizedSplitHttpScMaxBufferedPosts,
            SplitHttpScStreamUpServerSecs = normalizedSplitHttpScStreamUpServerSecs,
            SplitHttpServerMaxHeaderBytes = normalizedSplitHttpServerMaxHeaderBytes,
            SplitHttpXmux = normalizedSplitHttpXmux,
            SplitHttpDownloadSettings = normalizedSplitHttpDownloadSettings,
            ApplicationProtocols = NormalizeSenderApplicationProtocols(internetStack, applicationProtocols),
            QuicOptions = NormalizeQuicOptions(quicOptions),
            GrpcServiceName = RuntimeGrpcUtilities.NormalizeServiceName(grpcServiceName),
            GrpcAuthority = RuntimeGrpcUtilities.NormalizeAuthority(grpcAuthority),
            GrpcMultiMode = internetStack.TransportProtocol == RuntimeInternetTransportProtocols.Grpc && grpcMultiMode,
            GrpcUserAgent = RuntimeGrpcUtilities.NormalizeUserAgent(grpcUserAgent),
            GrpcIdleTimeoutSeconds = internetStack.TransportProtocol == RuntimeInternetTransportProtocols.Grpc
                ? Math.Max(0, grpcIdleTimeoutSeconds)
                : 0,
            GrpcHealthCheckTimeoutSeconds = internetStack.TransportProtocol == RuntimeInternetTransportProtocols.Grpc
                ? Math.Max(0, grpcHealthCheckTimeoutSeconds)
                : 0,
            GrpcPermitWithoutStream = internetStack.TransportProtocol == RuntimeInternetTransportProtocols.Grpc && grpcPermitWithoutStream,
            GrpcInitialWindowSize = internetStack.TransportProtocol == RuntimeInternetTransportProtocols.Grpc
                ? Math.Max(0, grpcInitialWindowSize)
                : 0,
            ConnectTimeoutSeconds = Math.Max(0, connectTimeoutSeconds),
            HandshakeTimeoutSeconds = Math.Max(0, handshakeTimeoutSeconds)
        };
        error = null;
        return true;
    }

    private static IReadOnlyDictionary<string, string> NormalizeHeaders(IReadOnlyDictionary<string, string> headers)
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

    private static IReadOnlyList<string> NormalizeApplicationProtocols(IReadOnlyList<string> values)
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

    private static string NormalizeOptionalValue(string? value)
        => string.IsNullOrWhiteSpace(value) ? string.Empty : value.Trim();

    private static IReadOnlyList<string> NormalizeSenderApplicationProtocols(
        ProxyInternetStack stack,
        IReadOnlyList<string> values)
        => stack.TransportProtocol switch
        {
            RuntimeInternetTransportProtocols.Tcp
                when RuntimeInternetSecurityTypes.IsSecure(stack.SecurityType)
                    => NormalizeApplicationProtocols(values),
            RuntimeInternetTransportProtocols.Mkcp
                when RuntimeInternetSecurityTypes.IsSecure(stack.SecurityType)
                    => NormalizeApplicationProtocols(values),
            RuntimeInternetTransportProtocols.Grpc => ["h2"],
            RuntimeInternetTransportProtocols.SplitHttp
                when RuntimeInternetSecurityTypes.IsSecure(stack.SecurityType)
                    => NormalizeSplitHttpApplicationProtocols(values),
            RuntimeInternetTransportProtocols.Ws or RuntimeInternetTransportProtocols.HttpUpgrade
                when RuntimeInternetSecurityTypes.IsSecure(stack.SecurityType)
                    => ["http/1.1"],
            _ => Array.Empty<string>()
        };

    private static IReadOnlyList<string> NormalizeSplitHttpApplicationProtocols(IReadOnlyList<string> values)
    {
        var normalized = NormalizeApplicationProtocols(values);
        return normalized.Count > 0 ? normalized : ["h2", "http/1.1"];
    }

    private static RuntimeQuicOptions NormalizeQuicOptions(RuntimeQuicOptions? value)
    {
        if (value is null)
        {
            return RuntimeQuicOptions.Empty;
        }

        return new RuntimeQuicOptions
        {
            Congestion = string.IsNullOrWhiteSpace(value.Congestion)
                ? string.Empty
                : value.Congestion.Trim().ToLowerInvariant(),
            BrutalUp = Math.Max(0, value.BrutalUp),
            BrutalDown = Math.Max(0, value.BrutalDown),
            UdpHop = NormalizeUdpHopOptions(value.UdpHop),
            InitStreamReceiveWindow = Math.Max(0, value.InitStreamReceiveWindow),
            MaxStreamReceiveWindow = Math.Max(0, value.MaxStreamReceiveWindow),
            InitConnReceiveWindow = Math.Max(0, value.InitConnReceiveWindow),
            MaxConnReceiveWindow = Math.Max(0, value.MaxConnReceiveWindow),
            MaxIdleTimeoutSeconds = Math.Max(0, value.MaxIdleTimeoutSeconds),
            KeepAlivePeriodSeconds = Math.Max(0, value.KeepAlivePeriodSeconds),
            DisablePathMtuDiscovery = value.DisablePathMtuDiscovery,
            MaxIncomingStreams = Math.Max(0, value.MaxIncomingStreams)
        };
    }

    private static RuntimeUdpHopOptions NormalizeUdpHopOptions(RuntimeUdpHopOptions? value)
    {
        if (value is null)
        {
            return RuntimeUdpHopOptions.Empty;
        }

        return new RuntimeUdpHopOptions
        {
            Ports = (value.Ports ?? Array.Empty<int>())
                .Where(static port => port is > 0 and <= 65535)
                .Distinct()
                .ToArray(),
            IntervalMinSeconds = Math.Max(0, value.IntervalMinSeconds),
            IntervalMaxSeconds = Math.Max(0, value.IntervalMaxSeconds)
        };
    }

    private static string NormalizeSenderWebSocketPath(string value)
    {
        if (string.IsNullOrWhiteSpace(value))
        {
            return "/";
        }

        var normalized = value.Trim();
        return normalized.StartsWith("/", StringComparison.Ordinal) ? normalized : $"/{normalized}";
    }

    private static string NormalizeSenderSplitHttpPath(string value)
        => RuntimeSplitHttpNormalization.NormalizePath(value);

    private static string NormalizeSenderHttpUpgradePath(string value)
        => RuntimeInternetHttpUtilities.NormalizePath(value);

    private static bool TryNormalizeSplitHttpMode(
        string value,
        out string normalized,
        out string? error)
        => RuntimeSplitHttpNormalization.TryNormalizeMode(value, out normalized, out error);

    private static string NormalizeSplitHttpUplinkHttpMethod(string value)
        => string.IsNullOrWhiteSpace(value) ? "POST" : value.Trim().ToUpperInvariant();

    private static bool TryNormalizeSplitHttpXPaddingBytes(
        RuntimeInt32Range? value,
        out RuntimeInt32Range normalized,
        out string? error)
        => RuntimeSplitHttpNormalization.TryNormalizeXPaddingBytes(value, out normalized, out error);

    private static string NormalizeSplitHttpXPaddingKey(string value)
        => RuntimeSplitHttpNormalization.NormalizeXPaddingKey(value);

    private static string NormalizeSplitHttpXPaddingHeader(string value)
        => RuntimeSplitHttpNormalization.NormalizeXPaddingHeader(value);

    private static bool TryNormalizeSplitHttpXPaddingPlacement(
        string value,
        out string normalized,
        out string? error)
        => RuntimeSplitHttpNormalization.TryNormalizeXPaddingPlacement(value, out normalized, out error);

    private static bool TryNormalizeSplitHttpXPaddingMethod(
        string value,
        out string normalized,
        out string? error)
        => RuntimeSplitHttpNormalization.TryNormalizeXPaddingMethod(value, out normalized, out error);

    private static bool TryNormalizeSplitHttpUplinkDataPlacement(
        string value,
        out string normalized,
        out string? error)
        => RuntimeSplitHttpNormalization.TryNormalizeUplinkDataPlacement(value, out normalized, out error);

    private static bool TryNormalizeSplitHttpSessionPlacement(
        string value,
        out string normalized,
        out string? error)
        => RuntimeSplitHttpNormalization.TryNormalizeSessionPlacement(value, out normalized, out error);

    private static string NormalizeSplitHttpSessionKey(string placement, string value)
        => RuntimeSplitHttpNormalization.ResolveSessionKey(placement, value);

    private static bool TryNormalizeSplitHttpSeqPlacement(
        string value,
        out string normalized,
        out string? error)
        => RuntimeSplitHttpNormalization.TryNormalizeSeqPlacement(value, out normalized, out error);

    private static string NormalizeSplitHttpSeqKey(string placement, string value)
        => RuntimeSplitHttpNormalization.ResolveSeqKey(placement, value);

    private static string NormalizeSplitHttpUplinkDataKey(string placement, string value)
        => RuntimeSplitHttpNormalization.ResolveUplinkDataKey(placement, value);

    private static RuntimeInt32Range NormalizeSplitHttpRange(RuntimeInt32Range? value)
        => RuntimeSplitHttpNormalization.NormalizeRange(value);

    private static bool TryNormalizeSplitHttpServerMaxHeaderBytes(
        int value,
        out int normalized,
        out string? error)
        => RuntimeSplitHttpNormalization.TryNormalizeServerMaxHeaderBytes(value, out normalized, out error);

    private static bool TryNormalizeSplitHttpDownloadSettings(
        RuntimeSplitHttpDownloadOptions? value,
        string serverHost,
        int serverPort,
        string serverName,
        string fingerprint,
        string transportSecurity,
        RuntimeRealityOptions realityOptions,
        string splitHttpHost,
        string splitHttpPath,
        IReadOnlyDictionary<string, string> splitHttpHeaders,
        int connectTimeoutSeconds,
        int handshakeTimeoutSeconds,
        bool skipCertificateValidation,
        out RuntimeSplitHttpDownloadOptions? normalized,
        out string? error)
    {
        if (value is null)
        {
            normalized = null;
            error = null;
            return true;
        }

        var normalizedServerHost = value.ServerHost is null ? serverHost : value.ServerHost.Trim();
        if (normalizedServerHost.Length == 0)
        {
            normalized = null;
            error = "SplitHTTP downloadSettings server host is not specified.";
            return false;
        }

        var normalizedServerPort = value.ServerPort ?? serverPort;
        if (normalizedServerPort is <= 0 or > 65535)
        {
            normalized = null;
            error = "Invalid SplitHTTP downloadSettings port.";
            return false;
        }

        var normalizedSecurityType = value.TransportSecurity is null
            ? transportSecurity
            : RuntimeInternetSecurityTypes.Normalize(value.TransportSecurity);
        var normalizedFingerprint = string.Empty;
        if (string.Equals(normalizedSecurityType, RuntimeInternetSecurityTypes.Tls, StringComparison.Ordinal))
        {
            if (value.Fingerprint is null)
            {
                normalizedFingerprint = fingerprint;
            }
            else if (!TryNormalizeNormalFingerprint(value.Fingerprint, out normalizedFingerprint, out error))
            {
                normalized = null;
                return false;
            }
        }
        var normalizedRealityOptions = RuntimeRealityOptions.Empty;
        if (string.Equals(normalizedSecurityType, RuntimeInternetSecurityTypes.Reality, StringComparison.Ordinal))
        {
            var sourceRealityOptions = value.RealityOptions ?? realityOptions;
            if (!RuntimeRealityOptions.Normalize(sourceRealityOptions)
                    .TryValidateForReality(out normalizedRealityOptions, out error))
            {
                normalized = null;
                return false;
            }
        }

        var normalizedHeaders = value.Headers is null
            ? splitHttpHeaders.ToDictionary(
                static pair => pair.Key,
                static pair => pair.Value,
                StringComparer.OrdinalIgnoreCase)
            : NormalizeHeaders(value.Headers);
        if (normalizedHeaders.ContainsKey("Host"))
        {
            normalized = null;
            error = "\"downloadSettings.headers\" can't contain \"host\"";
            return false;
        }

        normalized = new RuntimeSplitHttpDownloadOptions
        {
            ServerHost = normalizedServerHost,
            ServerPort = normalizedServerPort,
            ServerName = value.ServerName is null ? serverName : value.ServerName.Trim(),
            Fingerprint = normalizedFingerprint,
            TransportSecurity = normalizedSecurityType,
            RealityOptions = normalizedRealityOptions,
            Host = value.Host is null ? splitHttpHost : value.Host.Trim(),
            Path = value.Path is null ? splitHttpPath : NormalizeSenderSplitHttpPath(value.Path),
            Headers = normalizedHeaders,
            ConnectTimeoutSeconds = Math.Max(0, value.ConnectTimeoutSeconds ?? connectTimeoutSeconds),
            HandshakeTimeoutSeconds = Math.Max(0, value.HandshakeTimeoutSeconds ?? handshakeTimeoutSeconds),
            SkipCertificateValidation = value.SkipCertificateValidation ?? skipCertificateValidation
        };
        error = null;
        return true;
    }

    private sealed record CompiledProxyCommon
    {
        public required string ServerHost { get; init; }

        public required int ServerPort { get; init; }

        public string ServerName { get; init; } = string.Empty;

        public string Fingerprint { get; init; } = string.Empty;

        public string Transport { get; init; } = TrojanOutboundTransports.Tls;

        public string TransportSecurity { get; init; } = string.Empty;

        public RuntimeRealityOptions RealityOptions { get; init; } = RuntimeRealityOptions.Empty;

        public string WebSocketPath { get; init; } = "/";

        public IReadOnlyDictionary<string, string> WebSocketHeaders { get; init; }
            = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);

        public int WebSocketEarlyDataBytes { get; init; }

        public int WebSocketHeartbeatPeriodSeconds { get; init; }

        public string SplitHttpHost { get; init; } = string.Empty;

        public string SplitHttpPath { get; init; } = "/";

        public IReadOnlyDictionary<string, string> SplitHttpHeaders { get; init; }
            = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);

        public string SplitHttpMode { get; init; } = string.Empty;

        public bool SplitHttpNoGrpcHeader { get; init; }

        public bool SplitHttpNoSseHeader { get; init; }

        public RuntimeInt32Range SplitHttpXPaddingBytes { get; init; } = RuntimeInt32Range.Empty;

        public bool SplitHttpXPaddingObfsMode { get; init; }

        public string SplitHttpXPaddingKey { get; init; } = string.Empty;

        public string SplitHttpXPaddingHeader { get; init; } = string.Empty;

        public string SplitHttpXPaddingPlacement { get; init; } = string.Empty;

        public string SplitHttpXPaddingMethod { get; init; } = string.Empty;

        public string SplitHttpUplinkHttpMethod { get; init; } = string.Empty;

        public string SplitHttpSessionPlacement { get; init; } = string.Empty;

        public string SplitHttpSessionKey { get; init; } = string.Empty;

        public string SplitHttpSeqPlacement { get; init; } = string.Empty;

        public string SplitHttpSeqKey { get; init; } = string.Empty;

        public string SplitHttpUplinkDataPlacement { get; init; } = string.Empty;

        public string SplitHttpUplinkDataKey { get; init; } = string.Empty;

        public RuntimeInt32Range SplitHttpUplinkChunkSize { get; init; } = RuntimeInt32Range.Empty;

        public RuntimeInt32Range SplitHttpScMaxEachPostBytes { get; init; } = RuntimeInt32Range.Empty;

        public RuntimeInt32Range SplitHttpScMinPostsIntervalMs { get; init; } = RuntimeInt32Range.Empty;

        public int SplitHttpScMaxBufferedPosts { get; init; }

        public RuntimeInt32Range SplitHttpScStreamUpServerSecs { get; init; } = RuntimeInt32Range.Empty;

        public int SplitHttpServerMaxHeaderBytes { get; init; }

        public RuntimeSplitHttpXmuxOptions SplitHttpXmux { get; init; } = RuntimeSplitHttpXmuxOptions.Empty;

        public RuntimeSplitHttpDownloadOptions? SplitHttpDownloadSettings { get; init; }

        public IReadOnlyList<string> ApplicationProtocols { get; init; } = Array.Empty<string>();

        public RuntimeQuicOptions QuicOptions { get; init; } = RuntimeQuicOptions.Empty;

        public string GrpcServiceName { get; init; } = string.Empty;

        public string GrpcAuthority { get; init; } = string.Empty;

        public bool GrpcMultiMode { get; init; }

        public string GrpcUserAgent { get; init; } = string.Empty;

        public int GrpcIdleTimeoutSeconds { get; init; }

        public int GrpcHealthCheckTimeoutSeconds { get; init; }

        public bool GrpcPermitWithoutStream { get; init; }

        public int GrpcInitialWindowSize { get; init; }

        public int ConnectTimeoutSeconds { get; init; }

        public int HandshakeTimeoutSeconds { get; init; }
    }

    private static bool TryNormalizeNormalFingerprint(
        string? value,
        out string normalized,
        out string? error)
    {
        normalized = RuntimeTlsFingerprintCatalog.Normalize(value);
        if (RuntimeTlsFingerprintCatalog.IsKnown(normalized))
        {
            error = null;
            return true;
        }

        error = $"Unknown TLS fingerprint '{normalized}'.";
        return false;
    }
}

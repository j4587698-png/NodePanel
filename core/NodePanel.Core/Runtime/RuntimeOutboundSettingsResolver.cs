namespace NodePanel.Core.Runtime;

internal static class RuntimeOutboundSettingsResolver
{
    public static bool TryResolveOutbound(
        IOutboundRuntimePlanProvider planProvider,
        DispatchContext context,
        out OutboundRuntime outbound)
    {
        ArgumentNullException.ThrowIfNull(planProvider);

        var plan = planProvider.GetCurrentOutboundPlan();
        if (plan.TryResolveOutboundTag(context, out var outboundTag) &&
            plan.TryGetOutbound(outboundTag, out outbound))
        {
            return true;
        }

        outbound = default!;
        return false;
    }

    public static OutboundCommonSettings CreateCommonSettings(OutboundRuntime outbound)
        => new()
        {
            Tag = outbound.Tag,
            Protocol = OutboundProtocols.Normalize(outbound.Protocol),
            Via = outbound.Via,
            ViaCidr = outbound.ViaCidr,
            TargetStrategy = outbound.TargetStrategy,
            ProxyOutboundTag = outbound.ProxyOutboundTag,
            MultiplexSettings = CloneMultiplexSettings(outbound.MultiplexSettings)
        };

    public static TrojanOutboundSettings CreateTrojanSettings(
        OutboundRuntime outbound,
        RuntimeTrojanOutboundOptions trojan)
        => new()
        {
            Tag = outbound.Tag,
            Via = outbound.Via,
            ViaCidr = outbound.ViaCidr,
            TargetStrategy = outbound.TargetStrategy,
            ProxyOutboundTag = outbound.ProxyOutboundTag,
            MultiplexSettings = CloneMultiplexSettings(outbound.MultiplexSettings),
            ServerHost = trojan.ServerHost,
            ServerPort = trojan.ServerPort,
            ServerName = trojan.ServerName,
            Fingerprint = trojan.Fingerprint,
            Transport = TrojanOutboundTransports.Normalize(trojan.Transport),
            TransportSecurity = trojan.TransportSecurity,
            RealityOptions = trojan.RealityOptions,
            WebSocketPath = trojan.WebSocketPath,
            WebSocketHeaders = CloneHeaders(trojan.WebSocketHeaders),
            WebSocketEarlyDataBytes = trojan.WebSocketEarlyDataBytes,
            WebSocketHeartbeatPeriodSeconds = trojan.WebSocketHeartbeatPeriodSeconds,
            SplitHttpHost = trojan.SplitHttpHost,
            SplitHttpPath = trojan.SplitHttpPath,
            SplitHttpHeaders = CloneHeaders(trojan.SplitHttpHeaders),
            SplitHttpMode = trojan.SplitHttpMode,
            SplitHttpNoGrpcHeader = trojan.SplitHttpNoGrpcHeader,
            SplitHttpNoSseHeader = trojan.SplitHttpNoSseHeader,
            SplitHttpXPaddingBytes = trojan.SplitHttpXPaddingBytes,
            SplitHttpXPaddingObfsMode = trojan.SplitHttpXPaddingObfsMode,
            SplitHttpXPaddingKey = trojan.SplitHttpXPaddingKey,
            SplitHttpXPaddingHeader = trojan.SplitHttpXPaddingHeader,
            SplitHttpXPaddingPlacement = trojan.SplitHttpXPaddingPlacement,
            SplitHttpXPaddingMethod = trojan.SplitHttpXPaddingMethod,
            SplitHttpUplinkHttpMethod = trojan.SplitHttpUplinkHttpMethod,
            SplitHttpSessionPlacement = trojan.SplitHttpSessionPlacement,
            SplitHttpSessionKey = trojan.SplitHttpSessionKey,
            SplitHttpSeqPlacement = trojan.SplitHttpSeqPlacement,
            SplitHttpSeqKey = trojan.SplitHttpSeqKey,
            SplitHttpUplinkDataPlacement = trojan.SplitHttpUplinkDataPlacement,
            SplitHttpUplinkDataKey = trojan.SplitHttpUplinkDataKey,
            SplitHttpUplinkChunkSize = trojan.SplitHttpUplinkChunkSize,
            SplitHttpScMaxEachPostBytes = trojan.SplitHttpScMaxEachPostBytes,
            SplitHttpScMinPostsIntervalMs = trojan.SplitHttpScMinPostsIntervalMs,
            SplitHttpScMaxBufferedPosts = trojan.SplitHttpScMaxBufferedPosts,
            SplitHttpScStreamUpServerSecs = trojan.SplitHttpScStreamUpServerSecs,
            SplitHttpServerMaxHeaderBytes = trojan.SplitHttpServerMaxHeaderBytes,
            SplitHttpXmux = CloneSplitHttpXmuxSettings(trojan.SplitHttpXmux),
            SplitHttpDownloadSettings = CloneSplitHttpDownloadSettings(trojan.SplitHttpDownloadSettings),
            ApplicationProtocols = trojan.ApplicationProtocols.ToArray(),
            QuicOptions = CloneQuicOptions(trojan.QuicOptions),
            GrpcServiceName = trojan.GrpcServiceName,
            GrpcAuthority = trojan.GrpcAuthority,
            GrpcMultiMode = trojan.GrpcMultiMode,
            GrpcUserAgent = trojan.GrpcUserAgent,
            GrpcIdleTimeoutSeconds = trojan.GrpcIdleTimeoutSeconds,
            GrpcHealthCheckTimeoutSeconds = trojan.GrpcHealthCheckTimeoutSeconds,
            GrpcPermitWithoutStream = trojan.GrpcPermitWithoutStream,
            GrpcInitialWindowSize = trojan.GrpcInitialWindowSize,
            Password = trojan.Password,
            ConnectTimeoutSeconds = trojan.ConnectTimeoutSeconds,
            HandshakeTimeoutSeconds = trojan.HandshakeTimeoutSeconds,
            EnableTlsSessionResumption = trojan.EnableTlsSessionResumption,
            SkipCertificateValidation = trojan.SkipCertificateValidation
        };

    public static Shadowsocks2022OutboundSettings CreateShadowsocks2022Settings(
        OutboundRuntime outbound,
        RuntimeShadowsocks2022OutboundOptions shadowsocks2022)
    {
        var compiled = ShadowsocksOutboundOptionsCompiler.Compile2022(shadowsocks2022);
        return new Shadowsocks2022OutboundSettings
        {
            Tag = outbound.Tag,
            Via = outbound.Via,
            ViaCidr = outbound.ViaCidr,
            TargetStrategy = outbound.TargetStrategy,
            ProxyOutboundTag = outbound.ProxyOutboundTag,
            ServerHost = compiled.ServerHost,
            ServerPort = compiled.ServerPort,
            Method = compiled.Method,
            Key = compiled.Key,
            UdpOverTcp = compiled.UdpOverTcp,
            UdpOverTcpVersion = compiled.UdpOverTcpVersion,
            ConnectTimeoutSeconds = compiled.ConnectTimeoutSeconds
        };
    }

    public static VlessOutboundSettings CreateVlessSettings(
        OutboundRuntime outbound,
        RuntimeVlessOutboundOptions vless)
        => new()
        {
            Tag = outbound.Tag,
            Via = outbound.Via,
            ViaCidr = outbound.ViaCidr,
            TargetStrategy = outbound.TargetStrategy,
            ProxyOutboundTag = outbound.ProxyOutboundTag,
            MultiplexSettings = CloneMultiplexSettings(outbound.MultiplexSettings),
            ServerHost = vless.ServerHost,
            ServerPort = vless.ServerPort,
            ServerName = vless.ServerName,
            Fingerprint = vless.Fingerprint,
            Transport = VlessOutboundTransports.Normalize(vless.Transport),
            TransportSecurity = vless.TransportSecurity,
            RealityOptions = vless.RealityOptions,
            WebSocketPath = vless.WebSocketPath,
            WebSocketHeaders = CloneHeaders(vless.WebSocketHeaders),
            WebSocketEarlyDataBytes = vless.WebSocketEarlyDataBytes,
            WebSocketHeartbeatPeriodSeconds = vless.WebSocketHeartbeatPeriodSeconds,
            SplitHttpHost = vless.SplitHttpHost,
            SplitHttpPath = vless.SplitHttpPath,
            SplitHttpHeaders = CloneHeaders(vless.SplitHttpHeaders),
            SplitHttpMode = vless.SplitHttpMode,
            SplitHttpNoGrpcHeader = vless.SplitHttpNoGrpcHeader,
            SplitHttpNoSseHeader = vless.SplitHttpNoSseHeader,
            SplitHttpXPaddingBytes = vless.SplitHttpXPaddingBytes,
            SplitHttpXPaddingObfsMode = vless.SplitHttpXPaddingObfsMode,
            SplitHttpXPaddingKey = vless.SplitHttpXPaddingKey,
            SplitHttpXPaddingHeader = vless.SplitHttpXPaddingHeader,
            SplitHttpXPaddingPlacement = vless.SplitHttpXPaddingPlacement,
            SplitHttpXPaddingMethod = vless.SplitHttpXPaddingMethod,
            SplitHttpUplinkHttpMethod = vless.SplitHttpUplinkHttpMethod,
            SplitHttpSessionPlacement = vless.SplitHttpSessionPlacement,
            SplitHttpSessionKey = vless.SplitHttpSessionKey,
            SplitHttpSeqPlacement = vless.SplitHttpSeqPlacement,
            SplitHttpSeqKey = vless.SplitHttpSeqKey,
            SplitHttpUplinkDataPlacement = vless.SplitHttpUplinkDataPlacement,
            SplitHttpUplinkDataKey = vless.SplitHttpUplinkDataKey,
            SplitHttpUplinkChunkSize = vless.SplitHttpUplinkChunkSize,
            SplitHttpScMaxEachPostBytes = vless.SplitHttpScMaxEachPostBytes,
            SplitHttpScMinPostsIntervalMs = vless.SplitHttpScMinPostsIntervalMs,
            SplitHttpScMaxBufferedPosts = vless.SplitHttpScMaxBufferedPosts,
            SplitHttpScStreamUpServerSecs = vless.SplitHttpScStreamUpServerSecs,
            SplitHttpServerMaxHeaderBytes = vless.SplitHttpServerMaxHeaderBytes,
            SplitHttpXmux = CloneSplitHttpXmuxSettings(vless.SplitHttpXmux),
            SplitHttpDownloadSettings = CloneSplitHttpDownloadSettings(vless.SplitHttpDownloadSettings),
            ApplicationProtocols = vless.ApplicationProtocols.ToArray(),
            QuicOptions = CloneQuicOptions(vless.QuicOptions),
            GrpcServiceName = vless.GrpcServiceName,
            GrpcAuthority = vless.GrpcAuthority,
            GrpcMultiMode = vless.GrpcMultiMode,
            GrpcUserAgent = vless.GrpcUserAgent,
            GrpcIdleTimeoutSeconds = vless.GrpcIdleTimeoutSeconds,
            GrpcHealthCheckTimeoutSeconds = vless.GrpcHealthCheckTimeoutSeconds,
            GrpcPermitWithoutStream = vless.GrpcPermitWithoutStream,
            GrpcInitialWindowSize = vless.GrpcInitialWindowSize,
            Version = vless.Version,
            UserUuid = vless.UserUuid,
            Flow = VlessFlowTypes.Normalize(vless.Flow),
            Encryption = vless.Encryption,
            XorMode = vless.XorMode,
            Seconds = Math.Max(0, vless.Seconds),
            Padding = vless.Padding,
            TestSeed = vless.TestSeed.ToArray(),
            TestPre = Math.Max(0, vless.TestPre),
            ReverseTag = vless.ReverseTag,
            ConnectTimeoutSeconds = vless.ConnectTimeoutSeconds,
            HandshakeTimeoutSeconds = vless.HandshakeTimeoutSeconds,
            EnableTlsSessionResumption = vless.EnableTlsSessionResumption,
            SkipCertificateValidation = vless.SkipCertificateValidation
        };

    public static VmessOutboundSettings CreateVmessSettings(
        OutboundRuntime outbound,
        RuntimeVmessOutboundOptions vmess)
        => new()
        {
            Tag = outbound.Tag,
            Via = outbound.Via,
            ViaCidr = outbound.ViaCidr,
            TargetStrategy = outbound.TargetStrategy,
            ProxyOutboundTag = outbound.ProxyOutboundTag,
            MultiplexSettings = CloneMultiplexSettings(outbound.MultiplexSettings),
            ServerHost = vmess.ServerHost,
            ServerPort = vmess.ServerPort,
            ServerName = vmess.ServerName,
            Fingerprint = vmess.Fingerprint,
            Transport = VmessOutboundTransports.Normalize(vmess.Transport),
            TransportSecurity = vmess.TransportSecurity,
            RealityOptions = vmess.RealityOptions,
            WebSocketPath = vmess.WebSocketPath,
            WebSocketHeaders = CloneHeaders(vmess.WebSocketHeaders),
            WebSocketEarlyDataBytes = vmess.WebSocketEarlyDataBytes,
            WebSocketHeartbeatPeriodSeconds = vmess.WebSocketHeartbeatPeriodSeconds,
            SplitHttpHost = vmess.SplitHttpHost,
            SplitHttpPath = vmess.SplitHttpPath,
            SplitHttpHeaders = CloneHeaders(vmess.SplitHttpHeaders),
            SplitHttpMode = vmess.SplitHttpMode,
            SplitHttpNoGrpcHeader = vmess.SplitHttpNoGrpcHeader,
            SplitHttpNoSseHeader = vmess.SplitHttpNoSseHeader,
            SplitHttpXPaddingBytes = vmess.SplitHttpXPaddingBytes,
            SplitHttpXPaddingObfsMode = vmess.SplitHttpXPaddingObfsMode,
            SplitHttpXPaddingKey = vmess.SplitHttpXPaddingKey,
            SplitHttpXPaddingHeader = vmess.SplitHttpXPaddingHeader,
            SplitHttpXPaddingPlacement = vmess.SplitHttpXPaddingPlacement,
            SplitHttpXPaddingMethod = vmess.SplitHttpXPaddingMethod,
            SplitHttpUplinkHttpMethod = vmess.SplitHttpUplinkHttpMethod,
            SplitHttpSessionPlacement = vmess.SplitHttpSessionPlacement,
            SplitHttpSessionKey = vmess.SplitHttpSessionKey,
            SplitHttpSeqPlacement = vmess.SplitHttpSeqPlacement,
            SplitHttpSeqKey = vmess.SplitHttpSeqKey,
            SplitHttpUplinkDataPlacement = vmess.SplitHttpUplinkDataPlacement,
            SplitHttpUplinkDataKey = vmess.SplitHttpUplinkDataKey,
            SplitHttpUplinkChunkSize = vmess.SplitHttpUplinkChunkSize,
            SplitHttpScMaxEachPostBytes = vmess.SplitHttpScMaxEachPostBytes,
            SplitHttpScMinPostsIntervalMs = vmess.SplitHttpScMinPostsIntervalMs,
            SplitHttpScMaxBufferedPosts = vmess.SplitHttpScMaxBufferedPosts,
            SplitHttpScStreamUpServerSecs = vmess.SplitHttpScStreamUpServerSecs,
            SplitHttpServerMaxHeaderBytes = vmess.SplitHttpServerMaxHeaderBytes,
            SplitHttpXmux = CloneSplitHttpXmuxSettings(vmess.SplitHttpXmux),
            SplitHttpDownloadSettings = CloneSplitHttpDownloadSettings(vmess.SplitHttpDownloadSettings),
            ApplicationProtocols = vmess.ApplicationProtocols.ToArray(),
            QuicOptions = CloneQuicOptions(vmess.QuicOptions),
            GrpcServiceName = vmess.GrpcServiceName,
            GrpcAuthority = vmess.GrpcAuthority,
            GrpcMultiMode = vmess.GrpcMultiMode,
            GrpcUserAgent = vmess.GrpcUserAgent,
            GrpcIdleTimeoutSeconds = vmess.GrpcIdleTimeoutSeconds,
            GrpcHealthCheckTimeoutSeconds = vmess.GrpcHealthCheckTimeoutSeconds,
            GrpcPermitWithoutStream = vmess.GrpcPermitWithoutStream,
            GrpcInitialWindowSize = vmess.GrpcInitialWindowSize,
            UserUuid = vmess.UserUuid,
            Security = VmessOutboundSecurityTypes.Normalize(vmess.Security),
            AuthenticatedLength = vmess.AuthenticatedLength,
            NoTerminationSignal = vmess.NoTerminationSignal,
            ConnectTimeoutSeconds = vmess.ConnectTimeoutSeconds,
            HandshakeTimeoutSeconds = vmess.HandshakeTimeoutSeconds,
            EnableTlsSessionResumption = vmess.EnableTlsSessionResumption,
            SkipCertificateValidation = vmess.SkipCertificateValidation
        };

    public static bool TryResolveTrojan(
        IOutboundRuntimePlanProvider planProvider,
        IRuntimeOutboundSettingsProvider settingsProvider,
        DispatchContext context,
        out TrojanOutboundSettings settings)
        => TryResolve<RuntimeTrojanOutboundOptions, TrojanOutboundSettings>(
            planProvider,
            settingsProvider,
            context,
            OutboundProtocols.Trojan,
            CreateTrojanSettings,
            out settings);

    public static bool TryResolveShadowsocks2022(
        IOutboundRuntimePlanProvider planProvider,
        IRuntimeOutboundSettingsProvider settingsProvider,
        DispatchContext context,
        out Shadowsocks2022OutboundSettings settings)
    {
        ArgumentNullException.ThrowIfNull(settingsProvider);

        if (!TryResolveOutbound(planProvider, context, out var outbound) ||
            !settingsProvider.TryResolve(context, out IRuntimeOutboundOptions runtimeOptions))
        {
            settings = default!;
            return false;
        }

        var outboundProtocol = OutboundProtocols.Normalize(outbound.Protocol);
        if (!string.Equals(outboundProtocol, OutboundProtocols.Shadowsocks, StringComparison.Ordinal) ||
            !string.Equals(outboundProtocol, OutboundProtocols.Normalize(runtimeOptions.Protocol), StringComparison.Ordinal))
        {
            settings = default!;
            return false;
        }

        if (!ShadowsocksOutboundOptionsCompiler.TryCompile(runtimeOptions, out var compiled, out _) ||
            compiled is not RuntimeShadowsocks2022OutboundOptions shadowsocks2022)
        {
            settings = default!;
            return false;
        }

        settings = CreateShadowsocks2022Settings(outbound, shadowsocks2022);
        return true;
    }

    public static bool TryResolveVless(
        IOutboundRuntimePlanProvider planProvider,
        IRuntimeOutboundSettingsProvider settingsProvider,
        DispatchContext context,
        out VlessOutboundSettings settings)
        => TryResolve<RuntimeVlessOutboundOptions, VlessOutboundSettings>(
            planProvider,
            settingsProvider,
            context,
            OutboundProtocols.Vless,
            CreateVlessSettings,
            out settings);

    public static bool TryResolveVmess(
        IOutboundRuntimePlanProvider planProvider,
        IRuntimeOutboundSettingsProvider settingsProvider,
        DispatchContext context,
        out VmessOutboundSettings settings)
        => TryResolve<RuntimeVmessOutboundOptions, VmessOutboundSettings>(
            planProvider,
            settingsProvider,
            context,
            OutboundProtocols.Vmess,
            CreateVmessSettings,
            out settings);

    private static bool TryResolve<TOptions, TSettings>(
        IOutboundRuntimePlanProvider planProvider,
        IRuntimeOutboundSettingsProvider settingsProvider,
        DispatchContext context,
        string expectedProtocol,
        Func<OutboundRuntime, TOptions, TSettings> factory,
        out TSettings settings)
        where TOptions : class, IRuntimeOutboundOptions
    {
        ArgumentNullException.ThrowIfNull(settingsProvider);

        if (!TryResolveOutbound(planProvider, context, out var outbound) ||
            !settingsProvider.TryResolve(context, out TOptions runtimeOptions))
        {
            settings = default!;
            return false;
        }

        var outboundProtocol = OutboundProtocols.Normalize(outbound.Protocol);
        if (!string.Equals(outboundProtocol, expectedProtocol, StringComparison.Ordinal) ||
            !string.Equals(outboundProtocol, OutboundProtocols.Normalize(runtimeOptions.Protocol), StringComparison.Ordinal))
        {
            settings = default!;
            return false;
        }

        settings = factory(outbound, runtimeOptions);
        return true;
    }

    private static OutboundMultiplexRuntime CloneMultiplexSettings(IOutboundMultiplexDefinition definition)
        => new()
        {
            Enabled = definition.Enabled,
            Concurrency = definition.Concurrency,
            XudpConcurrency = definition.XudpConcurrency,
            XudpProxyUdp443 = OutboundXudpProxyModes.Normalize(definition.XudpProxyUdp443)
        };

    private static IReadOnlyDictionary<string, string> CloneHeaders(IReadOnlyDictionary<string, string> headers)
        => headers.ToDictionary(
            static pair => pair.Key,
            static pair => pair.Value,
            StringComparer.OrdinalIgnoreCase);

    private static RuntimeSplitHttpDownloadOptions? CloneSplitHttpDownloadSettings(RuntimeSplitHttpDownloadOptions? settings)
        => settings is null
            ? null
            : new RuntimeSplitHttpDownloadOptions
            {
                ServerHost = settings.ServerHost,
                ServerPort = settings.ServerPort,
                ServerName = settings.ServerName,
                TransportSecurity = settings.TransportSecurity,
                RealityOptions = settings.RealityOptions,
                Host = settings.Host,
                Path = settings.Path,
                Headers = settings.Headers is null
                    ? null
                    : settings.Headers.ToDictionary(
                        static pair => pair.Key,
                        static pair => pair.Value,
                        StringComparer.OrdinalIgnoreCase),
                ConnectTimeoutSeconds = settings.ConnectTimeoutSeconds,
                HandshakeTimeoutSeconds = settings.HandshakeTimeoutSeconds,
                SkipCertificateValidation = settings.SkipCertificateValidation
            };

    private static RuntimeSplitHttpXmuxOptions CloneSplitHttpXmuxSettings(RuntimeSplitHttpXmuxOptions? settings)
        => settings is null
            ? RuntimeSplitHttpXmuxOptions.Empty
            : new RuntimeSplitHttpXmuxOptions
            {
                MaxConcurrency = settings.MaxConcurrency,
                MaxConnections = settings.MaxConnections,
                CMaxReuseTimes = settings.CMaxReuseTimes,
                HMaxRequestTimes = settings.HMaxRequestTimes,
                HMaxReusableSecs = settings.HMaxReusableSecs,
                HKeepAlivePeriodSeconds = settings.HKeepAlivePeriodSeconds
            };

    private static RuntimeQuicOptions CloneQuicOptions(RuntimeQuicOptions? settings)
        => settings is null
            ? RuntimeQuicOptions.Empty
            : new RuntimeQuicOptions
            {
                Congestion = settings.Congestion,
                BrutalUp = settings.BrutalUp,
                BrutalDown = settings.BrutalDown,
                UdpHop = settings.UdpHop is null
                    ? RuntimeUdpHopOptions.Empty
                    : new RuntimeUdpHopOptions
                    {
                        Ports = settings.UdpHop.Ports.ToArray(),
                        IntervalMinSeconds = settings.UdpHop.IntervalMinSeconds,
                        IntervalMaxSeconds = settings.UdpHop.IntervalMaxSeconds
                    },
                InitStreamReceiveWindow = settings.InitStreamReceiveWindow,
                MaxStreamReceiveWindow = settings.MaxStreamReceiveWindow,
                InitConnReceiveWindow = settings.InitConnReceiveWindow,
                MaxConnReceiveWindow = settings.MaxConnReceiveWindow,
                MaxIdleTimeoutSeconds = settings.MaxIdleTimeoutSeconds,
                KeepAlivePeriodSeconds = settings.KeepAlivePeriodSeconds,
                DisablePathMtuDiscovery = settings.DisablePathMtuDiscovery,
                MaxIncomingStreams = settings.MaxIncomingStreams
            };
}

using System.Net;
using NodePanel.ControlPlane.Configuration;
using NodePanel.Core.Runtime;

namespace NodePanel.ControlPlane.Runtime;

public sealed class NodeRuntimeSnapshotBuilder
{
    private readonly IReadOnlyList<IInboundProtocolRuntimeCompiler> _inboundProtocolCompilers;
    private readonly HashSet<string> _supportedInboundProtocols;
    private readonly IReadOnlyList<IOutboundProtocolRuntimeCompiler> _outboundProtocolCompilers;
    private readonly HashSet<string> _supportedOutboundProtocols;

    public NodeRuntimeSnapshotBuilder(IEnumerable<IInboundProtocolRuntimeCompiler> inboundProtocolCompilers)
        : this(inboundProtocolCompilers, CreateDefaultOutboundProtocolCompilers())
    {
    }

    public NodeRuntimeSnapshotBuilder(
        IEnumerable<IInboundProtocolRuntimeCompiler> inboundProtocolCompilers,
        IEnumerable<IOutboundProtocolRuntimeCompiler> outboundProtocolCompilers)
    {
        ArgumentNullException.ThrowIfNull(inboundProtocolCompilers);
        ArgumentNullException.ThrowIfNull(outboundProtocolCompilers);

        var materializedInboundCompilers = new List<IInboundProtocolRuntimeCompiler>();
        var supportedInboundProtocols = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (var compiler in inboundProtocolCompilers)
        {
            var protocol = NormalizeProtocolKey(compiler.Protocol);
            if (string.IsNullOrWhiteSpace(protocol))
            {
                throw new InvalidOperationException("Inbound protocol compiler must declare a protocol.");
            }

            if (!supportedInboundProtocols.Add(protocol))
            {
                throw new InvalidOperationException($"Duplicate inbound protocol compiler registration: {protocol}.");
            }

            materializedInboundCompilers.Add(compiler);
        }

        _inboundProtocolCompilers = materializedInboundCompilers;
        _supportedInboundProtocols = supportedInboundProtocols;

        var materializedOutboundCompilers = new List<IOutboundProtocolRuntimeCompiler>();
        var supportedOutboundProtocols = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (var compiler in outboundProtocolCompilers)
        {
            ArgumentNullException.ThrowIfNull(compiler);

            if (compiler.SupportedProtocols.Count == 0)
            {
                throw new InvalidOperationException("Outbound protocol compiler must declare at least one supported protocol.");
            }

            foreach (var declaredProtocol in compiler.SupportedProtocols)
            {
                var protocol = NormalizeProtocolKey(declaredProtocol);
                if (string.IsNullOrWhiteSpace(protocol))
                {
                    throw new InvalidOperationException("Outbound protocol compiler must declare a protocol.");
                }

                if (!supportedOutboundProtocols.Add(protocol))
                {
                    throw new InvalidOperationException($"Duplicate outbound protocol compiler registration: {protocol}.");
                }
            }

            materializedOutboundCompilers.Add(compiler);
        }

        _outboundProtocolCompilers = materializedOutboundCompilers;
        _supportedOutboundProtocols = supportedOutboundProtocols;
    }

    public NodeServiceConfig Normalize(NodeServiceConfig config)
    {
        ArgumentNullException.ThrowIfNull(config);

        var limits = config.Limits ?? new InboundLimitsConfig();
        var telemetry = config.Telemetry ?? new TelemetryOptions();
        var normalized = config with
        {
            Inbounds = config.Inbounds ?? Array.Empty<InboundConfig>(),
            ProxyInbounds = NormalizeProxyInbounds(config.ProxyInbounds),
            Outbounds = NormalizeOutbounds(config.Outbounds),
            RoutingRules = NormalizeRoutingRules(config.RoutingRules),
            RoutingResources = NormalizeRoutingResources(config.RoutingResources),
            Certificate = NormalizeCertificateOptions(config.Certificate),
            Dns = NormalizeDnsOptions(config.Dns),
            Limits = limits with
            {
                GlobalBytesPerSecond = Math.Max(0, limits.GlobalBytesPerSecond),
                ConnectTimeoutSeconds = NormalizePositive(limits.ConnectTimeoutSeconds, 10),
                ConnectionIdleSeconds = NormalizePositive(limits.ConnectionIdleSeconds, 300),
                UplinkOnlySeconds = NormalizePositive(limits.UplinkOnlySeconds, 1),
                DownlinkOnlySeconds = NormalizePositive(limits.DownlinkOnlySeconds, 1)
            },
            Policy = NormalizePolicyOptions(config.Policy),
            Telemetry = telemetry with
            {
                FlushIntervalSeconds = NormalizePositive(telemetry.FlushIntervalSeconds, 15)
            },
            Users = config.Users ?? Array.Empty<TrojanUserConfig>(),
            Fallbacks = config.Fallbacks ?? Array.Empty<TrojanFallbackConfig>()
        };

        foreach (var compiler in _inboundProtocolCompilers)
        {
            normalized = compiler.Normalize(normalized);
        }

        foreach (var compiler in _outboundProtocolCompilers)
        {
            normalized = compiler.Normalize(normalized);
        }

        return normalized;
    }

    public bool TryBuild(
        int revision,
        NodeServiceConfig config,
        IReadOnlyList<string> supportedOutboundProtocols,
        out NodeRuntimeSnapshot snapshot,
        out string? error)
    {
        var normalized = Normalize(config);
        return TryBuildNormalized(revision, normalized, supportedOutboundProtocols, out snapshot, out error);
    }

    public bool TryBuildNormalized(
        int revision,
        NodeServiceConfig config,
        IReadOnlyList<string> supportedOutboundProtocols,
        out NodeRuntimeSnapshot snapshot,
        out string? error)
    {
        ArgumentNullException.ThrowIfNull(config);
        ArgumentNullException.ThrowIfNull(supportedOutboundProtocols);

        if (!ValidateInboundProtocolCoverage(config.Inbounds, out error))
        {
            snapshot = CreateEmptySnapshot(revision, config);
            return false;
        }

        if (!TryBuildInboundPlans(config, out var inboundPlans, out var activeUsers, out var requiresCertificate, out error))
        {
            snapshot = CreateEmptySnapshot(revision, config);
            return false;
        }

        if (!ValidateCertificateOptions(config.Certificate, requiresCertificate, out error))
        {
            snapshot = CreateEmptySnapshot(revision, config);
            return false;
        }

        if (!ValidateDnsOptions(config.Dns, out error))
        {
            snapshot = CreateEmptySnapshot(revision, config);
            return false;
        }

        if (!ValidateProxyInboundDefinitions(config.ProxyInbounds, out error))
        {
            snapshot = CreateEmptySnapshot(revision, config);
            return false;
        }

        if (!ValidateOutboundProtocolCoverage(config.Outbounds, out error))
        {
            snapshot = CreateEmptySnapshot(revision, config);
            return false;
        }

        if (!ValidateOutboundDefinitions(config, out error))
        {
            snapshot = CreateEmptySnapshot(revision, config);
            return false;
        }

        var additionalOutboundTags = CollectDynamicOutboundTags(activeUsers);
        if (!ValidateDynamicOutboundTags(config.Outbounds, additionalOutboundTags, out error))
        {
            snapshot = CreateEmptySnapshot(revision, config);
            return false;
        }

        if (!RoutingResourceExpander.TryExpand(config, out config, out error))
        {
            snapshot = CreateEmptySnapshot(revision, config);
            return false;
        }

        if (!OutboundRuntimePlanner.TryBuild(
                config.Outbounds,
                config.RoutingRules,
                supportedOutboundProtocols,
                out var outboundPlan,
                out error,
                additionalOutboundTags))
        {
            snapshot = CreateEmptySnapshot(revision, config);
            return false;
        }

        snapshot = new NodeRuntimeSnapshot
        {
            Revision = Math.Max(0, revision),
            Config = config,
            Plan = new NodeRuntimePlan
            {
                Inbounds = inboundPlans,
                Outbound = outboundPlan
            },
            TransportLimits = CreateTransportLimits(config.Limits),
            SessionPolicies = CreateSessionPolicies(config.Limits, config.Policy),
            Dns = CreateDnsSettings(config.Dns),
            ProxyInbounds = CreateProxyInboundPlan(config.ProxyInbounds),
            OutboundSettings = CreateOutboundSettings(config),
            ActiveUsers = activeUsers.ToArray()
        };
        error = null;
        return true;
    }

    private static IReadOnlyList<string> CollectDynamicOutboundTags(IReadOnlyList<IRuntimeUserDefinition> activeUsers)
        => activeUsers
            .OfType<VlessUser>()
            .Select(static user => NormalizeOptionalTag(user.ReverseTag))
            .Where(static tag => !string.IsNullOrWhiteSpace(tag))
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .ToArray();

    private static bool ValidateDynamicOutboundTags(
        IReadOnlyList<OutboundConfig> outbounds,
        IReadOnlyList<string> additionalOutboundTags,
        out string? error)
    {
        if (additionalOutboundTags.Count == 0)
        {
            error = null;
            return true;
        }

        var configuredTags = new HashSet<string>(
            outbounds
                .Where(static outbound => outbound.Enabled)
                .Select(static outbound => NormalizeOptionalTag(outbound.Tag))
                .Where(static tag => !string.IsNullOrWhiteSpace(tag)),
            StringComparer.OrdinalIgnoreCase);

        foreach (var tag in additionalOutboundTags)
        {
            if (configuredTags.Contains(tag))
            {
                error = $"Dynamic VLESS reverse tag conflicts with configured outbound tag: {tag}.";
                return false;
            }
        }

        error = null;
        return true;
    }

    private static string NormalizeOptionalTag(string? value)
        => string.IsNullOrWhiteSpace(value) ? string.Empty : value.Trim();

    private bool TryBuildInboundPlans(
        NodeServiceConfig config,
        out InboundRuntimePlanCollection inboundPlans,
        out IReadOnlyList<IRuntimeUserDefinition> activeUsers,
        out bool requiresCertificate,
        out string? error)
    {
        var compiledPlans = new List<IInboundProtocolRuntimePlan>(_inboundProtocolCompilers.Count);
        var users = new List<IRuntimeUserDefinition>();

        foreach (var compiler in _inboundProtocolCompilers)
        {
            if (!compiler.TryCompile(config, out var compilation, out error))
            {
                inboundPlans = InboundRuntimePlanCollection.Empty;
                activeUsers = Array.Empty<IRuntimeUserDefinition>();
                requiresCertificate = false;
                return false;
            }

            compiledPlans.Add(compilation.Plan);
            users.AddRange(compilation.ActiveUsers);
        }

        inboundPlans = InboundRuntimePlanCollection.Create(compiledPlans);
        activeUsers = users.ToArray();
        requiresCertificate = inboundPlans.RequiresCertificate;
        error = null;
        return true;
    }

    private bool ValidateOutboundProtocolCoverage(IReadOnlyList<OutboundConfig> outbounds, out string? error)
    {
        foreach (var outbound in outbounds)
        {
            if (!outbound.Enabled)
            {
                continue;
            }

            var protocol = OutboundProtocols.Normalize(outbound.Protocol);
            if (_supportedOutboundProtocols.Contains(protocol))
            {
                continue;
            }

            error = $"Unsupported outbound protocol: {protocol}.";
            return false;
        }

        error = null;
        return true;
    }

    private bool ValidateInboundProtocolCoverage(IReadOnlyList<InboundConfig> inbounds, out string? error)
    {
        foreach (var inbound in inbounds)
        {
            if (!inbound.Enabled)
            {
                continue;
            }

            var protocol = InboundProtocols.Normalize(inbound.Protocol);
            if (_supportedInboundProtocols.Contains(protocol))
            {
                continue;
            }

            error = $"Unsupported inbound protocol: {protocol}.";
            return false;
        }

        error = null;
        return true;
    }

    private static RuntimeTransportLimits CreateTransportLimits(InboundLimitsConfig limits)
        => new()
        {
            GlobalBytesPerSecond = limits.GlobalBytesPerSecond,
            ConnectTimeoutSeconds = limits.ConnectTimeoutSeconds,
            ConnectionIdleSeconds = limits.ConnectionIdleSeconds,
            UplinkOnlySeconds = limits.UplinkOnlySeconds,
            DownlinkOnlySeconds = limits.DownlinkOnlySeconds
        };

    private static RuntimeSessionPolicyCatalog CreateSessionPolicies(
        InboundLimitsConfig limits,
        PolicyConfig policy)
    {
        ArgumentNullException.ThrowIfNull(limits);
        ArgumentNullException.ThrowIfNull(policy);

        var defaultPolicy = new RuntimeSessionPolicy
        {
            Timeout = new RuntimeSessionPolicyTimeouts
            {
                HandshakeSeconds = 60,
                ConnectionIdleSeconds = limits.ConnectionIdleSeconds,
                UplinkOnlySeconds = limits.UplinkOnlySeconds,
                DownlinkOnlySeconds = limits.DownlinkOnlySeconds
            }
        };

        var levels = new Dictionary<int, RuntimeSessionPolicy>();
        foreach (var (level, entry) in policy.Level)
        {
            if (level < 0)
            {
                continue;
            }

            levels[level] = new RuntimeSessionPolicy
            {
                Timeout = new RuntimeSessionPolicyTimeouts
                {
                    HandshakeSeconds = NormalizeOptionalPositive(
                        entry.Timeout.Handshake,
                        defaultPolicy.Timeout.HandshakeSeconds),
                    ConnectionIdleSeconds = NormalizeOptionalPositive(
                        entry.Timeout.ConnectionIdle,
                        defaultPolicy.Timeout.ConnectionIdleSeconds),
                    UplinkOnlySeconds = NormalizeOptionalPositive(
                        entry.Timeout.UplinkOnly,
                        defaultPolicy.Timeout.UplinkOnlySeconds),
                    DownlinkOnlySeconds = NormalizeOptionalPositive(
                        entry.Timeout.DownlinkOnly,
                        defaultPolicy.Timeout.DownlinkOnlySeconds)
                }
            };
        }

        return new RuntimeSessionPolicyCatalog
        {
            DefaultPolicy = defaultPolicy,
            Levels = levels
        };
    }

    private static DnsRuntimeSettings CreateDnsSettings(DnsOptions options)
        => new()
        {
            Mode = DnsModes.Normalize(options.Mode),
            TimeoutSeconds = options.TimeoutSeconds,
            CacheTtlSeconds = options.CacheTtlSeconds,
            Servers = options.Servers
                .Select(static server => new DnsHttpServerRuntime
                {
                    Url = server.Url,
                    Headers = server.Headers.ToDictionary(
                        static pair => pair.Key,
                        static pair => pair.Value,
                        StringComparer.OrdinalIgnoreCase)
                })
                .ToArray()
        };

    private static PolicyConfig NormalizePolicyOptions(PolicyConfig? options)
    {
        var normalizedOptions = options ?? new PolicyConfig();

        var normalized = new Dictionary<int, SessionLevelPolicyConfig>();
        foreach (var (level, entry) in normalizedOptions.Level ?? new Dictionary<int, SessionLevelPolicyConfig>())
        {
            if (level < 0)
            {
                continue;
            }

            var timeout = entry?.Timeout ?? new SessionTimeoutPolicyConfig();
            normalized[level] = new SessionLevelPolicyConfig
            {
                Timeout = new SessionTimeoutPolicyConfig
                {
                    Handshake = NormalizeOptionalPositive(timeout.Handshake),
                    ConnectionIdle = NormalizeOptionalPositive(timeout.ConnectionIdle),
                    UplinkOnly = NormalizeOptionalPositive(timeout.UplinkOnly),
                    DownlinkOnly = NormalizeOptionalPositive(timeout.DownlinkOnly)
                }
            };
        }

        return normalizedOptions with
        {
            Level = normalized
        };
    }

    private static ProxyInboundRuntimePlan CreateProxyInboundPlan(IReadOnlyList<ProxyInboundConfig> proxyInbounds)
    {
        var socksListeners = new List<ProxyInboundListenerDefinition>();
        var httpListeners = new List<ProxyInboundListenerDefinition>();
        var socksAuthenticationsByTag = new Dictionary<string, Socks5LocalAuthenticationOptions>(StringComparer.OrdinalIgnoreCase);
        var httpAuthenticationsByTag = new Dictionary<string, Socks5LocalAuthenticationOptions>(StringComparer.OrdinalIgnoreCase);

        foreach (var inbound in proxyInbounds.Where(static inbound => inbound.Enabled))
        {
            var protocol = ProxyInboundProtocols.Normalize(inbound.Protocol);
            var listener = new ProxyInboundListenerDefinition
            {
                Tag = inbound.Tag,
                Binding = new ListenerBinding(inbound.ListenAddress, inbound.Port),
                UserLevel = Math.Max(0, inbound.UserLevel),
                HandshakeTimeoutSeconds = inbound.HandshakeTimeoutSeconds,
                AllowTransparent = string.Equals(protocol, ProxyInboundProtocols.Http, StringComparison.Ordinal) && inbound.AllowTransparent
            };

            if (string.Equals(protocol, ProxyInboundProtocols.Http, StringComparison.Ordinal))
            {
                httpListeners.Add(listener);
                if (inbound.HttpUsers.Count > 0)
                {
                    httpAuthenticationsByTag[listener.Tag] = CreateLocalAuthenticationOptions(inbound.HttpUsers);
                }

                continue;
            }

            socksListeners.Add(listener);
            if (inbound.SocksUsers.Count > 0)
            {
                socksAuthenticationsByTag[listener.Tag] = CreateLocalAuthenticationOptions(inbound.SocksUsers);
            }
        }

        return new ProxyInboundRuntimePlan
        {
            SocksListeners = socksListeners.ToArray(),
            HttpListeners = httpListeners.ToArray(),
            SocksAuthenticationsByTag = socksAuthenticationsByTag,
            HttpAuthenticationsByTag = httpAuthenticationsByTag
        };
    }

    private static Socks5LocalAuthenticationOptions CreateLocalAuthenticationOptions(
        IEnumerable<LocalSocksUserConfig> users)
        => Socks5LocalAuthenticationOptions.Create(
            users.Select(static user => new Socks5LocalUserCredential
            {
                Username = user.Username,
                Password = user.Password
            }));

    private RuntimeOutboundSettingsCatalog CreateOutboundSettings(NodeServiceConfig config)
        => RuntimeOutboundSettingsCatalog.Create(
            _outboundProtocolCompilers
                .SelectMany(compiler => compiler.BuildRuntimeOptions(config))
                .ToArray());

    private static NodeRuntimeSnapshot CreateEmptySnapshot(int revision, NodeServiceConfig config)
        => NodeRuntimeSnapshot.Empty with
        {
            Revision = Math.Max(0, revision),
            Config = config
        };

    private static bool ValidateCertificateOptions(
        CertificateOptions certificate,
        bool requiresCertificate,
        out string? error)
    {
        var certificateMode = CertificateModes.Normalize(certificate.Mode);

        if (requiresCertificate && certificateMode == CertificateModes.Disabled)
        {
            error = "A TLS certificate mode is required when an inbound listener requires TLS certificates.";
            return false;
        }

        if (requiresCertificate && string.IsNullOrWhiteSpace(certificate.PfxPath))
        {
            error = "A TLS certificate is required when an inbound listener requires TLS certificates.";
            return false;
        }

        if (certificateMode == CertificateModes.AcmeExternal)
        {
            if (string.IsNullOrWhiteSpace(certificate.Domain))
            {
                error = "ACME external mode requires a primary domain.";
                return false;
            }

            if (string.IsNullOrWhiteSpace(certificate.PfxPath))
            {
                error = "ACME external mode requires a PFX output path.";
                return false;
            }

            if (string.IsNullOrWhiteSpace(certificate.ExternalToolPath))
            {
                error = "ACME external mode requires an external tool path.";
                return false;
            }
        }

        if (certificateMode == CertificateModes.AcmeManaged)
        {
            if (string.IsNullOrWhiteSpace(certificate.Domain))
            {
                error = "ACME managed mode requires a primary domain.";
                return false;
            }

            if (string.IsNullOrWhiteSpace(certificate.PfxPath))
            {
                error = "ACME managed mode requires a PFX output path.";
                return false;
            }

            if (!string.Equals(certificate.ChallengeType, CertificateChallengeTypes.Http01, StringComparison.Ordinal))
            {
                error = "ACME managed mode currently supports only http-01.";
                return false;
            }

            if (!IPAddress.TryParse(certificate.HttpChallengeListenAddress, out _))
            {
                error = $"Invalid HTTP-01 listen address: {certificate.HttpChallengeListenAddress}.";
                return false;
            }

            if (certificate.HttpChallengePort is <= 0 or > 65535)
            {
                error = $"Invalid HTTP-01 port: {certificate.HttpChallengePort}.";
                return false;
            }
        }

        if (certificateMode == CertificateModes.PanelDistributed)
        {
            if (string.IsNullOrWhiteSpace(certificate.PanelCertificateId))
            {
                error = "Panel distributed certificate mode requires a panel certificate id.";
                return false;
            }

            if (string.IsNullOrWhiteSpace(certificate.PfxPath))
            {
                error = "Panel distributed certificate mode requires a local cache path.";
                return false;
            }
        }

        error = null;
        return true;
    }

    private bool ValidateOutboundDefinitions(NodeServiceConfig config, out string? error)
    {
        foreach (var compiler in _outboundProtocolCompilers)
        {
            if (!compiler.TryValidate(config, out error))
            {
                return false;
            }
        }

        error = null;
        return true;
    }

    private static bool ValidateProxyInboundDefinitions(IReadOnlyList<ProxyInboundConfig> proxyInbounds, out string? error)
    {
        var seenTags = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        var seenBindings = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

        foreach (var inbound in proxyInbounds)
        {
            if (!inbound.Enabled)
            {
                continue;
            }

            var tag = inbound.Tag.Trim();
            if (tag.Length == 0)
            {
                error = "Local inbound tag cannot be empty.";
                return false;
            }

            if (!seenTags.Add(tag))
            {
                error = $"Duplicate local inbound tag: {tag}.";
                return false;
            }

            var protocol = ProxyInboundProtocols.Normalize(inbound.Protocol);
            if (protocol is not (ProxyInboundProtocols.Socks or ProxyInboundProtocols.Http))
            {
                error = $"Unsupported proxy inbound protocol: {inbound.Protocol}.";
                return false;
            }

            var normalizedAddress = NormalizeProxyInboundListenAddress(inbound.ListenAddress);
            var normalizedPort = NormalizeProxyInboundPort(inbound.Port);
            var bindingKey = $"{normalizedAddress}:{normalizedPort}";
            if (!seenBindings.Add(bindingKey))
            {
                error = $"Duplicate local inbound binding: {bindingKey}.";
                return false;
            }
        }

        error = null;
        return true;
    }

    private static CertificateOptions NormalizeCertificateOptions(CertificateOptions? options)
    {
        var normalizedOptions = options ?? new CertificateOptions();
        var normalizedMode = CertificateModes.Normalize(normalizedOptions.Mode);
        var altNames = (normalizedOptions.AltNames ?? Array.Empty<string>())
            .Where(static name => !string.IsNullOrWhiteSpace(name))
            .Select(static name => name.Trim())
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .ToArray();

        var environmentVariables = (normalizedOptions.EnvironmentVariables ?? Array.Empty<CertificateEnvironmentVariable>())
            .Where(static item => !string.IsNullOrWhiteSpace(item.Name))
            .Select(static item => item with
            {
                Name = item.Name.Trim(),
                Value = item.Value.Trim()
            })
            .ToArray();

        return normalizedOptions with
        {
            Mode = normalizedMode,
            PfxPath = ResolveCertificatePath(
                normalizedMode,
                normalizedOptions.PfxPath,
                normalizedOptions.PanelCertificateId,
                normalizedOptions.Domain),
            PfxPassword = normalizedOptions.PfxPassword.Trim(),
            PanelCertificateId = normalizedOptions.PanelCertificateId.Trim(),
            DistributedAsset = NormalizeDistributedCertificateAsset(normalizedOptions.DistributedAsset),
            Domain = normalizedOptions.Domain.Trim(),
            AltNames = altNames,
            Email = normalizedOptions.Email.Trim(),
            AcmeDirectoryUrl = normalizedOptions.AcmeDirectoryUrl.Trim(),
            ChallengeType = CertificateChallengeTypes.Normalize(normalizedOptions.ChallengeType),
            RenewBeforeDays = Math.Max(1, normalizedOptions.RenewBeforeDays),
            CheckIntervalMinutes = NormalizePositive(normalizedOptions.CheckIntervalMinutes, 60),
            HttpChallengeListenAddress = NormalizeListenAddress(normalizedOptions.HttpChallengeListenAddress),
            HttpChallengePort = NormalizePort(normalizedOptions.HttpChallengePort, 80),
            ExternalTimeoutSeconds = NormalizePositive(normalizedOptions.ExternalTimeoutSeconds, 300),
            ClientHelloPolicy = NormalizeClientHelloPolicyOptions(normalizedOptions.ClientHelloPolicy),
            ExternalToolPath = normalizedOptions.ExternalToolPath.Trim(),
            ExternalArguments = normalizedOptions.ExternalArguments.Trim(),
            WorkingDirectory = normalizedOptions.WorkingDirectory.Trim(),
            EnvironmentVariables = environmentVariables
        };
    }

    private static DistributedCertificateAsset NormalizeDistributedCertificateAsset(DistributedCertificateAsset? asset)
    {
        var normalizedAsset = asset ?? new DistributedCertificateAsset();
        return normalizedAsset with
        {
            PfxBase64 = normalizedAsset.PfxBase64.Trim(),
            Thumbprint = normalizedAsset.Thumbprint.Trim()
        };
    }

    private static string ResolveCertificatePath(string mode, string path, string panelCertificateId, string domain)
    {
        var normalizedPath = path.Trim();
        if (!string.IsNullOrWhiteSpace(normalizedPath))
        {
            return normalizedPath;
        }

        if (mode == CertificateModes.AcmeManaged)
        {
            var fileName = string.IsNullOrWhiteSpace(domain)
                ? "acme-managed.pfx"
                : $"{SanitizeFileName(domain)}.pfx";

            return Path.GetFullPath(Path.Combine(AppContext.BaseDirectory, "certificates", "acme-managed", fileName));
        }

        if (mode == CertificateModes.PanelDistributed)
        {
            var fileName = string.IsNullOrWhiteSpace(panelCertificateId)
                ? "panel-distributed.pfx"
                : $"{SanitizeFileName(panelCertificateId)}.pfx";

            return Path.GetFullPath(Path.Combine(AppContext.BaseDirectory, "certificates", fileName));
        }

        return normalizedPath;
    }

    private static string SanitizeFileName(string value)
    {
        var invalid = Path.GetInvalidFileNameChars();
        var buffer = value
            .Trim()
            .Select(static ch => ch)
            .ToArray();

        for (var index = 0; index < buffer.Length; index++)
        {
            if (invalid.Contains(buffer[index]))
            {
                buffer[index] = '-';
            }
        }

        return new string(buffer);
    }

    private static TlsClientHelloPolicyConfig NormalizeClientHelloPolicyOptions(TlsClientHelloPolicyConfig? options)
    {
        var normalizedOptions = options ?? new TlsClientHelloPolicyConfig();
        return normalizedOptions with
        {
            AllowedServerNames = NormalizeLowerStringList(normalizedOptions.AllowedServerNames),
            BlockedServerNames = NormalizeLowerStringList(normalizedOptions.BlockedServerNames),
            AllowedApplicationProtocols = NormalizeLowerStringList(normalizedOptions.AllowedApplicationProtocols),
            BlockedApplicationProtocols = NormalizeLowerStringList(normalizedOptions.BlockedApplicationProtocols),
            AllowedJa3 = NormalizeLowerStringList(normalizedOptions.AllowedJa3),
            BlockedJa3 = NormalizeLowerStringList(normalizedOptions.BlockedJa3)
        };
    }

    private static DnsOptions NormalizeDnsOptions(DnsOptions? options)
    {
        var normalizedOptions = options ?? new DnsOptions();
        var servers = (normalizedOptions.Servers ?? Array.Empty<DnsHttpServerConfig>())
            .Where(static server => !string.IsNullOrWhiteSpace(server.Url))
            .Select(static server => server with
            {
                Url = server.Url.Trim(),
                Headers = NormalizeHeaderDictionary(server.Headers)
            })
            .ToArray();

        return normalizedOptions with
        {
            Mode = DnsModes.Normalize(normalizedOptions.Mode),
            TimeoutSeconds = NormalizePositive(normalizedOptions.TimeoutSeconds, 5),
            CacheTtlSeconds = Math.Max(0, normalizedOptions.CacheTtlSeconds),
            Servers = servers
        };
    }

    private static IReadOnlyList<OutboundConfig> NormalizeOutbounds(IReadOnlyList<OutboundConfig>? outbounds)
    {
        if (outbounds is null || outbounds.Count == 0)
        {
            return
            [
                new OutboundConfig
                {
                    Tag = "direct",
                    Enabled = true,
                    Protocol = OutboundProtocols.Freedom
                }
            ];
        }

        return outbounds
            .Where(static outbound => outbound is not null && !string.IsNullOrWhiteSpace(outbound.Tag))
            .Select(static outbound => NormalizeOutbound(outbound!))
            .ToArray();
    }

    private static IReadOnlyList<ProxyInboundConfig> NormalizeProxyInbounds(IReadOnlyList<ProxyInboundConfig>? proxyInbounds)
        => (proxyInbounds ?? Array.Empty<ProxyInboundConfig>())
            .Where(static inbound => inbound is not null && !string.IsNullOrWhiteSpace(inbound.Tag))
            .Select(static inbound => inbound with
            {
                Tag = inbound!.Tag.Trim(),
                Protocol = ProxyInboundProtocols.Normalize(inbound.Protocol),
                ListenAddress = NormalizeProxyInboundListenAddress(inbound.ListenAddress),
                Port = NormalizeProxyInboundPort(inbound.Port),
                UserLevel = Math.Max(0, inbound.UserLevel),
                HandshakeTimeoutSeconds = NormalizePositive(inbound.HandshakeTimeoutSeconds, 10),
                SocksUsers = NormalizeLocalProxyUsers(inbound.SocksUsers),
                HttpUsers = NormalizeLocalProxyUsers(inbound.HttpUsers)
            })
            .ToArray();

    private static IReadOnlyList<RoutingRuleConfig> NormalizeRoutingRules(IReadOnlyList<RoutingRuleConfig>? routingRules)
        => (routingRules ?? Array.Empty<RoutingRuleConfig>())
            .Where(static rule => rule is not null && !string.IsNullOrWhiteSpace(rule.OutboundTag))
            .Select(static rule => rule with
            {
                RuleTag = rule!.RuleTag?.Trim() ?? string.Empty,
                InboundTags = NormalizeStringList(rule.InboundTags),
                Protocols = NormalizeStringList(rule.Protocols)
                    .Select(static value => RoutingProtocols.Normalize(value))
                    .Where(static value => !string.IsNullOrWhiteSpace(value))
                    .Distinct(StringComparer.OrdinalIgnoreCase)
                    .ToArray(),
                Networks = NormalizeStringList(rule.Networks)
                    .Select(static value => RoutingNetworks.Normalize(value))
                    .Distinct(StringComparer.OrdinalIgnoreCase)
                    .ToArray(),
                UserIds = NormalizeTrimmedStringList(rule.UserIds)
                    .Distinct(StringComparer.Ordinal)
                    .ToArray(),
                Processes = NormalizeTrimmedStringList(rule.Processes)
                    .Distinct(StringComparer.Ordinal)
                    .ToArray(),
                Domains = NormalizeStringList(rule.Domains),
                SourceCidrs = NormalizeStringList(rule.SourceCidrs),
                DestinationCidrs = NormalizeStringList(rule.DestinationCidrs),
                DestinationPorts = NormalizeStringList(rule.DestinationPorts),
                SourcePorts = NormalizeStringList(rule.SourcePorts),
                LocalCidrs = NormalizeStringList(rule.LocalCidrs),
                LocalPorts = NormalizeStringList(rule.LocalPorts),
                VlessRoutes = NormalizeStringList(rule.VlessRoutes),
                Attributes = NormalizeRoutingAttributeDictionary(rule.Attributes),
                OutboundTag = rule.OutboundTag.Trim()
            })
            .ToArray();

    private static IReadOnlyList<LocalSocksUserConfig> NormalizeLocalProxyUsers(IReadOnlyList<LocalSocksUserConfig>? users)
        => (users ?? Array.Empty<LocalSocksUserConfig>())
            .Where(static user => user is not null && !string.IsNullOrWhiteSpace(user.Username))
            .Select(static user => user! with
            {
                Username = user.Username.Trim()
            })
            .ToArray();

    private static RoutingResourceOptions NormalizeRoutingResources(RoutingResourceOptions? resources)
    {
        var normalized = resources ?? new RoutingResourceOptions();
        return normalized with
        {
            ResourceDirectory = normalized.ResourceDirectory?.Trim() ?? string.Empty,
            GeoSitePath = normalized.GeoSitePath?.Trim() ?? string.Empty,
            GeoIpPath = normalized.GeoIpPath?.Trim() ?? string.Empty
        };
    }

    private static OutboundConfig NormalizeOutbound(OutboundConfig outbound)
        => OutboundRuntimeCompilerUtilities.Normalize(outbound);

    private static string NormalizeListenAddress(string value)
        => string.IsNullOrWhiteSpace(value) ? "0.0.0.0" : value.Trim();

    private static string NormalizeProxyInboundListenAddress(string value)
        => string.IsNullOrWhiteSpace(value) ? "127.0.0.1" : value.Trim();

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

    private static IReadOnlyDictionary<string, string> NormalizeRoutingAttributeDictionary(IReadOnlyDictionary<string, string>? attributes)
    {
        var normalized = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        if (attributes is null)
        {
            return normalized;
        }

        foreach (var (name, value) in attributes)
        {
            if (string.IsNullOrWhiteSpace(name))
            {
                continue;
            }

            normalized[name.Trim()] = value?.Trim() ?? string.Empty;
        }

        return normalized;
    }

    private static IReadOnlyList<string> NormalizeStringList(IReadOnlyList<string>? values)
        => (values ?? Array.Empty<string>())
            .Where(static value => !string.IsNullOrWhiteSpace(value))
            .Select(static value => value.Trim())
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .ToArray();

    private static IReadOnlyList<string> NormalizeTrimmedStringList(IReadOnlyList<string>? values)
        => (values ?? Array.Empty<string>())
            .Where(static value => !string.IsNullOrWhiteSpace(value))
            .Select(static value => value.Trim())
            .ToArray();

    private static IReadOnlyList<string> NormalizeLowerStringList(IReadOnlyList<string>? values)
        => NormalizeStringList(values)
            .Select(static value => value.ToLowerInvariant())
            .ToArray();

    private static int NormalizePort(int value, int fallback)
        => value is > 0 and <= 65535 ? value : fallback;

    private static int NormalizeProxyInboundPort(int value)
        => value is >= 0 and <= 65535 ? value : 10808;

    private static int NormalizePositive(int value, int fallback)
        => value > 0 ? value : fallback;

    private static int? NormalizeOptionalPositive(int? value, int? fallback = null)
        => value is > 0 ? value.Value : fallback;

    private static int NormalizeOptionalPositive(int? value, int fallback)
        => value is > 0 ? value.Value : fallback;

    private static string NormalizeProtocolKey(string? value)
        => string.IsNullOrWhiteSpace(value)
            ? string.Empty
            : value.Trim().ToLowerInvariant();

    private static IReadOnlyList<IOutboundProtocolRuntimeCompiler> CreateDefaultOutboundProtocolCompilers()
        =>
        [
            new BuiltinOutboundRuntimeCompiler(),
            new ShadowsocksOutboundRuntimeCompiler(),
            new HttpOutboundRuntimeCompiler(),
            new SocksOutboundRuntimeCompiler(),
            new TrojanOutboundRuntimeCompiler(),
            new VlessOutboundRuntimeCompiler(),
            new VmessOutboundRuntimeCompiler()
        ];

    private static bool ValidateDnsOptions(DnsOptions options, out string? error)
    {
        if (!string.Equals(options.Mode, DnsModes.Http, StringComparison.Ordinal))
        {
            error = null;
            return true;
        }

        if (options.Servers.Count == 0)
        {
            error = "HTTP DNS mode requires at least one configured server.";
            return false;
        }

        foreach (var server in options.Servers)
        {
            if (!Uri.TryCreate(server.Url, UriKind.Absolute, out var uri) ||
                uri.Scheme is not ("http" or "https"))
            {
                error = $"HTTP DNS server URL is invalid: {server.Url}.";
                return false;
            }
        }

        error = null;
        return true;
    }
}

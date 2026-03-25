using System.Net;
using Microsoft.Extensions.Logging;
using NodePanel.ControlPlane.Configuration;
using NodePanel.ControlPlane.Protocol;
using NodePanel.Core.Runtime;

namespace NodePanel.Service.Runtime;

public sealed class ConfigOrchestrator
{
    private readonly SemaphoreSlim _applyLock = new(1, 1);
    private readonly IReadOnlyList<IInboundProtocolRuntimeCompiler> _inboundProtocolCompilers;
    private readonly ILogger<ConfigOrchestrator> _logger;
    private readonly PersistedNodeConfigStore _persistedNodeConfigStore;
    private readonly RateLimiterRegistry _rateLimiterRegistry;
    private readonly RuntimeConfigStore _runtimeConfigStore;
    private readonly IReadOnlyList<string> _supportedOutboundProtocols;
    private readonly HashSet<string> _supportedInboundProtocols;
    private readonly UserStore _userStore;

    public ConfigOrchestrator(
        RuntimeConfigStore runtimeConfigStore,
        UserStore userStore,
        RateLimiterRegistry rateLimiterRegistry,
        IEnumerable<IOutboundHandler> outboundHandlers,
        IEnumerable<IInboundProtocolRuntimeCompiler> inboundProtocolCompilers,
        PersistedNodeConfigStore persistedNodeConfigStore,
        ILogger<ConfigOrchestrator> logger)
    {
        ArgumentNullException.ThrowIfNull(outboundHandlers);
        ArgumentNullException.ThrowIfNull(inboundProtocolCompilers);

        _runtimeConfigStore = runtimeConfigStore;
        _userStore = userStore;
        _rateLimiterRegistry = rateLimiterRegistry;
        _supportedOutboundProtocols = outboundHandlers
            .Select(static handler => OutboundProtocols.Normalize(handler.Protocol))
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .ToArray();

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
        _persistedNodeConfigStore = persistedNodeConfigStore;
        _logger = logger;
    }

    public void ApplyBootstrap(NodeServiceConfig config, int revision = 0)
    {
        var normalized = Normalize(config);
        if (!TryCreateRuntimeSnapshot(revision, normalized, out var snapshot, out var activeUsers, out var error))
        {
            throw new InvalidOperationException(error ?? "Bootstrap config is invalid.");
        }

        _userStore.Replace(activeUsers);
        _rateLimiterRegistry.Apply(normalized.Limits, activeUsers);
        _runtimeConfigStore.Bootstrap(snapshot);
        TryPersist(revision, normalized);
    }

    public async ValueTask<ApplyResultPayload> ApplySnapshotAsync(int revision, NodeServiceConfig config, CancellationToken cancellationToken)
    {
        await _applyLock.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            var normalized = Normalize(config);
            if (!TryMaterializeDistributedCertificate(normalized.Certificate, out var certificate, out var assetError))
            {
                return new ApplyResultPayload
                {
                    RequestedRevision = revision,
                    Success = false,
                    Error = assetError
                };
            }

            normalized = normalized with
            {
                Certificate = certificate
            };

            if (!TryCreateRuntimeSnapshot(revision, normalized, out var snapshot, out var activeUsers, out var error))
            {
                return new ApplyResultPayload
                {
                    RequestedRevision = revision,
                    Success = false,
                    Error = error
                };
            }

            _userStore.Replace(activeUsers);
            _rateLimiterRegistry.Apply(normalized.Limits, activeUsers);

            if (!_runtimeConfigStore.TryCommit(snapshot, out error))
            {
                return new ApplyResultPayload
                {
                    RequestedRevision = revision,
                    Success = false,
                    Error = error
                };
            }

            TryPersist(revision, normalized);

            return new ApplyResultPayload
            {
                RequestedRevision = revision,
                Success = true
            };
        }
        finally
        {
            _applyLock.Release();
        }
    }

    private NodeServiceConfig Normalize(NodeServiceConfig config)
    {
        var normalized = config with
        {
            LocalInbounds = NormalizeLocalInbounds(config.LocalInbounds),
            Outbounds = NormalizeOutbounds(config.Outbounds),
            RoutingRules = NormalizeRoutingRules(config.RoutingRules),
            Certificate = NormalizeCertificateOptions(config.Certificate),
            Dns = NormalizeDnsOptions(config.Dns),
            Limits = config.Limits with
            {
                GlobalBytesPerSecond = Math.Max(0, config.Limits.GlobalBytesPerSecond),
                ConnectTimeoutSeconds = NormalizePositive(config.Limits.ConnectTimeoutSeconds, 10),
                ConnectionIdleSeconds = NormalizePositive(config.Limits.ConnectionIdleSeconds, 300),
                UplinkOnlySeconds = NormalizePositive(config.Limits.UplinkOnlySeconds, 1),
                DownlinkOnlySeconds = NormalizePositive(config.Limits.DownlinkOnlySeconds, 1)
            },
            Telemetry = config.Telemetry with
            {
                FlushIntervalSeconds = NormalizePositive(config.Telemetry.FlushIntervalSeconds, 15)
            }
        };

        foreach (var compiler in _inboundProtocolCompilers)
        {
            normalized = compiler.Normalize(normalized);
        }

        return normalized;
    }

    private bool TryCreateRuntimeSnapshot(
        int revision,
        NodeServiceConfig config,
        out NodeRuntimeSnapshot snapshot,
        out IReadOnlyList<IRuntimeUserDefinition> activeUsers,
        out string? error)
    {
        if (!ValidateInboundProtocolCoverage(config.Inbounds, out error))
        {
            snapshot = new NodeRuntimeSnapshot(Math.Max(0, revision), config, NodeRuntimePlan.Empty);
            activeUsers = Array.Empty<IRuntimeUserDefinition>();
            return false;
        }

        if (!TryBuildInboundPlans(config, out var inboundPlans, out activeUsers, out var requiresCertificate, out error))
        {
            snapshot = new NodeRuntimeSnapshot(Math.Max(0, revision), config, NodeRuntimePlan.Empty);
            return false;
        }

        if (!ValidateCertificateOptions(config.Certificate, requiresCertificate, out error))
        {
            snapshot = new NodeRuntimeSnapshot(Math.Max(0, revision), config, NodeRuntimePlan.Empty);
            return false;
        }

        if (!ValidateDnsOptions(config.Dns, out error))
        {
            snapshot = new NodeRuntimeSnapshot(Math.Max(0, revision), config, NodeRuntimePlan.Empty);
            return false;
        }

        if (!ValidateLocalInboundDefinitions(config.LocalInbounds, out error))
        {
            snapshot = new NodeRuntimeSnapshot(Math.Max(0, revision), config, NodeRuntimePlan.Empty);
            return false;
        }

        if (!ValidateOutboundDefinitions(config.Outbounds, out error))
        {
            snapshot = new NodeRuntimeSnapshot(Math.Max(0, revision), config, NodeRuntimePlan.Empty);
            return false;
        }

        if (!OutboundRuntimePlanner.TryBuild(
                config.Outbounds,
                config.RoutingRules,
                _supportedOutboundProtocols,
                out var outboundPlan,
                out error))
        {
            snapshot = new NodeRuntimeSnapshot(Math.Max(0, revision), config, NodeRuntimePlan.Empty);
            return false;
        }

        snapshot = new NodeRuntimeSnapshot(
            Math.Max(0, revision),
            config,
            new NodeRuntimePlan
            {
                Inbounds = inboundPlans,
                Outbound = outboundPlan
            });
        error = null;
        return true;
    }

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

    private static bool ValidateOutboundDefinitions(IReadOnlyList<OutboundConfig> outbounds, out string? error)
    {
        foreach (var outbound in outbounds)
        {
            var protocol = OutboundProtocols.Normalize(outbound.Protocol);
            if (protocol is OutboundProtocols.Selector or
                OutboundProtocols.UrlTest or
                OutboundProtocols.Fallback or
                OutboundProtocols.LoadBalance)
            {
                if (!Uri.TryCreate(outbound.ProbeUrl, UriKind.Absolute, out var probeUri) ||
                    probeUri.Scheme is not ("http" or "https"))
                {
                    error = $"Strategy outbound '{outbound.Tag}' requires a valid probe URL.";
                    return false;
                }

                continue;
            }

            if (!string.Equals(protocol, OutboundProtocols.Trojan, StringComparison.Ordinal))
            {
                continue;
            }

            if (string.IsNullOrWhiteSpace(outbound.ServerHost))
            {
                error = $"Trojan outbound '{outbound.Tag}' requires a server host.";
                return false;
            }

            if (outbound.ServerPort is <= 0 or > 65535)
            {
                error = $"Trojan outbound '{outbound.Tag}' has an invalid server port: {outbound.ServerPort}.";
                return false;
            }

            if (string.IsNullOrWhiteSpace(outbound.Password))
            {
                error = $"Trojan outbound '{outbound.Tag}' requires a password.";
                return false;
            }

            if (TrojanOutboundTransports.Normalize(outbound.Transport) is not
                (TrojanOutboundTransports.Tcp or
                 TrojanOutboundTransports.Tls or
                 TrojanOutboundTransports.Ws or
                 TrojanOutboundTransports.Wss))
            {
                error = $"Trojan outbound '{outbound.Tag}' uses an unsupported transport: {outbound.Transport}.";
                return false;
            }
        }

        error = null;
        return true;
    }

    private static bool ValidateLocalInboundDefinitions(IReadOnlyList<LocalInboundConfig> localInbounds, out string? error)
    {
        var seenTags = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        var seenBindings = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

        foreach (var inbound in localInbounds)
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

            var protocol = LocalInboundProtocols.Normalize(inbound.Protocol);
            if (protocol is not (LocalInboundProtocols.Socks or LocalInboundProtocols.Http))
            {
                error = $"Unsupported local inbound protocol: {inbound.Protocol}.";
                return false;
            }

            var normalizedAddress = NormalizeLocalInboundListenAddress(inbound.ListenAddress);
            var normalizedPort = NormalizeLocalInboundPort(inbound.Port);
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

    private static CertificateOptions NormalizeCertificateOptions(CertificateOptions options)
    {
        var normalizedMode = CertificateModes.Normalize(options.Mode);
        var altNames = options.AltNames
            .Where(static name => !string.IsNullOrWhiteSpace(name))
            .Select(static name => name.Trim())
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .ToArray();

        var environmentVariables = options.EnvironmentVariables
            .Where(static item => !string.IsNullOrWhiteSpace(item.Name))
            .Select(static item => item with
            {
                Name = item.Name.Trim(),
                Value = item.Value.Trim()
            })
            .ToArray();

        return options with
        {
            Mode = normalizedMode,
            PfxPath = ResolveCertificatePath(normalizedMode, options.PfxPath, options.PanelCertificateId),
            PfxPassword = options.PfxPassword.Trim(),
            PanelCertificateId = options.PanelCertificateId.Trim(),
            DistributedAsset = NormalizeDistributedCertificateAsset(options.DistributedAsset),
            Domain = options.Domain.Trim(),
            AltNames = altNames,
            Email = options.Email.Trim(),
            AcmeDirectoryUrl = options.AcmeDirectoryUrl.Trim(),
            ChallengeType = CertificateChallengeTypes.Normalize(options.ChallengeType),
            RenewBeforeDays = Math.Max(1, options.RenewBeforeDays),
            CheckIntervalMinutes = NormalizePositive(options.CheckIntervalMinutes, 60),
            HttpChallengeListenAddress = NormalizeListenAddress(options.HttpChallengeListenAddress),
            HttpChallengePort = NormalizePort(options.HttpChallengePort, 80),
            ExternalTimeoutSeconds = NormalizePositive(options.ExternalTimeoutSeconds, 300),
            ClientHelloPolicy = NormalizeClientHelloPolicyOptions(options.ClientHelloPolicy),
            ExternalToolPath = options.ExternalToolPath.Trim(),
            ExternalArguments = options.ExternalArguments.Trim(),
            WorkingDirectory = options.WorkingDirectory.Trim(),
            EnvironmentVariables = environmentVariables
        };
    }

    private static DistributedCertificateAsset NormalizeDistributedCertificateAsset(DistributedCertificateAsset asset)
        => asset with
        {
            PfxBase64 = asset.PfxBase64.Trim(),
            Thumbprint = asset.Thumbprint.Trim()
        };

    private static string ResolveCertificatePath(string mode, string path, string panelCertificateId)
    {
        var normalizedPath = path.Trim();
        if (mode != CertificateModes.PanelDistributed || !string.IsNullOrWhiteSpace(normalizedPath))
        {
            return normalizedPath;
        }

        var fileName = string.IsNullOrWhiteSpace(panelCertificateId)
            ? "panel-distributed.pfx"
            : $"{SanitizeFileName(panelCertificateId)}.pfx";

        return Path.GetFullPath(Path.Combine(AppContext.BaseDirectory, "certificates", fileName));
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

    private static bool TryMaterializeDistributedCertificate(
        CertificateOptions certificate,
        out CertificateOptions normalized,
        out string? error)
    {
        normalized = certificate;
        if (CertificateModes.Normalize(certificate.Mode) != CertificateModes.PanelDistributed)
        {
            error = null;
            return true;
        }

        var asset = certificate.DistributedAsset;
        if (string.IsNullOrWhiteSpace(asset.PfxBase64))
        {
            error = null;
            return true;
        }

        if (string.IsNullOrWhiteSpace(certificate.PfxPath))
        {
            error = "Panel distributed certificate mode requires a local cache path.";
            return false;
        }

        try
        {
            var bytes = Convert.FromBase64String(asset.PfxBase64);
            var fullPath = Path.GetFullPath(certificate.PfxPath);
            var directory = Path.GetDirectoryName(fullPath);
            if (!string.IsNullOrWhiteSpace(directory))
            {
                Directory.CreateDirectory(directory);
            }

            var tempPath = fullPath + ".tmp";
            File.WriteAllBytes(tempPath, bytes);
            File.Move(tempPath, fullPath, overwrite: true);

            normalized = certificate with
            {
                PfxPath = fullPath,
                DistributedAsset = asset with
                {
                    PfxBase64 = string.Empty
                }
            };

            error = null;
            return true;
        }
        catch (Exception ex) when (ex is FormatException or IOException or UnauthorizedAccessException)
        {
            error = $"Failed to materialize distributed certificate asset: {ex.Message}";
            return false;
        }
    }

    private static TlsClientHelloPolicyConfig NormalizeClientHelloPolicyOptions(TlsClientHelloPolicyConfig options)
        => options with
        {
            AllowedServerNames = NormalizeLowerStringList(options.AllowedServerNames),
            BlockedServerNames = NormalizeLowerStringList(options.BlockedServerNames),
            AllowedApplicationProtocols = NormalizeLowerStringList(options.AllowedApplicationProtocols),
            BlockedApplicationProtocols = NormalizeLowerStringList(options.BlockedApplicationProtocols),
            AllowedJa3 = NormalizeLowerStringList(options.AllowedJa3),
            BlockedJa3 = NormalizeLowerStringList(options.BlockedJa3)
        };

    private static DnsOptions NormalizeDnsOptions(DnsOptions options)
    {
        var servers = options.Servers
            .Where(static server => !string.IsNullOrWhiteSpace(server.Url))
            .Select(static server => server with
            {
                Url = server.Url.Trim(),
                Headers = NormalizeHeaderDictionary(server.Headers)
            })
            .ToArray();

        return options with
        {
            Mode = DnsModes.Normalize(options.Mode),
            TimeoutSeconds = NormalizePositive(options.TimeoutSeconds, 5),
            CacheTtlSeconds = Math.Max(0, options.CacheTtlSeconds),
            Servers = servers
        };
    }

    private static IReadOnlyList<OutboundConfig> NormalizeOutbounds(IReadOnlyList<OutboundConfig> outbounds)
    {
        if (outbounds.Count == 0)
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
            .Where(static outbound => !string.IsNullOrWhiteSpace(outbound.Tag))
            .Select(NormalizeOutbound)
            .ToArray();
    }

    private static IReadOnlyList<LocalInboundConfig> NormalizeLocalInbounds(IReadOnlyList<LocalInboundConfig> localInbounds)
        => localInbounds
            .Where(static inbound => !string.IsNullOrWhiteSpace(inbound.Tag))
            .Select(static inbound => inbound with
            {
                Tag = inbound.Tag.Trim(),
                Protocol = LocalInboundProtocols.Normalize(inbound.Protocol),
                ListenAddress = NormalizeLocalInboundListenAddress(inbound.ListenAddress),
                Port = NormalizeLocalInboundPort(inbound.Port),
                HandshakeTimeoutSeconds = NormalizePositive(inbound.HandshakeTimeoutSeconds, 10)
            })
            .ToArray();

    private static IReadOnlyList<RoutingRuleConfig> NormalizeRoutingRules(IReadOnlyList<RoutingRuleConfig> routingRules)
        => routingRules
            .Where(static rule => !string.IsNullOrWhiteSpace(rule.OutboundTag))
            .Select(static rule => rule with
            {
                InboundTags = rule.InboundTags
                    .Where(static value => !string.IsNullOrWhiteSpace(value))
                    .Select(static value => value.Trim())
                    .Distinct(StringComparer.OrdinalIgnoreCase)
                    .ToArray(),
                Protocols = rule.Protocols
                    .Where(static value => !string.IsNullOrWhiteSpace(value))
                    .Select(static value => RoutingProtocols.Normalize(value))
                    .Distinct(StringComparer.OrdinalIgnoreCase)
                    .ToArray(),
                Networks = rule.Networks
                    .Where(static value => !string.IsNullOrWhiteSpace(value))
                    .Select(static value => RoutingNetworks.Normalize(value))
                    .Distinct(StringComparer.OrdinalIgnoreCase)
                    .ToArray(),
                UserIds = rule.UserIds
                    .Where(static value => !string.IsNullOrWhiteSpace(value))
                    .Select(static value => value.Trim())
                    .Distinct(StringComparer.OrdinalIgnoreCase)
                    .ToArray(),
                Domains = rule.Domains
                    .Where(static value => !string.IsNullOrWhiteSpace(value))
                    .Select(static value => value.Trim())
                    .Distinct(StringComparer.OrdinalIgnoreCase)
                    .ToArray(),
                SourceCidrs = rule.SourceCidrs
                    .Where(static value => !string.IsNullOrWhiteSpace(value))
                    .Select(static value => value.Trim())
                    .Distinct(StringComparer.OrdinalIgnoreCase)
                    .ToArray(),
                DestinationPorts = rule.DestinationPorts
                    .Where(static value => !string.IsNullOrWhiteSpace(value))
                    .Select(static value => value.Trim())
                    .Distinct(StringComparer.OrdinalIgnoreCase)
                    .ToArray(),
                OutboundTag = rule.OutboundTag.Trim()
            })
            .ToArray();

    private static OutboundConfig NormalizeOutbound(OutboundConfig outbound)
    {
        var protocol = OutboundProtocols.Normalize(outbound.Protocol);
        var transport = protocol == OutboundProtocols.Trojan
            ? TrojanOutboundTransports.Normalize(outbound.Transport)
            : string.Empty;

        return outbound with
        {
            Tag = outbound.Tag.Trim(),
            Protocol = protocol,
            Via = outbound.Via.Trim(),
            ViaCidr = NormalizeViaCidr(outbound.ViaCidr),
            TargetStrategy = OutboundTargetStrategies.Normalize(outbound.TargetStrategy),
            ProxyOutboundTag = outbound.ProxyOutboundTag.Trim(),
            MultiplexSettings = NormalizeMultiplexSettings(outbound.MultiplexSettings),
            Transport = transport,
            ServerHost = outbound.ServerHost.Trim(),
            ServerPort = protocol == OutboundProtocols.Trojan ? NormalizePort(outbound.ServerPort, 443) : outbound.ServerPort,
            ServerName = outbound.ServerName.Trim(),
            WebSocketPath = protocol == OutboundProtocols.Trojan &&
                            transport is TrojanOutboundTransports.Ws or TrojanOutboundTransports.Wss
                ? NormalizeOutboundWebSocketPath(outbound.WebSocketPath)
                : string.Empty,
            WebSocketHeaders = protocol == OutboundProtocols.Trojan
                ? NormalizeHeaderDictionary(outbound.WebSocketHeaders)
                : new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase),
            WebSocketEarlyDataBytes = Math.Max(0, outbound.WebSocketEarlyDataBytes),
            WebSocketHeartbeatPeriodSeconds = Math.Max(0, outbound.WebSocketHeartbeatPeriodSeconds),
            ApplicationProtocols = NormalizeOutboundApplicationProtocols(
                protocol,
                transport,
                outbound.ApplicationProtocols),
            Password = outbound.Password.Trim(),
            ConnectTimeoutSeconds = Math.Max(0, outbound.ConnectTimeoutSeconds),
            HandshakeTimeoutSeconds = Math.Max(0, outbound.HandshakeTimeoutSeconds),
            CandidateTags = NormalizeStringList(outbound.CandidateTags),
            SelectedTag = outbound.SelectedTag.Trim(),
            ProbeUrl = string.IsNullOrWhiteSpace(outbound.ProbeUrl)
                ? StrategyOutboundDefaults.ProbeUrl
                : outbound.ProbeUrl.Trim(),
            ProbeIntervalSeconds = NormalizePositive(outbound.ProbeIntervalSeconds, StrategyOutboundDefaults.ProbeIntervalSeconds),
            ProbeTimeoutSeconds = NormalizePositive(outbound.ProbeTimeoutSeconds, StrategyOutboundDefaults.ProbeTimeoutSeconds),
            ToleranceMilliseconds = Math.Max(0, outbound.ToleranceMilliseconds)
        };
    }

    private static string NormalizeListenAddress(string value)
        => string.IsNullOrWhiteSpace(value) ? "0.0.0.0" : value.Trim();

    private static string NormalizeLocalInboundListenAddress(string value)
        => string.IsNullOrWhiteSpace(value) ? "127.0.0.1" : value.Trim();

    private static IReadOnlyList<string> NormalizeOutboundApplicationProtocols(
        string protocol,
        string transport,
        IReadOnlyList<string> values)
    {
        if (!string.Equals(protocol, OutboundProtocols.Trojan, StringComparison.Ordinal))
        {
            return Array.Empty<string>();
        }

        return transport switch
        {
            TrojanOutboundTransports.Tls => NormalizeStringList(values),
            TrojanOutboundTransports.Wss => ["http/1.1"],
            _ => Array.Empty<string>()
        };
    }

    private static string NormalizeViaCidr(string value)
        => string.IsNullOrWhiteSpace(value) ? string.Empty : value.Trim().TrimStart('/');

    private static OutboundMultiplexConfig NormalizeMultiplexSettings(OutboundMultiplexConfig settings)
        => settings with
        {
            Concurrency = settings.Concurrency,
            XudpConcurrency = settings.XudpConcurrency,
            XudpProxyUdp443 = OutboundXudpProxyModes.Normalize(settings.XudpProxyUdp443)
        };

    private static string NormalizeOutboundWebSocketPath(string value)
    {
        if (string.IsNullOrWhiteSpace(value))
        {
            return "/";
        }

        var normalized = value.Trim();
        return normalized.StartsWith("/", StringComparison.Ordinal) ? normalized : "/" + normalized;
    }

    private static IReadOnlyDictionary<string, string> NormalizeHeaderDictionary(IReadOnlyDictionary<string, string> headers)
    {
        var normalized = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
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

    private static IReadOnlyList<string> NormalizeStringList(IReadOnlyList<string> values)
        => values
            .Where(static value => !string.IsNullOrWhiteSpace(value))
            .Select(static value => value.Trim())
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .ToArray();

    private static IReadOnlyList<string> NormalizeLowerStringList(IReadOnlyList<string> values)
        => NormalizeStringList(values)
            .Select(static value => value.ToLowerInvariant())
            .ToArray();

    private static int NormalizePort(int value, int fallback)
        => value is > 0 and <= 65535 ? value : fallback;

    private static int NormalizeLocalInboundPort(int value)
        => value is >= 0 and <= 65535 ? value : 10808;

    private static int NormalizePositive(int value, int fallback)
        => value > 0 ? value : fallback;

    private static string NormalizeProtocolKey(string? value)
        => string.IsNullOrWhiteSpace(value)
            ? string.Empty
            : value.Trim().ToLowerInvariant();

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

    private void TryPersist(int revision, NodeServiceConfig config)
    {
        try
        {
            _persistedNodeConfigStore.Save(revision, config);
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "Failed to persist node runtime config revision {Revision}.", revision);
        }
    }
}

using System.Security.Cryptography;
using System.Text.Json;
using Microsoft.Extensions.Options;
using NodePanel.ControlPlane.Configuration;
using NodePanel.ControlPlane.Protocol;
using NodePanel.Core.Runtime;
using NodePanel.Panel.Configuration;
using NodePanel.Panel.Models;

namespace NodePanel.Panel.Services;

public sealed class PanelStateStore
{
    private readonly SemaphoreSlim _gate = new(1, 1);
    private readonly JsonSerializerOptions _jsonOptions = new(JsonSerializerDefaults.Web)
    {
        WriteIndented = true
    };

    private readonly string _dataFilePath;
    private PanelState _state;

    public PanelStateStore(IOptions<PanelOptions> options)
    {
        ArgumentNullException.ThrowIfNull(options);

        _dataFilePath = ResolveDataFilePath(options.Value.DataFilePath, AppContext.BaseDirectory);
        _state = LoadState(_dataFilePath, _jsonOptions);
    }

    public PanelState GetSnapshot() => Volatile.Read(ref _state);

    public async Task<PanelState> EnsureNodeAsync(string nodeId, CancellationToken cancellationToken)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(nodeId);

        var result = await MutateAsync(
            static (state, boxedNodeId) =>
            {
                var normalizedNodeId = (string)boxedNodeId;
                if (state.Nodes.Any(node => string.Equals(node.NodeId, normalizedNodeId, StringComparison.Ordinal)))
                {
                    return new PanelMutationResult
                    {
                        State = state
                    };
                }

                var nodes = state.Nodes
                    .Append(new PanelNodeRecord
                    {
                        NodeId = normalizedNodeId,
                        DisplayName = normalizedNodeId,
                        Config = new NodeServiceConfig()
                    })
                    .OrderBy(static node => node.NodeId, StringComparer.Ordinal)
                    .ToArray();

                return new PanelMutationResult
                {
                    State = state with
                    {
                        Nodes = nodes
                    }
                };
            },
            nodeId.Trim(),
            cancellationToken).ConfigureAwait(false);

        return result.State;
    }

    public Task<PanelMutationResult> UpsertNodeAsync(string nodeId, UpsertNodeRequest request, CancellationToken cancellationToken)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(nodeId);
        ArgumentNullException.ThrowIfNull(request);

        return MutateAsync(
            static (state, boxedState) =>
            {
                var payload = (NodeUpsertPayload)boxedState;
                var current = state.Nodes.FirstOrDefault(node => string.Equals(node.NodeId, payload.NodeId, StringComparison.Ordinal));

                var next = new PanelNodeRecord
                {
                    NodeId = payload.NodeId,
                    DisplayName = string.IsNullOrWhiteSpace(payload.Request.DisplayName) ? payload.NodeId : payload.Request.DisplayName.Trim(),
                    Enabled = payload.Request.Enabled,
                    DesiredRevision = current?.DesiredRevision + 1 ?? 1,
                    SubscriptionHost = payload.Request.SubscriptionHost.Trim(),
                    SubscriptionSni = payload.Request.SubscriptionSni.Trim(),
                    SubscriptionAllowInsecure = payload.Request.SubscriptionAllowInsecure,
                    Config = NormalizeNodeConfig(payload.Request.Config)
                };

                var nodes = ReplaceOrAdd(
                        state.Nodes,
                        next,
                        payload.NodeId,
                        static node => node.NodeId)
                    .OrderBy(static node => node.NodeId, StringComparer.Ordinal)
                    .ToArray();

                return new PanelMutationResult
                {
                    State = state with
                    {
                        Nodes = nodes
                    },
                    AffectedNodeIds = new[] { payload.NodeId }
                };
            },
            new NodeUpsertPayload(nodeId.Trim(), request),
            cancellationToken);
    }

    public Task<PanelMutationResult> UpsertUserAsync(string userId, UpsertUserRequest request, CancellationToken cancellationToken)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(userId);
        ArgumentNullException.ThrowIfNull(request);

        return MutateAsync(
            static (state, boxedState) =>
            {
                var payload = (UserUpsertPayload)boxedState;
                var current = state.Users.FirstOrDefault(user => string.Equals(user.UserId, payload.UserId, StringComparison.Ordinal));

                var next = new PanelUserRecord
                {
                    UserId = payload.UserId,
                    DisplayName = string.IsNullOrWhiteSpace(payload.Request.DisplayName) ? payload.UserId : payload.Request.DisplayName.Trim(),
                    SubscriptionToken = NormalizeSecret(payload.Request.SubscriptionToken, current?.SubscriptionToken),
                    TrojanPassword = NormalizeSecret(payload.Request.TrojanPassword, current?.TrojanPassword),
                    V2rayUuid = NormalizeUuid(payload.Request.V2rayUuid, current?.V2rayUuid),
                    InviteUserId = payload.Request.InviteUserId.Trim(),
                    CommissionBalance = payload.Request.CommissionBalance,
                    CommissionRate = Math.Clamp(payload.Request.CommissionRate, 0, 100),
                    GroupId = payload.Request.GroupId,
                    Enabled = payload.Request.Enabled,
                    BytesPerSecond = Math.Max(0, payload.Request.BytesPerSecond),
                    DeviceLimit = Math.Max(0, payload.Request.DeviceLimit),
                    Subscription = NormalizeUserSubscription(payload.Request.Subscription),
                    NodeIds = NormalizeNodeIds(payload.Request.NodeIds)
                };

                var users = ReplaceOrAdd(
                        state.Users,
                        next,
                        payload.UserId,
                        static user => user.UserId)
                    .OrderBy(static user => user.UserId, StringComparer.Ordinal)
                    .ToArray();

                var affectedNodeIds = ResolveAffectedNodes(state.Nodes, current, next);
                var affectedLookup = new HashSet<string>(affectedNodeIds, StringComparer.Ordinal);
                var nodes = state.Nodes
                    .Select(node => affectedLookup.Contains(node.NodeId)
                        ? node with
                        {
                            DesiredRevision = node.DesiredRevision + 1
                        }
                        : node)
                    .ToArray();

                return new PanelMutationResult
                {
                    State = state with
                    {
                        Nodes = nodes,
                        Users = users
                    },
                    AffectedNodeIds = affectedNodeIds
                };
            },
            new UserUpsertPayload(userId.Trim(), request),
            cancellationToken);
    }

    public Task<PanelMutationResult> UpsertPlanAsync(string planId, UpsertPlanRequest request, CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(planId);
        ArgumentNullException.ThrowIfNull(request);

        return MutateAsync(
            static (state, boxedState) =>
            {
                var payload = (PlanUpsertPayload)boxedState;
                var current = state.Plans.FirstOrDefault(plan => string.Equals(plan.PlanId, payload.PlanId, StringComparison.Ordinal));

                var next = new PanelPlanRecord
                {
                    PlanId = payload.PlanId,
                    Name = string.IsNullOrWhiteSpace(payload.Request.Name) ? payload.PlanId : payload.Request.Name.Trim(),
                    TransferEnableBytes = Math.Max(0, payload.Request.TransferEnableBytes),
                    MonthPrice = payload.Request.MonthPrice.HasValue ? Math.Max(0, payload.Request.MonthPrice.Value) : null,
                    QuarterPrice = payload.Request.QuarterPrice.HasValue ? Math.Max(0, payload.Request.QuarterPrice.Value) : null,
                    HalfYearPrice = payload.Request.HalfYearPrice.HasValue ? Math.Max(0, payload.Request.HalfYearPrice.Value) : null,
                    YearPrice = payload.Request.YearPrice.HasValue ? Math.Max(0, payload.Request.YearPrice.Value) : null,
                    OneTimePrice = payload.Request.OneTimePrice.HasValue ? Math.Max(0, payload.Request.OneTimePrice.Value) : null,
                    ResetPrice = payload.Request.ResetPrice.HasValue ? Math.Max(0, payload.Request.ResetPrice.Value) : null
                };

                var plans = ReplaceOrAdd(
                        state.Plans,
                        next,
                        payload.PlanId,
                        static plan => plan.PlanId)
                    .OrderBy(static plan => plan.PlanId, StringComparer.Ordinal)
                    .ToArray();

                return new PanelMutationResult
                {
                    State = state with
                    {
                        Plans = plans
                    }
                };
            },
            new PlanUpsertPayload(planId.Trim(), request),
            cancellationToken);
    }

    public Task<PanelMutationResult> DeletePlanAsync(string planId, CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(planId);
        return MutateAsync(
            static (state, boxedState) =>
            {
                var id = (string)boxedState;
                var plans = state.Plans.Where(p => !string.Equals(p.PlanId, id, StringComparison.Ordinal)).ToArray();
                return new PanelMutationResult
                {
                    State = state with { Plans = plans }
                };
            },
            planId.Trim(),
            cancellationToken);
    }

    public Task<PanelMutationResult> ResetUserTrafficAsync(string userId, CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(userId);
        return MutateAsync(
            static (state, boxedState) =>
            {
                var id = (string)boxedState;
                var records = state.TrafficRecords.ToDictionary(r => r.UserId, StringComparer.Ordinal);
                if (records.TryGetValue(id, out var existing))
                {
                    records[id] = existing with
                    {
                        UploadBytes = 0,
                        DownloadBytes = 0,
                        LastResetAt = DateTimeOffset.UtcNow
                    };
                }
                else
                {
                    records[id] = new PanelUserTrafficRecord
                    {
                        UserId = id,
                        UploadBytes = 0,
                        DownloadBytes = 0,
                        LastResetAt = DateTimeOffset.UtcNow
                    };
                }

                return new PanelMutationResult
                {
                    State = state with { TrafficRecords = records.Values.OrderBy(r => r.UserId, StringComparer.Ordinal).ToArray() }
                };
            },
            userId.Trim(),
            cancellationToken);
    }

    public Task<PanelMutationResult> CommitTrafficAsync(IReadOnlyList<UserTrafficDelta> deltas, CancellationToken cancellationToken = default)
    {
        if (deltas is null || deltas.Count == 0) return Task.FromResult(new PanelMutationResult { State = _state });

        return MutateAsync(
            static (state, boxedState) =>
            {
                var d = (IReadOnlyList<UserTrafficDelta>)boxedState;
                var records = state.TrafficRecords.ToDictionary(r => r.UserId, StringComparer.Ordinal);
                
                foreach (var delta in d)
                {
                    if (records.TryGetValue(delta.UserId, out var existing))
                    {
                        records[delta.UserId] = existing with
                        {
                            UploadBytes = existing.UploadBytes + delta.UploadBytes,
                            DownloadBytes = existing.DownloadBytes + delta.DownloadBytes
                        };
                    }
                    else
                    {
                        records[delta.UserId] = new PanelUserTrafficRecord
                        {
                            UserId = delta.UserId,
                            UploadBytes = delta.UploadBytes,
                            DownloadBytes = delta.DownloadBytes,
                            LastResetAt = DateTimeOffset.UtcNow
                        };
                    }
                }

                return new PanelMutationResult
                {
                    State = state with
                    {
                        TrafficRecords = records.Values.OrderBy(r => r.UserId, StringComparer.Ordinal).ToArray()
                    }
                };
            },
            deltas,
            cancellationToken);
    }

    private async Task<PanelMutationResult> MutateAsync(
        Func<PanelState, object, PanelMutationResult> mutator,
        object state,
        CancellationToken cancellationToken)
    {
        await _gate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            var current = _state;
            var result = mutator(current, state);
            if (!ReferenceEquals(current, result.State))
            {
                _state = result.State;
                await SaveStateAsync(_dataFilePath, result.State, _jsonOptions, cancellationToken).ConfigureAwait(false);
            }

            return result;
        }
        finally
        {
            _gate.Release();
        }
    }

    private static IReadOnlyList<string> ResolveAffectedNodes(
        IReadOnlyList<PanelNodeRecord> nodes,
        PanelUserRecord? current,
        PanelUserRecord next)
    {
        if (IsGlobalUser(current) || IsGlobalUser(next))
        {
            return nodes.Select(static node => node.NodeId).ToArray();
        }

        return current?.NodeIds
            .Concat(next.NodeIds)
            .Distinct(StringComparer.Ordinal)
            .OrderBy(static nodeId => nodeId, StringComparer.Ordinal)
            .ToArray() ?? next.NodeIds;
    }

    private static bool IsGlobalUser(PanelUserRecord? user)
        => user is { NodeIds.Count: 0 };

    private static IReadOnlyList<string> NormalizeNodeIds(IReadOnlyList<string> nodeIds)
        => nodeIds
            .Where(static nodeId => !string.IsNullOrWhiteSpace(nodeId))
            .Select(static nodeId => nodeId.Trim())
            .Distinct(StringComparer.Ordinal)
            .OrderBy(static nodeId => nodeId, StringComparer.Ordinal)
            .ToArray();

    private static string NormalizeSecret(string requested, string? current)
    {
        if (!string.IsNullOrWhiteSpace(requested))
        {
            return requested.Trim();
        }

        if (!string.IsNullOrWhiteSpace(current))
        {
            return current;
        }

        return Convert.ToHexString(RandomNumberGenerator.GetBytes(16)).ToLowerInvariant();
    }

    private static string NormalizeUuid(string requested, string? current)
    {
        if (Guid.TryParse(requested?.Trim(), out var requestedUuid))
        {
            return requestedUuid.ToString("D");
        }

        if (Guid.TryParse(current?.Trim(), out var currentUuid))
        {
            return currentUuid.ToString("D");
        }

        return Guid.NewGuid().ToString("D");
    }

    private static PanelUserSubscriptionProfile NormalizeUserSubscription(PanelUserSubscriptionProfile subscription)
    {
        ArgumentNullException.ThrowIfNull(subscription);

        return subscription with
        {
            PlanName = subscription.PlanName.Trim(),
            TransferEnableBytes = Math.Max(0, subscription.TransferEnableBytes),
            PurchaseUrl = subscription.PurchaseUrl.Trim(),
            PortalNotice = subscription.PortalNotice.Trim()
        };
    }

    private static NodeServiceConfig NormalizeNodeConfig(NodeServiceConfig config)
    {
        ArgumentNullException.ThrowIfNull(config);

        config = NodeServiceConfigInbounds.LiftLegacyTrojanScope(config);

        var altNames = config.Certificate.AltNames
            .Where(static value => !string.IsNullOrWhiteSpace(value))
            .Select(static value => value.Trim())
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .ToArray();

        var environmentVariables = config.Certificate.EnvironmentVariables
            .Where(static value => !string.IsNullOrWhiteSpace(value.Name))
            .Select(static value => value with
            {
                Name = value.Name.Trim(),
                Value = value.Value.Trim()
            })
            .ToArray();

        return config with
        {
            Inbounds = NormalizeInbounds(config.Inbounds),
            Users = Array.Empty<TrojanUserConfig>(),
            Fallbacks = Array.Empty<TrojanFallbackConfig>(),
            Certificate = config.Certificate with
            {
                Mode = CertificateModes.Normalize(config.Certificate.Mode),
                PfxPath = config.Certificate.PfxPath.Trim(),
                PfxPassword = config.Certificate.PfxPassword.Trim(),
                Domain = config.Certificate.Domain.Trim(),
                AltNames = altNames,
                Email = config.Certificate.Email.Trim(),
                AcmeDirectoryUrl = config.Certificate.AcmeDirectoryUrl.Trim(),
                ChallengeType = CertificateChallengeTypes.Normalize(config.Certificate.ChallengeType),
                RenewBeforeDays = Math.Max(1, config.Certificate.RenewBeforeDays),
                CheckIntervalMinutes = Math.Max(1, config.Certificate.CheckIntervalMinutes),
                HttpChallengeListenAddress = NormalizeListenAddress(config.Certificate.HttpChallengeListenAddress),
                HttpChallengePort = config.Certificate.HttpChallengePort is > 0 and <= 65535 ? config.Certificate.HttpChallengePort : 80,
                ExternalTimeoutSeconds = Math.Max(1, config.Certificate.ExternalTimeoutSeconds),
                UseStaging = false,
                ExternalToolPath = config.Certificate.ExternalToolPath.Trim(),
                ExternalArguments = config.Certificate.ExternalArguments.Trim(),
                WorkingDirectory = config.Certificate.WorkingDirectory.Trim(),
                EnvironmentVariables = environmentVariables
            }
        };
    }

    private static IReadOnlyList<InboundConfig> NormalizeInbounds(IReadOnlyList<InboundConfig> inbounds)
        => inbounds
            .Select(NormalizeInbound)
            .ToArray();

    private static InboundConfig NormalizeInbound(InboundConfig inbound)
    {
        var transport = InboundTransports.Normalize(inbound.Transport);

        return inbound with
        {
            Tag = inbound.Tag.Trim(),
            Protocol = InboundProtocols.Normalize(inbound.Protocol),
            Transport = transport,
            ListenAddress = NormalizeListenAddress(inbound.ListenAddress),
            Host = inbound.Host.Trim(),
            Path = transport == InboundTransports.Wss ? NormalizePath(inbound.Path) : string.Empty,
            EarlyDataBytes = Math.Max(0, inbound.EarlyDataBytes),
            HeartbeatPeriodSeconds = Math.Max(0, inbound.HeartbeatPeriodSeconds),
            ReceiveOriginalDestination = inbound.ReceiveOriginalDestination,
            Sniffing = inbound.Sniffing with
            {
                DestinationOverride = inbound.Sniffing.DestinationOverride
                    .Where(static value => !string.IsNullOrWhiteSpace(value))
                    .Select(static value => RoutingProtocols.Normalize(value))
                    .Distinct(StringComparer.OrdinalIgnoreCase)
                    .ToArray(),
                DomainsExcluded = inbound.Sniffing.DomainsExcluded
                    .Where(static value => !string.IsNullOrWhiteSpace(value))
                    .Select(static value => value.Trim().ToLowerInvariant())
                    .Distinct(StringComparer.OrdinalIgnoreCase)
                    .ToArray()
            },
            Users = inbound.Users
                .Where(static user => !string.IsNullOrWhiteSpace(user.UserId) && !string.IsNullOrWhiteSpace(user.Password))
                .Select(static user => user with
                {
                    UserId = user.UserId.Trim(),
                    Password = user.Password.Trim(),
                    BytesPerSecond = Math.Max(0, user.BytesPerSecond)
                })
                .ToArray(),
            Fallbacks = inbound.Fallbacks
                .Where(static value => !string.IsNullOrWhiteSpace(value.Dest))
                .Select(static value =>
                {
                    var normalizedType = TrojanFallbackCompatibility.NormalizeType(value.Type, value.Dest);
                    return value with
                    {
                        Name = value.Name.Trim().ToLowerInvariant(),
                        Alpn = value.Alpn.Trim().ToLowerInvariant(),
                        Path = TrojanFallbackCompatibility.NormalizePath(value.Path),
                        Type = normalizedType,
                        Dest = TrojanFallbackCompatibility.NormalizeDestination(normalizedType, value.Dest),
                        ProxyProtocolVersion = TrojanFallbackCompatibility.NormalizeProxyProtocolVersion(value.ProxyProtocolVersion)
                    };
                })
                .ToArray()
        };
    }

    private static string NormalizeListenAddress(string value)
        => string.IsNullOrWhiteSpace(value) ? "0.0.0.0" : value.Trim();

    private static string NormalizePath(string value)
    {
        if (string.IsNullOrWhiteSpace(value))
        {
            return "/ws";
        }

        return value.StartsWith("/", StringComparison.Ordinal) ? value : "/" + value;
    }

    private static IEnumerable<T> ReplaceOrAdd<T>(
        IEnumerable<T> source,
        T value,
        string identity,
        Func<T, string> selector)
    {
        var replaced = false;
        foreach (var item in source)
        {
            if (!replaced && string.Equals(selector(item), identity, StringComparison.Ordinal))
            {
                yield return value;
                replaced = true;
                continue;
            }

            yield return item;
        }

        if (!replaced)
        {
            yield return value;
        }
    }

    private static PanelState LoadState(string path, JsonSerializerOptions options)
    {
        if (!File.Exists(path))
        {
            return new PanelState();
        }

        var json = File.ReadAllText(path);
        if (string.IsNullOrWhiteSpace(json))
        {
            return new PanelState();
        }

        return NormalizeState(JsonSerializer.Deserialize<PanelState>(json, options) ?? new PanelState());
    }

    private static PanelState NormalizeState(PanelState state)
        => state with
        {
            Nodes = state.Nodes
                .Select(node => node with
                {
                    Config = NormalizeNodeConfig(node.Config)
                })
                .ToArray(),
            Users = state.Users
                .Select(user => user with
                {
                    DisplayName = string.IsNullOrWhiteSpace(user.DisplayName) ? user.UserId : user.DisplayName.Trim(),
                    SubscriptionToken = user.SubscriptionToken.Trim(),
                    TrojanPassword = user.TrojanPassword.Trim(),
                    V2rayUuid = NormalizeUuid(user.V2rayUuid, null),
                    InviteUserId = user.InviteUserId.Trim(),
                    CommissionRate = Math.Clamp(user.CommissionRate, 0, 100),
                    GroupId = Math.Max(0, user.GroupId),
                    BytesPerSecond = Math.Max(0, user.BytesPerSecond),
                    DeviceLimit = Math.Max(0, user.DeviceLimit),
                    Subscription = NormalizeUserSubscription(user.Subscription),
                    NodeIds = NormalizeNodeIds(user.NodeIds)
                })
                .ToArray(),
            Plans = (state.Plans ?? Array.Empty<PanelPlanRecord>())
                .OrderBy(static plan => plan.PlanId, StringComparer.Ordinal)
                .ToArray(),
            TrafficRecords = (state.TrafficRecords ?? Array.Empty<PanelUserTrafficRecord>())
                .OrderBy(static r => r.UserId, StringComparer.Ordinal)
                .ToArray()
        };

    private static async Task SaveStateAsync(string path, PanelState state, JsonSerializerOptions options, CancellationToken cancellationToken)
    {
        var directory = Path.GetDirectoryName(path);
        if (!string.IsNullOrWhiteSpace(directory))
        {
            Directory.CreateDirectory(directory);
        }

        await using var stream = File.Create(path);
        await JsonSerializer.SerializeAsync(stream, state, options, cancellationToken).ConfigureAwait(false);
    }

    private static string ResolveDataFilePath(string dataFilePath, string contentRootPath)
    {
        if (Path.IsPathRooted(dataFilePath))
        {
            return dataFilePath;
        }

        return Path.GetFullPath(Path.Combine(contentRootPath, dataFilePath));
    }

    private sealed record NodeUpsertPayload(string NodeId, UpsertNodeRequest Request);

    private sealed record UserUpsertPayload(string UserId, UpsertUserRequest Request);

    private sealed record PlanUpsertPayload(string PlanId, UpsertPlanRequest Request);
}

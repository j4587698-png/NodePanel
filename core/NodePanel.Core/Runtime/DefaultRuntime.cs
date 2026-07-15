using System.Collections.Concurrent;
using System.Threading.Channels;
using NodePanel.Core.Protocol;

namespace NodePanel.Core.Runtime;

public sealed class DefaultRuntime : IRuntime
{
    private readonly Channel<RuntimeEvent> _events = Channel.CreateUnbounded<RuntimeEvent>(
        new UnboundedChannelOptions
        {
            SingleReader = false,
            SingleWriter = false
        });
    private readonly SemaphoreSlim _lifecycleGate = new(1, 1);
    private readonly object _statusSync = new();
    private readonly RuntimeComponentCatalog _components;
    private readonly ConcurrentDictionary<string, IReadOnlyList<StrategyCandidateProbeResult>> _strategyProbeSnapshots = new(StringComparer.OrdinalIgnoreCase);

    private RuntimeFeatureGraph _featureGraph;

    private IRuntimeExecution? _currentRuntime;
    private RuntimeStatusSnapshot _status = new();
    private int _disposed;

    public DefaultRuntime()
        : this(null)
    {
    }

    public DefaultRuntime(RuntimeComponentCatalog? components)
    {
        _components = components ?? RuntimeComponentCatalog.Default;
        _featureGraph = RuntimeFeatureGraph.CreateDefault();
    }

    public RuntimeState State => Volatile.Read(ref _status).State;

    public IRuntimeUserStore Users => _featureGraph.UserStore;

    public async Task StartAsync(RuntimePlan plan, CancellationToken cancellationToken = default)
    {
        await _lifecycleGate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            ThrowIfDisposed();
            if (Volatile.Read(ref _currentRuntime) is not null)
            {
                throw new InvalidOperationException("Runtime is already running. Use ReloadAsync or StopAsync.");
            }

            await StartCoreAsync(ValidatePlan(plan), cancellationToken).ConfigureAwait(false);
        }
        finally
        {
            _lifecycleGate.Release();
        }
    }

    public async Task ReloadAsync(RuntimePlan plan, CancellationToken cancellationToken = default)
    {
        await _lifecycleGate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            ThrowIfDisposed();

            var normalizedPlan = ValidatePlan(plan);
            var currentRuntime = Volatile.Read(ref _currentRuntime);
            if (currentRuntime is not null)
            {
                await StopCoreAsync(
                        currentRuntime,
                        currentRuntime.Plan.Revision,
                        "Reloading runtime.",
                        publishStoppedEvent: false,
                        cancellationToken)
                    .ConfigureAwait(false);
            }

            await StartCoreAsync(normalizedPlan, cancellationToken).ConfigureAwait(false);
        }
        finally
        {
            _lifecycleGate.Release();
        }
    }

    public async Task StopAsync(CancellationToken cancellationToken = default)
    {
        await _lifecycleGate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            ThrowIfDisposed();

            var runtime = Volatile.Read(ref _currentRuntime);
            if (runtime is null)
            {
                return;
            }

            await StopCoreAsync(
                    runtime,
                    runtime.Plan.Revision,
                    "Stopping runtime.",
                    publishStoppedEvent: true,
                    cancellationToken)
                .ConfigureAwait(false);
        }
        finally
        {
            _lifecycleGate.Release();
        }
    }

    public RuntimeStatusSnapshot GetStatus()
    {
        var snapshot = Volatile.Read(ref _status);
        return snapshot with
        {
            ActiveSessions = _featureGraph.SessionRegistry.ActiveSessions,
            KnownUsers = _featureGraph.UserStore.KnownUsers,
            Strategies = BuildStrategyStatuses()
        };
    }

    public IReadOnlyList<UserTrafficSnapshot> GetTrafficSnapshot() => _featureGraph.TrafficRegistry.CreateSnapshot();

    public IReadOnlyList<UserSessionSnapshot> GetSessionSnapshot() => _featureGraph.SessionRegistry.CreateSnapshot();

    public async ValueTask<IReadOnlyList<RuntimeStrategyStatus>> RefreshStrategyStatusesAsync(
        CancellationToken cancellationToken = default)
    {
        var plan = _featureGraph.PlanState.GetCurrentPlan();
        var strategyOutbounds = GetStrategyOutbounds(plan);
        if (strategyOutbounds.Count == 0)
        {
            return Array.Empty<RuntimeStrategyStatus>();
        }

        if (State != RuntimeState.Running || Volatile.Read(ref _currentRuntime) is null)
        {
            return BuildStrategyStatuses();
        }

        foreach (var outbound in strategyOutbounds)
        {
            cancellationToken.ThrowIfCancellationRequested();

            try
            {
                var results = await _featureGraph.StrategyProbeService
                    .ProbeAsync(CreateStrategySettings(outbound), cancellationToken)
                    .ConfigureAwait(false);
                _strategyProbeSnapshots[outbound.Tag] = results.ToArray();
            }
            catch (InvalidOperationException)
            {
                break;
            }
        }

        return BuildStrategyStatuses();
    }

    public IAsyncEnumerable<RuntimeEvent> GetEventsAsync(CancellationToken cancellationToken = default)
        => _events.Reader.ReadAllAsync(cancellationToken);

    public async ValueTask DisposeAsync()
    {
        if (Interlocked.CompareExchange(ref _disposed, 1, 0) != 0)
        {
            return;
        }

        try
        {
            await _lifecycleGate.WaitAsync().ConfigureAwait(false);
            try
            {
                var runtime = Volatile.Read(ref _currentRuntime);
                if (runtime is not null)
                {
                    await StopCoreAsync(
                            runtime,
                            runtime.Plan.Revision,
                            "Disposing runtime.",
                            publishStoppedEvent: false,
                            CancellationToken.None)
                        .ConfigureAwait(false);
                }
            }
            finally
            {
                _lifecycleGate.Release();
            }
        }
        finally
        {
            _events.Writer.TryComplete();
            _lifecycleGate.Dispose();
        }
    }

    private async Task StartCoreAsync(RuntimePlan plan, CancellationToken cancellationToken)
    {
        _strategyProbeSnapshots.Clear();
        var activation = _featureGraph.Activate(_components, plan);
        _featureGraph = activation.Graph;

        var resolver = activation.Resolver;
        var inboundComposition = resolver.GetRequired<IRuntimeInboundComposition>();
        if (_featureGraph.UserStore is IRuntimeUserStoreController userStoreController)
        {
            userStoreController.Reset(plan);
        }
        else
        {
            _featureGraph.UserStore.Replace(plan.ActiveUsers);
        }
        _featureGraph.RateLimiterRegistry.Apply(plan.TransportLimits, plan.ActiveUsers);
        _featureGraph.StrategyProbeCache?.InvalidateAll();

        SetStatus(
            _ => CreateStatusSnapshot(
                plan,
                RuntimeState.Starting,
                "Starting runtime.",
                inboundComposition.CreateListenerStatuses(plan)));
        PublishStateChanged(plan.Revision, RuntimeState.Starting, "Starting runtime.");

        IRuntimeExecution? runtime = null;
        try
        {
            runtime = BuildRuntime(plan, resolver);
            Volatile.Write(ref _currentRuntime, runtime);

            await runtime.Startup.WaitAsync(cancellationToken).ConfigureAwait(false);

            var failure = runtime.GetImmediateFailure();
            if (failure is not null)
            {
                throw failure;
            }

            SetStatus(current => current with
            {
                State = RuntimeState.Running,
                Message = "Runtime is running.",
                UpdatedAt = DateTimeOffset.UtcNow
            });
            PublishStateChanged(plan.Revision, RuntimeState.Running, "Runtime is running.");
        }
        catch (Exception ex)
        {
            if (runtime is not null)
            {
                await runtime.DisposeAsync().ConfigureAwait(false);
            }

            if (ReferenceEquals(Volatile.Read(ref _currentRuntime), runtime))
            {
                Volatile.Write(ref _currentRuntime, null);
            }

            _featureGraph.DispatcherController.ClearDispatcher();
            SetAllListenersState(RuntimeState.Faulted, ex.Message);
            SetStatus(current => current with
            {
                State = RuntimeState.Faulted,
                Message = ex.Message,
                UpdatedAt = DateTimeOffset.UtcNow
            });
            PublishFault(plan.Revision, "runtime", ex.Message, ex);
            throw;
        }
    }

    private async Task StopCoreAsync(
        IRuntimeExecution runtime,
        int revision,
        string message,
        bool publishStoppedEvent,
        CancellationToken cancellationToken)
    {
        if (!ReferenceEquals(Volatile.Read(ref _currentRuntime), runtime))
        {
            return;
        }

        SetStatus(current => current with
        {
            State = RuntimeState.Stopping,
            Message = message,
            UpdatedAt = DateTimeOffset.UtcNow
        });
        PublishStateChanged(revision, RuntimeState.Stopping, message);

        runtime.Cancel();
        await runtime.DisposeAsync().ConfigureAwait(false);

        if (ReferenceEquals(Volatile.Read(ref _currentRuntime), runtime))
        {
            Volatile.Write(ref _currentRuntime, null);
        }

        _featureGraph.DispatcherController.ClearDispatcher();
        SetAllListenersState(RuntimeState.Stopped, "Listener stopped.");
        SetStatus(current => current with
        {
            State = RuntimeState.Stopped,
            Message = "Runtime is stopped.",
            UpdatedAt = DateTimeOffset.UtcNow
        });

        if (publishStoppedEvent)
        {
            PublishStateChanged(revision, RuntimeState.Stopped, "Runtime is stopped.");
        }

        cancellationToken.ThrowIfCancellationRequested();
    }

    private IRuntimeExecution BuildRuntime(RuntimePlan plan, RuntimeComponentResolver resolver)
    {
        return resolver.GetRequired<IRuntimeExecutionFactory>().Create(
            new RuntimeExecutionContext
            {
                Plan = plan,
                Resolver = resolver,
                Callbacks = new RuntimeExecutionCallbacks
                {
                    InboundListenerStarted = OnInboundListenerStarted,
                    ProxyInboundListenerStarted = OnProxyInboundListenerStarted,
                    InboundConnectionError = OnInboundConnectionError,
                    InboundClientHelloRejected = OnInboundClientHelloRejected,
                    InboundUnknownServerNameRejected = OnInboundUnknownServerNameRejected,
                    ProxyConnectionAccessed = (revision, context) => PublishConnectionAccessed(
                        revision,
                        context.Protocol,
                        context.InboundTag,
                        context.TargetHost,
                        context.TargetPort,
                        context.Network),
                    RuntimeTaskFaulted = ReportRuntimeFault
                },
                InboundLimits = plan.TransportLimits,
                InboundTls = plan.Tls,
                InboundReality = plan.Reality,
                ProxyInboundLimits = CreateProxyInboundLimits(plan.TransportLimits)
            });
    }

    private void ReportRuntimeFault(
        IRuntimeExecution runtime,
        string taskName,
        IReadOnlyList<string> listenerKeys,
        Exception exception)
    {
        if (!ReferenceEquals(Volatile.Read(ref _currentRuntime), runtime))
        {
            return;
        }

        runtime.Cancel();
        var listeners = SetListenerState(
            listenerKeys,
            RuntimeState.Faulted,
            exception.Message);
        SetStatus(current => current with
        {
            State = RuntimeState.Faulted,
            Message = exception.Message,
            UpdatedAt = DateTimeOffset.UtcNow
        });

        PublishEvent(
            new RuntimeListenerFaultedEvent
            {
                Revision = runtime.Plan.Revision,
                TaskName = taskName,
                Message = exception.Message,
                Listeners = listeners
            });

        PublishFault(runtime.Plan.Revision, taskName, exception.Message, exception);
    }

    private void OnInboundListenerStarted(
        int revision,
        IReadOnlyList<string> listenerKeys,
        string message)
    {
        var listeners = SetListenerState(listenerKeys, RuntimeState.Running, message);
        PublishListenerStarted(revision, listeners, message);
    }

    private void OnProxyInboundListenerStarted(
        int revision,
        string protocol,
        ProxyInboundListenerDefinition listener,
        string message)
    {
        var listeners = SetListenerState(
            [
                RuntimeListenerKeys.CreateListenerKey(protocol, listener.Tag, transport: string.Empty, listener.Binding)
            ],
            RuntimeState.Running,
            message);
        PublishListenerStarted(revision, listeners, message);
    }

    private void OnInboundConnectionError(
        int revision,
        RuntimeInboundConnectionErrorReport report)
    {
        PublishConnectionError(
            revision,
            NormalizeProtocol(report.Protocol),
            report.Tag,
            report.IsProxyInbound,
            report.RemoteEndPoint,
            string.IsNullOrWhiteSpace(report.Message) ? "Inbound connection failed." : report.Message,
            report.Exception);
    }

    private void OnInboundClientHelloRejected(
        int revision,
        RuntimeInboundClientHelloRejectedReport report)
    {
        PublishClientHelloRejected(
            revision,
            NormalizeProtocol(report.Protocol),
            report.RemoteEndPoint,
            report.ServerName,
            report.Ja3Hash,
            report.Reason);
    }

    private void OnInboundUnknownServerNameRejected(
        int revision,
        RuntimeInboundUnknownServerNameRejectedReport report)
    {
        PublishUnknownServerNameRejected(
            revision,
            NormalizeProtocol(report.Protocol),
            report.RemoteEndPoint,
            report.RequestedServerName);
    }

    private RuntimePlan ValidatePlan(RuntimePlan plan)
    {
        ArgumentNullException.ThrowIfNull(plan);

        foreach (var inboundPlan in plan.Plan.Inbounds.Plans.Values)
        {
            var protocol = NormalizeProtocol(inboundPlan.Protocol);
            if (!_components.SupportsInboundProtocol(protocol))
            {
                throw new InvalidOperationException($"Inbound protocol '{protocol}' is not supported.");
            }
        }

        if (plan.Plan.Inbounds.RequiresCertificate && plan.Tls is null)
        {
            throw new InvalidOperationException("Runtime plan requires TLS options because at least one inbound listener needs a certificate.");
        }

        if (plan.Plan.Inbounds.RequiresReality && plan.Reality is null)
        {
            throw new InvalidOperationException("Runtime plan requires REALITY options because at least one inbound listener uses REALITY security.");
        }

        foreach (var outbound in plan.Plan.Outbound.Outbounds)
        {
            var protocol = OutboundProtocols.Normalize(outbound.Protocol);
            if (!_components.SupportsOutboundProtocol(protocol))
            {
                throw new InvalidOperationException($"Outbound '{outbound.Tag}' uses unsupported protocol '{protocol}'.");
            }

            if (ProtocolRequiresRuntimeSettings(protocol) &&
                (!plan.OutboundSettings.TryGet(outbound.Tag, out var settings) ||
                 !string.Equals(protocol, OutboundProtocols.Normalize(settings.Protocol), StringComparison.Ordinal)))
            {
                throw new InvalidOperationException($"Outbound '{outbound.Tag}' ({protocol}) is missing runtime settings.");
            }
        }

        return plan with
        {
            Revision = Math.Max(0, plan.Revision),
            ActiveUsers = plan.ActiveUsers.ToArray()
        };
    }

    private static string NormalizeProtocol(string? protocol)
        => string.IsNullOrWhiteSpace(protocol)
            ? string.Empty
            : protocol.Trim().ToLowerInvariant();

    private static bool ProtocolRequiresRuntimeSettings(string protocol)
        => protocol is not (
            OutboundProtocols.Freedom or
            OutboundProtocols.Blackhole or
            OutboundProtocols.Selector or
            OutboundProtocols.UrlTest or
            OutboundProtocols.Fallback or
            OutboundProtocols.LoadBalance);

    private IReadOnlyList<RuntimeStrategyStatus> BuildStrategyStatuses()
    {
        var plan = _featureGraph.PlanState.GetCurrentPlan();
        var strategyOutbounds = GetStrategyOutbounds(plan);
        if (strategyOutbounds.Count == 0)
        {
            return Array.Empty<RuntimeStrategyStatus>();
        }

        return strategyOutbounds
            .Select(outbound =>
            {
                return new RuntimeStrategyStatus
                {
                    Tag = outbound.Tag,
                    Protocol = OutboundProtocols.Normalize(outbound.Protocol),
                    SelectedTag = outbound.SelectedTag,
                    ProbeUrl = outbound.ProbeUrl,
                    CandidateTags = outbound.CandidateTags.ToArray(),
                    ProbeResults = ResolveStrategyProbeResults(outbound.Tag)
                };
            })
            .ToArray();
    }

    private IReadOnlyList<StrategyCandidateProbeResult> ResolveStrategyProbeResults(string tag)
    {
        if (_featureGraph.StrategyProbeCache?.TryGetCachedResults(tag, out var cachedResults) == true)
        {
            return cachedResults;
        }

        return _strategyProbeSnapshots.TryGetValue(tag, out var snapshotResults)
            ? snapshotResults
            : Array.Empty<StrategyCandidateProbeResult>();
    }

    private static IReadOnlyList<OutboundRuntime> GetStrategyOutbounds(RuntimePlan plan)
    {
        return plan.Plan.Outbound.Outbounds
            .Where(static outbound =>
            {
                var protocol = OutboundProtocols.Normalize(outbound.Protocol);
                return protocol is
                    OutboundProtocols.Selector or
                    OutboundProtocols.UrlTest or
                    OutboundProtocols.Fallback or
                    OutboundProtocols.LoadBalance;
            })
            .OrderBy(static outbound => outbound.Tag, StringComparer.Ordinal)
            .ToArray();
    }

    private static StrategyOutboundSettings CreateStrategySettings(OutboundRuntime outbound)
    {
        return new StrategyOutboundSettings
        {
            Tag = outbound.Tag,
            Protocol = OutboundProtocols.Normalize(outbound.Protocol),
            CandidateTags = outbound.CandidateTags.ToArray(),
            SelectedTag = outbound.SelectedTag,
            ProbeUrl = outbound.ProbeUrl,
            ProbeIntervalSeconds = outbound.ProbeIntervalSeconds,
            ProbeTimeoutSeconds = outbound.ProbeTimeoutSeconds,
            ToleranceMilliseconds = outbound.ToleranceMilliseconds
        };
    }

    private static ProxyInboundServerLimits CreateProxyInboundLimits(RuntimeTransportLimits limits)
    {
        return new ProxyInboundServerLimits
        {
            ConnectTimeoutSeconds = limits.ConnectTimeoutSeconds,
            ConnectionIdleSeconds = limits.ConnectionIdleSeconds,
            UplinkOnlySeconds = limits.UplinkOnlySeconds,
            DownlinkOnlySeconds = limits.DownlinkOnlySeconds
        };
    }

    private static RuntimeStatusSnapshot CreateStatusSnapshot(
        RuntimePlan plan,
        RuntimeState state,
        string message,
        IReadOnlyList<RuntimeListenerStatus> listeners)
    {
        return new RuntimeStatusSnapshot
        {
            Revision = plan.Revision,
            State = state,
            Message = message,
            UpdatedAt = DateTimeOffset.UtcNow,
            KnownUsers = plan.ActiveUsers.Count,
            Listeners = listeners
        };
    }

    private IReadOnlyList<RuntimeListenerStatus> SetListenerState(
        IReadOnlyList<string> listenerKeys,
        RuntimeState state,
        string message)
    {
        if (listenerKeys.Count == 0)
        {
            return Array.Empty<RuntimeListenerStatus>();
        }

        RuntimeStatusSnapshot updatedSnapshot;
        lock (_statusSync)
        {
            var keySet = listenerKeys.ToHashSet(StringComparer.Ordinal);
            var timestamp = DateTimeOffset.UtcNow;
            var listeners = _status.Listeners
                .Select(listener =>
                    keySet.Contains(RuntimeListenerKeys.CreateListenerKey(listener.Protocol, listener.Tag, listener.Transport, listener.Binding))
                        ? listener with
                        {
                            State = state,
                            Message = message,
                            LastStartedAt = state == RuntimeState.Running
                                ? timestamp
                                : listener.LastStartedAt,
                            UpdatedAt = timestamp
                        }
                        : listener)
                .ToArray();

            _status = _status with
            {
                Listeners = listeners,
                UpdatedAt = timestamp
            };
            updatedSnapshot = _status;
        }

        return updatedSnapshot.Listeners
            .Where(listener => listenerKeys.Contains(
                RuntimeListenerKeys.CreateListenerKey(listener.Protocol, listener.Tag, listener.Transport, listener.Binding),
                StringComparer.Ordinal))
            .ToArray();
    }

    private void SetAllListenersState(RuntimeState state, string message)
    {
        SetStatus(current =>
        {
            var timestamp = DateTimeOffset.UtcNow;
            return current with
            {
                Listeners = current.Listeners
                    .Select(listener => listener with
                    {
                        State = state,
                        Message = message,
                        UpdatedAt = timestamp
                    })
                    .ToArray(),
                UpdatedAt = timestamp
            };
        });
    }

    private void PublishStateChanged(int revision, RuntimeState state, string message)
    {
        PublishEvent(
            new RuntimeStateChangedEvent
            {
                Revision = revision,
                State = state,
                Message = message
            });
    }

    private void PublishListenerStarted(
        int revision,
        IReadOnlyList<RuntimeListenerStatus> listeners,
        string message)
    {
        foreach (var listener in listeners)
        {
            PublishEvent(
                new RuntimeListenerStartedEvent
                {
                    Revision = revision,
                    Message = message,
                    Listener = listener
                });
        }
    }

    private void PublishConnectionError(
        int revision,
        string protocol,
        string tag,
        bool isProxyInbound,
        string? remoteEndPoint,
        string message,
        Exception exception)
    {
        PublishEvent(
            new RuntimeConnectionErrorEvent
            {
                Revision = revision,
                Protocol = protocol,
                Tag = tag,
                IsProxyInbound = isProxyInbound,
                RemoteEndPoint = remoteEndPoint,
                Message = message,
                Exception = exception
            });
    }

    private void PublishConnectionAccessed(
        int revision,
        string protocol,
        string tag,
        string targetHost,
        int targetPort,
        string network)
    {
        PublishEvent(
            new RuntimeConnectionAccessedEvent
            {
                Revision = revision,
                Protocol = protocol,
                Tag = tag,
                TargetHost = targetHost,
                TargetPort = targetPort,
                Network = network,
                Message = $"[{network.ToUpperInvariant()}] {targetHost}:{targetPort} via {tag} (Inbound: {protocol})"
            });
    }

    private void PublishClientHelloRejected(
        int revision,
        string protocol,
        string? remoteEndPoint,
        string? serverName,
        string? ja3Hash,
        string? reason)
    {
        PublishEvent(
            new RuntimeClientHelloRejectedEvent
            {
                Revision = revision,
                Protocol = protocol,
                RemoteEndPoint = remoteEndPoint,
                ServerName = serverName ?? string.Empty,
                Ja3Hash = ja3Hash ?? string.Empty,
                Reason = reason ?? string.Empty,
                Message = "Inbound connection rejected by client hello policy."
            });
    }

    private void PublishUnknownServerNameRejected(
        int revision,
        string protocol,
        string? remoteEndPoint,
        string? requestedServerName)
    {
        PublishEvent(
            new RuntimeUnknownServerNameRejectedEvent
            {
                Revision = revision,
                Protocol = protocol,
                RemoteEndPoint = remoteEndPoint,
                RequestedServerName = requestedServerName ?? string.Empty,
                Message = "Inbound connection rejected due to unknown server name."
            });
    }

    private void PublishFault(int revision, string taskName, string message, Exception exception)
    {
        PublishEvent(
            new RuntimeFaultedEvent
            {
                Revision = revision,
                TaskName = taskName,
                Message = message,
                Exception = exception
            });
    }

    private void PublishEvent(RuntimeEvent runtimeEvent)
    {
        _events.Writer.TryWrite(runtimeEvent);
    }

    private RuntimeStatusSnapshot SetStatus(Func<RuntimeStatusSnapshot, RuntimeStatusSnapshot> update)
    {
        lock (_statusSync)
        {
            _status = update(_status);
            return _status;
        }
    }

    private void ThrowIfDisposed()
    {
        if (Volatile.Read(ref _disposed) != 0)
        {
            throw new ObjectDisposedException(nameof(DefaultRuntime));
        }
    }
}

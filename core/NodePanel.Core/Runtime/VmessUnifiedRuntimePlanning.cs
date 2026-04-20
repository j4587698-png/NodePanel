using System.Net;
using NodePanel.Core.Protocol;

namespace NodePanel.Core.Runtime;

public interface IVmessUserDefinition : IRuntimeUserDefinition
{
    string Uuid { get; }
}

public interface IVmessInboundDefinition
{
    string Tag { get; }

    bool Enabled { get; }

    string Protocol { get; }

    string Transport { get; }

    string ListenAddress { get; }

    int Port { get; }

    int HandshakeTimeoutSeconds { get; }

    bool AcceptProxyProtocol { get; }

    string Host { get; }

    string Path { get; }

    int EarlyDataBytes { get; }

    int HeartbeatPeriodSeconds { get; }

    IReadOnlyList<string> ApplicationProtocols { get; }
}

public interface IVmessInboundScopeDefinition
{
    IReadOnlyList<IVmessUserDefinition> GetVmessUsers();

    IRuntimeSniffingDefinition GetSniffing();

    bool GetReceiveOriginalDestination();
}

public sealed record VmessUser : IRuntimeUserDefinition, IRuntimeScopedUserDefinition
{
    public required string UserId { get; init; }

    public required string Uuid { get; init; }

    public required byte[] CmdKey { get; init; }

    public string RuntimeKey { get; init; } = string.Empty;

    public int Level { get; init; }

    public required long BytesPerSecond { get; init; }

    public int DeviceLimit { get; init; }
}

public sealed record VmessTlsInboundRuntime
{
    private string _transportProtocol = string.Empty;
    private string _securityType = string.Empty;

    internal VmessInboundRuntimeState RuntimeState { get; init; } = new(Array.Empty<VmessUser>());

    public required string Tag { get; init; }

    public required string Transport { get; init; }

    public string TransportProtocol
    {
        get => ResolveInternetStack().TransportProtocol;
        init => _transportProtocol = value ?? string.Empty;
    }

    public string SecurityType
    {
        get => ResolveInternetStack().SecurityType;
        init => _securityType = value ?? string.Empty;
    }

    public required ListenerBinding Binding { get; init; }

    public int HandshakeTimeoutSeconds { get; init; } = 60;

    public string Host { get; init; } = string.Empty;

    public string Path { get; init; } = string.Empty;

    public int EarlyDataBytes { get; init; }

    public int HeartbeatPeriodSeconds { get; init; }

    public IReadOnlyList<string> ApplicationProtocols { get; init; } = Array.Empty<string>();

    public RuntimeQuicOptions QuicOptions { get; init; } = RuntimeQuicOptions.Empty;

    public RuntimeGrpcTransportOptions Grpc { get; init; } = RuntimeGrpcTransportOptions.Empty;

    public RuntimeSplitHttpInboundOptions SplitHttp { get; init; } = RuntimeSplitHttpInboundOptions.Empty;

    public bool ReceiveOriginalDestination { get; init; }

    public RuntimeSniffingOptions Sniffing { get; init; } = new();

    public IReadOnlyList<VmessUser> Users { get; init; } = Array.Empty<VmessUser>();

    public ulong BehaviorSeed => RuntimeState.BehaviorSeed;

    public InboundInternetStack InternetStack => ResolveInternetStack();

    private InboundInternetStack ResolveInternetStack()
        => InboundInternetStackResolver.Resolve(
            Transport,
            string.IsNullOrWhiteSpace(_transportProtocol) ? null : _transportProtocol,
            string.IsNullOrWhiteSpace(_securityType) ? null : _securityType);
}

public sealed record VmessTlsListenerRuntime
{
    private IReadOnlyList<VmessTlsInboundRuntime>? _inbounds;

    public required ListenerBinding Binding { get; init; }

    public bool AcceptProxyProtocol { get; init; }

    public IReadOnlyList<string> ApplicationProtocols { get; init; } = Array.Empty<string>();

    public IReadOnlyList<VmessTlsInboundRuntime> Inbounds
    {
        get => _inbounds ?? ComposeLegacyInbounds(RawTlsInbound, MkcpInbound, WebSocketInbound, HttpUpgradeInbound, GrpcInbound, SplitHttpInbound);
        init => _inbounds = value;
    }

    public VmessTlsInboundRuntime? RawTlsInbound { get; init; }

    public VmessTlsInboundRuntime? MkcpInbound { get; init; }

    public VmessTlsInboundRuntime? WebSocketInbound { get; init; }

    public VmessTlsInboundRuntime? HttpUpgradeInbound { get; init; }

    public VmessTlsInboundRuntime? GrpcInbound { get; init; }

    public VmessTlsInboundRuntime? SplitHttpInbound { get; init; }

    public bool IsShared => Inbounds.Count > 1;

    private static IReadOnlyList<VmessTlsInboundRuntime> ComposeLegacyInbounds(
        VmessTlsInboundRuntime? rawTlsInbound,
        VmessTlsInboundRuntime? mkcpInbound,
        VmessTlsInboundRuntime? webSocketInbound,
        VmessTlsInboundRuntime? httpUpgradeInbound,
        VmessTlsInboundRuntime? grpcInbound,
        VmessTlsInboundRuntime? splitHttpInbound)
    {
        var items = new List<VmessTlsInboundRuntime>(6);
        if (rawTlsInbound is not null)
        {
            items.Add(rawTlsInbound);
        }

        if (mkcpInbound is not null)
        {
            items.Add(mkcpInbound);
        }

        if (webSocketInbound is not null)
        {
            items.Add(webSocketInbound);
        }

        if (httpUpgradeInbound is not null)
        {
            items.Add(httpUpgradeInbound);
        }

        if (grpcInbound is not null)
        {
            items.Add(grpcInbound);
        }

        if (splitHttpInbound is not null)
        {
            items.Add(splitHttpInbound);
        }

        return items;
    }
}

public sealed record VmessInboundRuntimePlan : IInboundProtocolRuntimePlan
{
    private IReadOnlyList<VmessTlsListenerRuntime>? _listeners;

    public static VmessInboundRuntimePlan Empty { get; } = new();

    public string Protocol => InboundProtocols.Vmess;

    public IReadOnlyList<VmessTlsListenerRuntime> Listeners
    {
        get => _listeners ?? ComposeListeners(TlsListeners, RealityListeners, PlainListeners);
        init => _listeners = value;
    }

    public IReadOnlyList<VmessTlsListenerRuntime> TlsListeners { get; init; } = Array.Empty<VmessTlsListenerRuntime>();

    public IReadOnlyList<VmessTlsListenerRuntime> RealityListeners { get; init; } = Array.Empty<VmessTlsListenerRuntime>();

    public IReadOnlyList<VmessTlsListenerRuntime> PlainListeners { get; init; } = Array.Empty<VmessTlsListenerRuntime>();

    public bool RequiresCertificate => TlsListeners.Count > 0;

    public bool RequiresReality => RealityListeners.Count > 0;

    public bool HasTcpTls => TlsListeners.Any(static listener => listener.Inbounds.Any(static inbound =>
        InboundInternetStackResolver.IsTcpTls(inbound.TransportProtocol, inbound.SecurityType)));

    public bool HasWss => TlsListeners.Any(static listener => listener.Inbounds.Any(static inbound =>
        InboundInternetStackResolver.IsWsTls(inbound.TransportProtocol, inbound.SecurityType)));

    public bool HasGrpc => TlsListeners.Any(static listener => listener.Inbounds.Any(static inbound =>
        InboundInternetStackResolver.IsGrpcTls(inbound.TransportProtocol, inbound.SecurityType)));

    public bool HasSplitHttp => TlsListeners.Any(static listener => listener.Inbounds.Any(static inbound =>
        InboundInternetStackResolver.IsSplitHttpTls(inbound.TransportProtocol, inbound.SecurityType)));

    private static IReadOnlyList<VmessTlsListenerRuntime> ComposeListeners(
        IReadOnlyList<VmessTlsListenerRuntime> tlsListeners,
        IReadOnlyList<VmessTlsListenerRuntime> realityListeners,
        IReadOnlyList<VmessTlsListenerRuntime> plainListeners)
    {
        if (tlsListeners.Count == 0 &&
            realityListeners.Count == 0)
        {
            return plainListeners;
        }

        if (plainListeners.Count == 0 &&
            realityListeners.Count == 0)
        {
            return tlsListeners;
        }

        if (tlsListeners.Count == 0 &&
            plainListeners.Count == 0)
        {
            return realityListeners;
        }

        return tlsListeners.Concat(realityListeners).Concat(plainListeners).ToArray();
    }
}

public static class VmessInboundRuntimePlanner
{
    public static bool TryBuild(
        IReadOnlyList<IVmessInboundDefinition> inbounds,
        out VmessInboundRuntimePlan plan,
        out string? error)
    {
        ArgumentNullException.ThrowIfNull(inbounds);

        var normalized = Normalize(inbounds, out error);
        if (normalized is null)
        {
            plan = VmessInboundRuntimePlan.Empty;
            return false;
        }

        if (!ValidateBindingConflicts(normalized, out error))
        {
            plan = VmessInboundRuntimePlan.Empty;
            return false;
        }

        var listeners = BuildListeners(normalized, out error);
        if (listeners is null)
        {
            plan = VmessInboundRuntimePlan.Empty;
            return false;
        }

        var tlsListeners = listeners
            .Where(static listener => listener.Inbounds.Any(static inbound => IsTlsSecurity(inbound.SecurityType)))
            .ToArray();
        var realityListeners = listeners
            .Where(static listener => listener.Inbounds.Any(static inbound => IsRealitySecurity(inbound.SecurityType)))
            .ToArray();
        var plainListeners = listeners
            .Where(static listener => listener.Inbounds.Any(static inbound => IsPlainSecurity(inbound.SecurityType)))
            .ToArray();

        plan = new VmessInboundRuntimePlan
        {
            Listeners = listeners,
            TlsListeners = tlsListeners,
            RealityListeners = realityListeners,
            PlainListeners = plainListeners
        };
        error = null;
        return true;
    }

    public static VmessTlsInboundRuntime? SelectInbound(
        VmessTlsListenerRuntime listener,
        ReadOnlySpan<byte> initialPayload)
    {
        ArgumentNullException.ThrowIfNull(listener);

        if (RuntimeHttp2RequestProbe.LooksLikeConnectionPreface(initialPayload))
        {
            if (listener.SplitHttpInbound is not null &&
                RuntimeHttp2RequestProbe.TryExtractRequestPath(initialPayload, out var http2RequestPath) &&
                RuntimeSplitHttpRequestMetadata.MatchesPathPrefix(
                    http2RequestPath,
                    listener.SplitHttpInbound.Path))
            {
                return listener.SplitHttpInbound;
            }

            return listener.GrpcInbound
                   ?? listener.SplitHttpInbound
                   ?? listener.RawTlsInbound;
        }

        var requestPath = HttpRequestProbe.ExtractRequestPath(initialPayload);
        var splitHttpMatched = listener.SplitHttpInbound is not null &&
                               RuntimeSplitHttpRequestMetadata.MatchesPathPrefix(
                                   requestPath,
                                   listener.SplitHttpInbound.Path);
        var webSocketMatched = listener.WebSocketInbound is not null &&
                               string.Equals(requestPath, listener.WebSocketInbound.Path, StringComparison.Ordinal);
        var httpUpgradeMatched = listener.HttpUpgradeInbound is not null &&
                                 string.Equals(requestPath, listener.HttpUpgradeInbound.Path, StringComparison.Ordinal);

        if (splitHttpMatched && (webSocketMatched || httpUpgradeMatched))
        {
            return HttpRequestProbe.IsWebSocketUpgradeRequest(initialPayload)
                ? webSocketMatched && httpUpgradeMatched
                    ? HttpRequestProbe.LooksLikeWebSocketHandshake(initialPayload)
                        ? listener.WebSocketInbound
                        : listener.HttpUpgradeInbound
                    : webSocketMatched
                        ? listener.WebSocketInbound
                        : listener.HttpUpgradeInbound
                : listener.SplitHttpInbound;
        }

        if (webSocketMatched && httpUpgradeMatched)
        {
            return HttpRequestProbe.LooksLikeWebSocketHandshake(initialPayload)
                ? listener.WebSocketInbound
                : listener.HttpUpgradeInbound;
        }

        if (webSocketMatched)
        {
            return listener.WebSocketInbound;
        }

        if (httpUpgradeMatched)
        {
            return listener.HttpUpgradeInbound;
        }

        if (splitHttpMatched)
        {
            return listener.SplitHttpInbound;
        }

        return listener.RawTlsInbound
               ?? listener.SplitHttpInbound
               ?? listener.WebSocketInbound
               ?? listener.HttpUpgradeInbound;
    }

    private static IReadOnlyList<NormalizedInbound>? Normalize(
        IReadOnlyList<IVmessInboundDefinition> inbounds,
        out string? error)
    {
        var items = new List<NormalizedInbound>(inbounds.Count);

        for (var index = 0; index < inbounds.Count; index++)
        {
            var inbound = inbounds[index];
            if (!inbound.Enabled)
            {
                continue;
            }

            if (!string.Equals(InboundProtocols.Normalize(inbound.Protocol), InboundProtocols.Vmess, StringComparison.Ordinal))
            {
                continue;
            }

            var internetDefinition = inbound as IInboundInternetDefinition;
            if (!InboundInternetStackResolver.TryResolve(
                    inbound.Transport,
                    internetDefinition?.TransportProtocol,
                    internetDefinition?.TransportSecurity,
                    out var internetStack,
                    out error))
            {
                return null;
            }

            if (!IsSupportedInboundStack(internetStack.TransportProtocol, internetStack.SecurityType))
            {
                error = $"Unsupported VMess inbound transport/security stack: {internetStack.TransportProtocol}+{internetStack.SecurityType}. Currently only tcp/ws/httpupgrade/grpc/splithttp with none/tls security, mkcp with none security, plus tcp/grpc/splithttp with reality security, are supported.";
                return null;
            }

            var listenAddress = NormalizeListenAddress(inbound.ListenAddress);
            var port = NormalizeListenerPort(
                inbound.Port,
                IsWsTransport(internetStack.TransportProtocol) || IsHttpUpgradeTransport(internetStack.TransportProtocol) ? 8443 : 443);
            if (IsMkcpTransport(internetStack.TransportProtocol) &&
                !IPAddress.TryParse(listenAddress, out _))
            {
                error = "VMess mKCP inbound does not support UNIX listeners.";
                return null;
            }

            if (!IsValidListenerBinding(listenAddress, port))
            {
                error = $"Invalid {internetStack.Transport.ToUpperInvariant()} listen address: {listenAddress}.";
                return null;
            }

            var tag = NormalizeTag(inbound.Tag, internetStack.Transport, index);

            items.Add(new NormalizedInbound
            {
                Tag = tag,
                Transport = internetStack.Transport,
                TransportProtocol = internetStack.TransportProtocol,
                SecurityType = internetStack.SecurityType,
                Binding = new ListenerBinding(listenAddress, port),
                HandshakeTimeoutSeconds = NormalizePositive(inbound.HandshakeTimeoutSeconds, 60),
                AcceptProxyProtocol = inbound.AcceptProxyProtocol,
                Host = inbound.Host.Trim(),
                Path = IsWsTransport(internetStack.TransportProtocol) || IsHttpUpgradeTransport(internetStack.TransportProtocol)
                    ? NormalizePath(inbound.Path)
                    : IsSplitHttpTransport(internetStack.TransportProtocol)
                        ? RuntimeSplitHttpRequestMetadata.NormalizePath(inbound.Path)
                        : string.Empty,
                EarlyDataBytes = Math.Max(0, inbound.EarlyDataBytes),
                HeartbeatPeriodSeconds = Math.Max(0, inbound.HeartbeatPeriodSeconds),
                ApplicationProtocols = NormalizeInboundApplicationProtocols(
                    internetStack.TransportProtocol,
                    inbound.ApplicationProtocols),
                QuicOptions = inbound is IInboundQuicDefinition quicDefinition
                    ? RuntimeQuicOptionsNormalizer.Normalize(quicDefinition.QuicOptions)
                    : RuntimeQuicOptions.Empty,
                Grpc = RuntimeGrpcTransportOptions.Normalize(
                    inbound as IInboundGrpcDefinition,
                    internetStack.IsGrpcTransport),
                ReceiveOriginalDestination = inbound is IVmessInboundScopeDefinition scopedReceiver &&
                                             scopedReceiver.GetReceiveOriginalDestination(),
                Sniffing = inbound is IVmessInboundScopeDefinition scopedSniffing
                    ? NormalizeSniffing(scopedSniffing.GetSniffing())
                    : new RuntimeSniffingOptions(),
                Users = inbound is IVmessInboundScopeDefinition scopedInbound
                    ? CompileUsers(scopedInbound.GetVmessUsers(), tag)
                    : Array.Empty<VmessUser>(),
                SplitHttp = RuntimeSplitHttpInboundOptions.Empty
            });

            if (IsSplitHttpTransport(internetStack.TransportProtocol))
            {
                if (!RuntimeSplitHttpInboundOptionsNormalizer.TryNormalize(
                        inbound.Host,
                        inbound.Path,
                        inbound as IInboundSplitHttpDefinition,
                        out var splitHttp,
                        out error))
                {
                    return null;
                }

                items[^1] = items[^1] with
                {
                    Host = splitHttp.Host,
                    Path = splitHttp.Path,
                    SplitHttp = splitHttp
                };
            }
        }

        error = null;
        return items;
    }

    private static bool ValidateBindingConflicts(
        IReadOnlyList<NormalizedInbound> inbounds,
        out string? error)
    {
        for (var i = 0; i < inbounds.Count; i++)
        {
            for (var j = i + 1; j < inbounds.Count; j++)
            {
                var left = inbounds[i];
                var right = inbounds[j];

                if (left.Binding.IsUnix && right.Binding.IsUnix)
                {
                    if (string.Equals(left.Binding.ListenAddress, right.Binding.ListenAddress, StringComparison.OrdinalIgnoreCase))
                    {
                        error = "VMess inbounds cannot bind the same UNIX listener path more than once.";
                        return false;
                    }

                    continue;
                }

                if (left.Binding.IsUnix || right.Binding.IsUnix)
                {
                    continue;
                }

                if (left.Binding.Port != right.Binding.Port)
                {
                    continue;
                }

                if (string.Equals(left.Binding.ListenAddress, right.Binding.ListenAddress, StringComparison.OrdinalIgnoreCase))
                {
                    continue;
                }

                if (IsWildcardAddress(left.Binding.ListenAddress) || IsWildcardAddress(right.Binding.ListenAddress))
                {
                    error = "VMess inbounds cannot bind the same TCP port when one side uses a wildcard listen address unless both listeners share the exact same address.";
                    return false;
                }
            }
        }

        error = null;
        return true;
    }

    private static IReadOnlyList<VmessTlsListenerRuntime>? BuildListeners(
        IReadOnlyList<NormalizedInbound> inbounds,
        out string? error)
    {
        var groups = inbounds
            .GroupBy(static inbound => GetBindingKey(inbound.Binding), StringComparer.Ordinal)
            .OrderBy(static group => group.Key, StringComparer.Ordinal);

        var listeners = new List<VmessTlsListenerRuntime>();

        foreach (var group in groups)
        {
            var entries = group.ToArray();
            var binding = entries[0].Binding;

            if (binding.IsUnix && entries.Length > 1)
            {
                error = "VMess inbounds cannot share the same UNIX listener path.";
                return null;
            }

            if (entries.Select(static item => item.AcceptProxyProtocol).Distinct().Count() > 1)
            {
                error = "VMess inbounds that share the same listener binding must use the same AcceptProxyProtocol setting.";
                return null;
            }

            if (entries
                    .Select(static item => RuntimeInternetSecurityTypes.Normalize(item.SecurityType))
                    .Distinct(StringComparer.Ordinal)
                    .Count() > 1)
            {
                error = $"VMess listener {group.Key} mixes none/tls/reality security on the same binding, which is not supported.";
                return null;
            }

            var rawTlsInbound = entries.SingleOrDefault(static item =>
                IsTcpTransport(item.TransportProtocol));
            var mkcpInbound = entries.SingleOrDefault(static item =>
                IsMkcpTransport(item.TransportProtocol));
            var webSocketInbound = entries.SingleOrDefault(static item =>
                IsWsTransport(item.TransportProtocol));
            if (entries.Count(static item =>
                    IsTcpTransport(item.TransportProtocol)) > 1 ||
                entries.Count(static item =>
                    IsMkcpTransport(item.TransportProtocol)) > 1 ||
                entries.Count(static item =>
                    IsWsTransport(item.TransportProtocol)) > 1 ||
                entries.Count(static item =>
                    IsHttpUpgradeTransport(item.TransportProtocol)) > 1 ||
                entries.Count(static item =>
                    IsGrpcTransport(item.TransportProtocol)) > 1 ||
                entries.Count(static item =>
                    IsSplitHttpTransport(item.TransportProtocol)) > 1)
            {
                error = $"VMess listener {group.Key} defines duplicate transports on the same binding.";
                return null;
            }

            if (mkcpInbound is not null && entries.Length > 1)
            {
                error = $"VMess listener {group.Key} cannot share mKCP with other transports on the same binding.";
                return null;
            }

            if (!RuntimeSplitHttpInboundPlanning.TryValidateSharedBinding(
                    InboundProtocols.Vmess,
                    group.Key,
                    entries,
                    static item => item.SecurityType,
                    static item => item.TransportProtocol,
                    static item => item.ApplicationProtocols,
                    UsesTlsLikeSecurity,
                    IsSplitHttpTransport,
                    out error))
            {
                return null;
            }

            var runtimeInbounds = entries
                .Select(ToRuntime)
                .OrderBy(static inbound => inbound.TransportProtocol, StringComparer.Ordinal)
                .ThenBy(static inbound => inbound.SecurityType, StringComparer.Ordinal)
                .ToArray();

            listeners.Add(new VmessTlsListenerRuntime
            {
                Binding = binding,
                AcceptProxyProtocol = entries[0].AcceptProxyProtocol,
                ApplicationProtocols = BuildListenerApplicationProtocols(entries),
                Inbounds = runtimeInbounds,
                RawTlsInbound = runtimeInbounds.SingleOrDefault(static inbound =>
                    IsTcpTransport(inbound.TransportProtocol)),
                MkcpInbound = runtimeInbounds.SingleOrDefault(static inbound =>
                    IsMkcpTransport(inbound.TransportProtocol)),
                WebSocketInbound = runtimeInbounds.SingleOrDefault(static inbound =>
                    IsWsTransport(inbound.TransportProtocol)),
                HttpUpgradeInbound = runtimeInbounds.SingleOrDefault(static inbound =>
                    IsHttpUpgradeTransport(inbound.TransportProtocol)),
                GrpcInbound = runtimeInbounds.SingleOrDefault(static inbound =>
                    IsGrpcTransport(inbound.TransportProtocol)),
                SplitHttpInbound = runtimeInbounds.SingleOrDefault(static inbound =>
                    IsSplitHttpTransport(inbound.TransportProtocol))
            });
        }

        error = null;
        return listeners;
    }

    private static VmessTlsInboundRuntime ToRuntime(NormalizedInbound inbound)
        => new()
        {
            RuntimeState = new VmessInboundRuntimeState(inbound.Users),
            Tag = inbound.Tag,
            Transport = inbound.Transport,
            TransportProtocol = inbound.TransportProtocol,
            SecurityType = inbound.SecurityType,
            Binding = inbound.Binding,
            HandshakeTimeoutSeconds = inbound.HandshakeTimeoutSeconds,
            Host = inbound.Host,
            Path = inbound.Path,
            EarlyDataBytes = inbound.EarlyDataBytes,
            HeartbeatPeriodSeconds = inbound.HeartbeatPeriodSeconds,
            ApplicationProtocols = inbound.ApplicationProtocols,
            QuicOptions = inbound.QuicOptions,
            Grpc = inbound.Grpc,
            SplitHttp = inbound.SplitHttp,
            ReceiveOriginalDestination = inbound.ReceiveOriginalDestination,
            Sniffing = inbound.Sniffing,
            Users = inbound.Users
        };

    private static IReadOnlyList<string> BuildListenerApplicationProtocols(IReadOnlyList<NormalizedInbound> inbounds)
    {
        var ordered = new List<string>();
        var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

        if (inbounds.Any(static inbound =>
                UsesTlsLikeSecurity(inbound.SecurityType) &&
                (IsWsTransport(inbound.TransportProtocol) || IsHttpUpgradeTransport(inbound.TransportProtocol))))
        {
            AddApplicationProtocol("http/1.1", ordered, seen);
        }

        if (inbounds.Any(static inbound =>
                UsesTlsLikeSecurity(inbound.SecurityType) &&
                IsGrpcTransport(inbound.TransportProtocol)))
        {
            AddApplicationProtocol("h2", ordered, seen);
        }

        RuntimeSplitHttpInboundPlanning.AddListenerApplicationProtocols(
            inbounds,
            static inbound => inbound.SecurityType,
            static inbound => inbound.TransportProtocol,
            static inbound => inbound.ApplicationProtocols,
            UsesTlsLikeSecurity,
            IsSplitHttpTransport,
            applicationProtocol => AddApplicationProtocol(applicationProtocol, ordered, seen));

        foreach (var inbound in inbounds)
        {
            if (!UsesTlsLikeSecurity(inbound.SecurityType) ||
                !IsTcpTransport(inbound.TransportProtocol))
            {
                continue;
            }

            foreach (var applicationProtocol in inbound.ApplicationProtocols)
            {
                AddApplicationProtocol(applicationProtocol, ordered, seen);
            }
        }

        return ordered;
    }

    private static IReadOnlyList<VmessUser> CompileUsers(
        IReadOnlyList<IVmessUserDefinition> users,
        string inboundTag)
    {
        if (users.Count == 0)
        {
            return Array.Empty<VmessUser>();
        }

        var compiled = new List<VmessUser>(users.Count);
        var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (var user in users)
        {
            if (string.IsNullOrWhiteSpace(user.UserId) ||
                !ProtocolUuid.TryNormalize(user.Uuid, out var normalizedUuid) ||
                !seen.Add(normalizedUuid))
            {
                continue;
            }

            compiled.Add(new VmessUser
            {
                UserId = user.UserId.Trim(),
                Uuid = normalizedUuid,
                CmdKey = VmessAccountCodec.CreateCommandKey(normalizedUuid),
                RuntimeKey = RuntimeUserKeys.Create(InboundProtocols.Vmess, inboundTag, user.UserId),
                Level = Math.Max(0, user.Level),
                BytesPerSecond = Math.Max(0, user.BytesPerSecond),
                DeviceLimit = Math.Max(0, user.DeviceLimit)
            });
        }

        return compiled;
    }

    private static RuntimeSniffingOptions NormalizeSniffing(IRuntimeSniffingDefinition sniffing)
        => new()
        {
            Enabled = sniffing.Enabled,
            DestinationOverride = sniffing.DestinationOverride
                .Where(static value => !string.IsNullOrWhiteSpace(value))
                .Select(static value => RoutingProtocols.Normalize(value))
                .Distinct(StringComparer.OrdinalIgnoreCase)
                .ToArray(),
            DomainsExcluded = sniffing.DomainsExcluded
                .Where(static value => !string.IsNullOrWhiteSpace(value))
                .Select(static value => value.Trim().ToLowerInvariant())
                .Distinct(StringComparer.OrdinalIgnoreCase)
                .ToArray(),
            MetadataOnly = sniffing.MetadataOnly,
            RouteOnly = sniffing.RouteOnly
        };

    private static string NormalizeTag(string value, string transport, int index)
        => string.IsNullOrWhiteSpace(value)
            ? $"vmess-{transport}-{index + 1}"
            : value.Trim();

    private static string NormalizeListenAddress(string value)
        => string.IsNullOrWhiteSpace(value) ? "0.0.0.0" : value.Trim();

    private static int NormalizeListenerPort(int value, int fallback)
        => value is >= 0 and <= 65535 ? value : fallback;

    private static int NormalizePositive(int value, int fallback)
        => value > 0 ? value : fallback;

    private static string NormalizePath(string value)
    {
        if (string.IsNullOrWhiteSpace(value))
        {
            return "/ws";
        }

        var trimmed = value.Trim();
        return trimmed.StartsWith("/", StringComparison.Ordinal) ? trimmed : "/" + trimmed;
    }

    private static IReadOnlyList<string> NormalizeApplicationProtocols(IReadOnlyList<string> values)
    {
        if (values.Count == 0)
        {
            return Array.Empty<string>();
        }

        var normalized = new List<string>(values.Count);
        var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (var value in values)
        {
            AddApplicationProtocol(value, normalized, seen);
        }

        return normalized;
    }

    private static IReadOnlyList<string> NormalizeInboundApplicationProtocols(
        string transportProtocol,
        IReadOnlyList<string> values)
        => RuntimeInternetTransportProtocols.Normalize(transportProtocol) switch
        {
            RuntimeInternetTransportProtocols.Tcp => NormalizeApplicationProtocols(values),
            RuntimeInternetTransportProtocols.Ws or RuntimeInternetTransportProtocols.HttpUpgrade => ["http/1.1"],
            RuntimeInternetTransportProtocols.Grpc => ["h2"],
            RuntimeInternetTransportProtocols.SplitHttp
                => RuntimeSplitHttpInboundPlanning.NormalizeApplicationProtocols(
                    values,
                    NormalizeApplicationProtocols),
            _ => Array.Empty<string>()
        };

    private static void AddApplicationProtocol(
        string? value,
        ICollection<string> destination,
        ISet<string> seen)
    {
        if (string.IsNullOrWhiteSpace(value))
        {
            return;
        }

        var normalized = value.Trim();
        if (!seen.Add(normalized))
        {
            return;
        }

        destination.Add(normalized);
    }

    private static bool IsValidListenerBinding(string address, int port)
    {
        if (port == 0)
        {
            return !string.IsNullOrWhiteSpace(address) && !IPAddress.TryParse(address, out _);
        }

        return IPAddress.TryParse(address, out _);
    }

    private static bool IsWildcardAddress(string value)
        => string.Equals(value, "0.0.0.0", StringComparison.OrdinalIgnoreCase) ||
           string.Equals(value, "::", StringComparison.OrdinalIgnoreCase);

    private static string GetBindingKey(ListenerBinding binding)
        => binding.IsUnix
            ? "unix:" + binding.ListenAddress
            : binding.ListenAddress + ":" + binding.Port.ToString();

    private static bool IsSupportedInboundStack(string transportProtocol, string securityType)
        => (IsPlainSecurity(securityType) || IsTlsSecurity(securityType)) &&
           (IsTcpTransport(transportProtocol) ||
            IsWsTransport(transportProtocol) ||
            IsHttpUpgradeTransport(transportProtocol) ||
            IsGrpcTransport(transportProtocol) ||
            IsSplitHttpTransport(transportProtocol)) ||
           IsPlainSecurity(securityType) &&
           IsMkcpTransport(transportProtocol) ||
           IsRealitySecurity(securityType) &&
           (IsTcpTransport(transportProtocol) ||
            IsGrpcTransport(transportProtocol) ||
            IsSplitHttpTransport(transportProtocol));

    private static bool IsPlainSecurity(string securityType)
        => string.Equals(
            RuntimeInternetSecurityTypes.Normalize(securityType),
            RuntimeInternetSecurityTypes.None,
            StringComparison.Ordinal);

    private static bool IsTlsSecurity(string securityType)
        => string.Equals(
            RuntimeInternetSecurityTypes.Normalize(securityType),
            RuntimeInternetSecurityTypes.Tls,
            StringComparison.Ordinal);

    private static bool IsRealitySecurity(string securityType)
        => string.Equals(
            RuntimeInternetSecurityTypes.Normalize(securityType),
            RuntimeInternetSecurityTypes.Reality,
            StringComparison.Ordinal);

    private static bool UsesTlsLikeSecurity(string securityType)
        => IsTlsSecurity(securityType) || IsRealitySecurity(securityType);

    private static bool IsTcpTransport(string transportProtocol)
        => string.Equals(
            RuntimeInternetTransportProtocols.Normalize(transportProtocol),
            RuntimeInternetTransportProtocols.Tcp,
            StringComparison.Ordinal);

    private static bool IsMkcpTransport(string transportProtocol)
        => string.Equals(
            RuntimeInternetTransportProtocols.Normalize(transportProtocol),
            RuntimeInternetTransportProtocols.Mkcp,
            StringComparison.Ordinal);

    private static bool IsWsTransport(string transportProtocol)
        => string.Equals(
            RuntimeInternetTransportProtocols.Normalize(transportProtocol),
            RuntimeInternetTransportProtocols.Ws,
            StringComparison.Ordinal);

    private static bool IsHttpUpgradeTransport(string transportProtocol)
        => string.Equals(
            RuntimeInternetTransportProtocols.Normalize(transportProtocol),
            RuntimeInternetTransportProtocols.HttpUpgrade,
            StringComparison.Ordinal);

    private static bool IsGrpcTransport(string transportProtocol)
        => string.Equals(
            RuntimeInternetTransportProtocols.Normalize(transportProtocol),
            RuntimeInternetTransportProtocols.Grpc,
            StringComparison.Ordinal);

    private static bool IsSplitHttpTransport(string transportProtocol)
        => string.Equals(
            RuntimeInternetTransportProtocols.Normalize(transportProtocol),
            RuntimeInternetTransportProtocols.SplitHttp,
            StringComparison.Ordinal);

    private sealed record NormalizedInbound
    {
        public string Tag { get; init; } = string.Empty;

        public string Transport { get; init; } = InboundTransports.Tls;

        public string TransportProtocol { get; init; } = RuntimeInternetTransportProtocols.Tcp;

        public string SecurityType { get; init; } = RuntimeInternetSecurityTypes.Tls;

        public required ListenerBinding Binding { get; init; }

        public int HandshakeTimeoutSeconds { get; init; } = 60;

        public bool AcceptProxyProtocol { get; init; }

        public string Host { get; init; } = string.Empty;

        public string Path { get; init; } = string.Empty;

        public int EarlyDataBytes { get; init; }

        public int HeartbeatPeriodSeconds { get; init; }

        public IReadOnlyList<string> ApplicationProtocols { get; init; } = Array.Empty<string>();

        public RuntimeQuicOptions QuicOptions { get; init; } = RuntimeQuicOptions.Empty;

        public RuntimeGrpcTransportOptions Grpc { get; init; } = RuntimeGrpcTransportOptions.Empty;

        public RuntimeSplitHttpInboundOptions SplitHttp { get; init; } = RuntimeSplitHttpInboundOptions.Empty;

        public bool ReceiveOriginalDestination { get; init; }

        public RuntimeSniffingOptions Sniffing { get; init; } = new();

        public IReadOnlyList<VmessUser> Users { get; init; } = Array.Empty<VmessUser>();
    }
}

using NodePanel.ControlPlane.Configuration;
using NodePanel.ControlPlane.Protocol;
using NodePanel.Core.Runtime;

namespace NodePanel.Service.Runtime;

public sealed class LocalProxyStateStore
{
    private readonly object _sync = new();
    private readonly Dictionary<string, LocalProxyRuntimeState> _states = new(StringComparer.Ordinal);

    public void ReportListenerStarted(string protocol, LocalProxyListenerDefinition listener, int revision)
    {
        ArgumentNullException.ThrowIfNull(listener);

        var normalizedProtocol = LocalInboundProtocols.Normalize(protocol);
        var now = DateTimeOffset.UtcNow;
        var key = BuildKey(normalizedProtocol, listener.Tag, listener.Binding.ListenAddress, listener.Binding.Port);

        lock (_sync)
        {
            _states.TryGetValue(key, out var current);
            _states[key] = new LocalProxyRuntimeState
            {
                Revision = Math.Max(0, revision),
                Protocol = normalizedProtocol,
                Tag = listener.Tag ?? string.Empty,
                ListenAddress = listener.Binding.ListenAddress ?? string.Empty,
                Port = listener.Binding.Port,
                Listening = true,
                LastStartedAt = now,
                LastError = string.Empty,
                LastUpdatedAt = now,
                LastKnownStartedAt = now
            };
        }
    }

    public void ReportHostFailure(
        string protocol,
        IReadOnlyList<LocalProxyListenerDefinition> listeners,
        int revision,
        string? error)
    {
        ArgumentNullException.ThrowIfNull(listeners);

        if (listeners.Count == 0)
        {
            return;
        }

        var normalizedProtocol = LocalInboundProtocols.Normalize(protocol);
        var message = string.IsNullOrWhiteSpace(error) ? "Listener failed to start." : error.Trim();
        var now = DateTimeOffset.UtcNow;

        lock (_sync)
        {
            foreach (var listener in listeners)
            {
                var key = BuildKey(normalizedProtocol, listener.Tag, listener.Binding.ListenAddress, listener.Binding.Port);
                _states.TryGetValue(key, out var current);
                _states[key] = new LocalProxyRuntimeState
                {
                    Revision = Math.Max(0, revision),
                    Protocol = normalizedProtocol,
                    Tag = listener.Tag ?? string.Empty,
                    ListenAddress = listener.Binding.ListenAddress ?? string.Empty,
                    Port = listener.Binding.Port,
                    Listening = false,
                    LastStartedAt = current?.LastStartedAt,
                    LastError = message,
                    LastUpdatedAt = now,
                    LastKnownStartedAt = current?.LastKnownStartedAt
                };
            }
        }
    }

    public IReadOnlyList<NodeLocalProxyStatusPayload> CreateSnapshot(
        IReadOnlyList<LocalInboundConfig> localInbounds,
        int revision)
    {
        ArgumentNullException.ThrowIfNull(localInbounds);

        lock (_sync)
        {
            return localInbounds
                .Where(static inbound => inbound.Enabled)
                .Select(inbound =>
                {
                    var protocol = LocalInboundProtocols.Normalize(inbound.Protocol);
                    var listenAddress = inbound.ListenAddress ?? string.Empty;
                    var key = BuildKey(protocol, inbound.Tag, listenAddress, inbound.Port);

                    if (_states.TryGetValue(key, out var state) && state.Revision == Math.Max(0, revision))
                    {
                        return new NodeLocalProxyStatusPayload
                        {
                            Tag = inbound.Tag ?? string.Empty,
                            Protocol = protocol,
                            ListenAddress = listenAddress,
                            Port = inbound.Port,
                            Listening = state.Listening,
                            LastStartedAt = state.LastKnownStartedAt,
                            Error = string.IsNullOrWhiteSpace(state.LastError) ? null : state.LastError
                        };
                    }

                    return new NodeLocalProxyStatusPayload
                    {
                        Tag = inbound.Tag ?? string.Empty,
                        Protocol = protocol,
                        ListenAddress = listenAddress,
                        Port = inbound.Port,
                        Listening = false
                    };
                })
                .OrderBy(static item => item.Protocol, StringComparer.Ordinal)
                .ThenBy(static item => item.Tag, StringComparer.Ordinal)
                .ToArray();
        }
    }

    private static string BuildKey(string protocol, string? tag, string? listenAddress, int port)
        => string.Concat(
            protocol.Trim(),
            "\u0000",
            tag?.Trim() ?? string.Empty,
            "\u0000",
            listenAddress?.Trim() ?? string.Empty,
            "\u0000",
            port.ToString(System.Globalization.CultureInfo.InvariantCulture));

    private sealed record LocalProxyRuntimeState
    {
        public int Revision { get; init; }

        public string Protocol { get; init; } = string.Empty;

        public string Tag { get; init; } = string.Empty;

        public string ListenAddress { get; init; } = string.Empty;

        public int Port { get; init; }

        public bool Listening { get; init; }

        public DateTimeOffset? LastStartedAt { get; init; }

        public DateTimeOffset? LastKnownStartedAt { get; init; }

        public string LastError { get; init; } = string.Empty;

        public DateTimeOffset LastUpdatedAt { get; init; }
    }
}

namespace NodePanel.Core.Runtime;

public sealed class DefaultOutboundManager : IOutboundManager, IRuntimeManagedOutboundManager
{
    private readonly Dictionary<string, IOutboundHandler> _handlersByProtocol = new(StringComparer.OrdinalIgnoreCase);
    private readonly Dictionary<string, IOutboundHandler> _handlersByTag = new(StringComparer.OrdinalIgnoreCase);
    private readonly IOutboundRuntimePlanProvider _planProvider;
    private readonly object _sync = new();
    private bool _running;
    private int _disposed;

    public DefaultOutboundManager(IOutboundRuntimePlanProvider planProvider)
    {
        _planProvider = planProvider ?? throw new ArgumentNullException(nameof(planProvider));
    }

    public DefaultOutboundManager(
        IEnumerable<IOutboundHandler> handlers,
        IOutboundRuntimePlanProvider planProvider)
        : this(planProvider)
    {
        ArgumentNullException.ThrowIfNull(handlers);

        foreach (var handler in handlers)
        {
            AddHandler(handler);
        }

        var plan = _planProvider.GetCurrentOutboundPlan();
        foreach (var outbound in plan.Outbounds)
        {
            if (_handlersByProtocol.TryGetValue(OutboundProtocols.Normalize(outbound.Protocol), out var handler))
            {
                AddHandler(outbound.Tag, handler);
            }
        }
    }

    public void AddHandler(IOutboundHandler handler)
    {
        ArgumentNullException.ThrowIfNull(handler);
        ArgumentException.ThrowIfNullOrWhiteSpace(handler.Protocol);

        var protocol = OutboundProtocols.Normalize(handler.Protocol);
        var shouldStart = false;
        lock (_sync)
        {
            ThrowIfDisposed();
            var alreadyRegistered = IsHandlerRegisteredLocked(handler);

            if (!_handlersByProtocol.TryAdd(protocol, handler))
            {
                throw new InvalidOperationException($"Outbound handler '{protocol}' is already registered.");
            }

            shouldStart = _running && !alreadyRegistered;
        }

        if (shouldStart)
        {
            StartHandler(handler);
        }
    }

    internal void AddHandler(string tag, IOutboundHandler handler)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(tag);
        ArgumentNullException.ThrowIfNull(handler);

        var normalizedTag = tag.Trim();
        var shouldStart = false;
        lock (_sync)
        {
            ThrowIfDisposed();
            var alreadyRegistered = IsHandlerRegisteredLocked(handler);

            if (!_handlersByTag.TryAdd(normalizedTag, handler))
            {
                throw new InvalidOperationException($"Outbound handler '{normalizedTag}' is already registered.");
            }

            shouldStart = _running && !alreadyRegistered;
        }

        if (shouldStart)
        {
            StartHandler(handler);
        }
    }

    public bool RemoveHandler(string protocol)
    {
        if (string.IsNullOrWhiteSpace(protocol))
        {
            return false;
        }

        var key = protocol.Trim();
        lock (_sync)
        {
            if (_handlersByTag.Remove(key))
            {
                return true;
            }

            var normalizedProtocol = OutboundProtocols.Normalize(key);
            var removed = false;
            if (_handlersByProtocol.Remove(normalizedProtocol, out var removedHandler))
            {
                removed = true;
                foreach (var tag in _handlersByTag
                             .Where(entry => ReferenceEquals(entry.Value, removedHandler))
                             .Select(entry => entry.Key)
                             .ToArray())
                {
                    _handlersByTag.Remove(tag);
                }
            }

            foreach (var tag in _handlersByTag
                         .Where(entry => string.Equals(
                             OutboundProtocols.Normalize(entry.Value.Protocol),
                             normalizedProtocol,
                             StringComparison.Ordinal))
                         .Select(entry => entry.Key)
                         .ToArray())
            {
                _handlersByTag.Remove(tag);
                removed = true;
            }

            return removed;
        }
    }

    public IOutboundHandler? GetHandler(string tag)
    {
        if (string.IsNullOrWhiteSpace(tag))
        {
            return null;
        }

        var normalizedTag = tag.Trim();

        lock (_sync)
        {
            if (_handlersByTag.TryGetValue(normalizedTag, out var handler))
            {
                return handler;
            }
        }

        var plan = _planProvider.GetCurrentOutboundPlan();
        if (!plan.TryGetOutbound(normalizedTag, out var outbound))
        {
            return null;
        }

        lock (_sync)
        {
            _handlersByProtocol.TryGetValue(OutboundProtocols.Normalize(outbound.Protocol), out var handler);
            return handler;
        }
    }

    public IOutboundHandler GetDefaultHandler()
    {
        var plan = _planProvider.GetCurrentOutboundPlan();
        lock (_sync)
        {
            if (_handlersByProtocol.Count == 0 &&
                _handlersByTag.Count == 0)
            {
                throw new InvalidOperationException("At least one outbound handler must be registered.");
            }

            var outbound = plan.GetDefaultOutbound();
            if (outbound is not null)
            {
                if (_handlersByTag.TryGetValue(outbound.Tag, out var taggedHandler))
                {
                    return taggedHandler;
                }

                if (_handlersByProtocol.TryGetValue(OutboundProtocols.Normalize(outbound.Protocol), out var protocolHandler))
                {
                    return protocolHandler;
                }
            }

            if (_handlersByProtocol.TryGetValue(OutboundProtocols.Normalize(OutboundProtocols.Freedom), out var freedomHandler))
            {
                return freedomHandler;
            }

            var taggedFreedomHandler = _handlersByTag.Values.FirstOrDefault(handler =>
                string.Equals(
                    OutboundProtocols.Normalize(handler.Protocol),
                    OutboundProtocols.Normalize(OutboundProtocols.Freedom),
                    StringComparison.Ordinal));
            if (taggedFreedomHandler is not null)
            {
                return taggedFreedomHandler;
            }

            return GetDistinctHandlersLocked().First();
        }
    }

    public IReadOnlyList<IOutboundHandler> ListHandlers()
    {
        lock (_sync)
        {
            return GetDistinctHandlersLocked();
        }
    }

    public void Start()
    {
        ThrowIfDisposed();

        IOutboundHandler[] handlers;
        lock (_sync)
        {
            if (_running)
            {
                return;
            }

            _running = true;
            handlers = GetDistinctHandlersLocked().ToArray();
        }

        foreach (var handler in handlers)
        {
            StartHandler(handler);
        }
    }

    public async ValueTask DisposeAsync()
    {
        if (Interlocked.Exchange(ref _disposed, 1) != 0)
        {
            return;
        }

        IOutboundHandler[] handlers;
        lock (_sync)
        {
            _running = false;
            handlers = GetDistinctHandlersLocked().ToArray();
        }

        foreach (var handler in handlers.OfType<IAsyncDisposable>())
        {
            await handler.DisposeAsync().ConfigureAwait(false);
        }
    }

    private bool IsHandlerRegisteredLocked(IOutboundHandler handler)
    {
        ArgumentNullException.ThrowIfNull(handler);

        return _handlersByProtocol.Values.Any(existing => ReferenceEquals(existing, handler)) ||
               _handlersByTag.Values.Any(existing => ReferenceEquals(existing, handler));
    }

    private IReadOnlyList<IOutboundHandler> GetDistinctHandlersLocked()
    {
        var seen = new HashSet<object>(System.Collections.Generic.ReferenceEqualityComparer.Instance);
        var handlers = new List<IOutboundHandler>(_handlersByProtocol.Count + _handlersByTag.Count);

        foreach (var handler in _handlersByTag.Values)
        {
            if (seen.Add(handler))
            {
                handlers.Add(handler);
            }
        }

        foreach (var handler in _handlersByProtocol.Values)
        {
            if (seen.Add(handler))
            {
                handlers.Add(handler);
            }
        }

        return handlers.ToArray();
    }

    private static void StartHandler(IOutboundHandler handler)
    {
        ArgumentNullException.ThrowIfNull(handler);

        if (handler is IRuntimeStartable startable)
        {
            startable.Start();
        }
    }

    private void ThrowIfDisposed()
    {
        if (Volatile.Read(ref _disposed) != 0)
        {
            throw new ObjectDisposedException(nameof(DefaultOutboundManager));
        }
    }
}

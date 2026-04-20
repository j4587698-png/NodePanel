using System.Collections.Concurrent;

namespace NodePanel.Core.Runtime;

internal sealed class Http2TunnelSessionPool : IAsyncDisposable
{
    private readonly ConcurrentDictionary<string, Http2TunnelSession> _sessions = new(StringComparer.Ordinal);
    private readonly ConcurrentDictionary<string, SemaphoreSlim> _gates = new(StringComparer.Ordinal);

    public async ValueTask<Stream?> TryOpenAsync(
        string cacheKey,
        IReadOnlyDictionary<string, string> connectHeaders,
        DispatchDestination destination,
        byte[] initialPayload,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(connectHeaders);
        ArgumentNullException.ThrowIfNull(initialPayload);

        if (string.IsNullOrWhiteSpace(cacheKey) ||
            !_sessions.TryGetValue(cacheKey, out var session) ||
            !session.CanOpenNewStream)
        {
            return null;
        }

        try
        {
            return await session
                .OpenConnectStreamAsync(connectHeaders, destination, initialPayload, cancellationToken)
                .ConfigureAwait(false);
        }
        catch (ObjectDisposedException)
        {
            _sessions.TryRemove(cacheKey, out _);
            return null;
        }
        catch (InvalidOperationException) when (session.CanReuseConnection)
        {
            return null;
        }
        catch (InvalidOperationException)
        {
            _sessions.TryRemove(cacheKey, out _);
            return null;
        }
        catch
        {
            _sessions.TryRemove(cacheKey, out _);
            throw;
        }
    }

    public async ValueTask<Stream> AttachOrOpenAsync(
        string cacheKey,
        Stream transportStream,
        IReadOnlyDictionary<string, string> connectHeaders,
        DispatchDestination destination,
        byte[] initialPayload,
        CancellationToken cancellationToken)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(cacheKey);
        ArgumentNullException.ThrowIfNull(transportStream);
        ArgumentNullException.ThrowIfNull(connectHeaders);
        ArgumentNullException.ThrowIfNull(initialPayload);

        var gate = _gates.GetOrAdd(cacheKey, static _ => new SemaphoreSlim(1, 1));
        await gate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            if (_sessions.TryGetValue(cacheKey, out var existing) &&
                existing.CanOpenNewStream)
            {
                try
                {
                    var reused = await existing
                        .OpenConnectStreamAsync(connectHeaders, destination, initialPayload, cancellationToken)
                        .ConfigureAwait(false);
                    await transportStream.DisposeAsync().ConfigureAwait(false);
                    return reused;
                }
                catch (ObjectDisposedException)
                {
                    _sessions.TryRemove(cacheKey, out _);
                }
                catch (InvalidOperationException) when (existing.CanReuseConnection)
                {
                }
                catch (InvalidOperationException)
                {
                    _sessions.TryRemove(cacheKey, out _);
                }
                catch
                {
                    _sessions.TryRemove(cacheKey, out _);
                    await transportStream.DisposeAsync().ConfigureAwait(false);
                    throw;
                }
            }

            var session = await Http2TunnelSession
                .CreateAsync(
                    transportStream,
                    cancellationToken,
                    terminatedCallback: closed => RemoveIfSame(cacheKey, closed))
                .ConfigureAwait(false);

            _sessions[cacheKey] = session;
            return await session
                .OpenConnectStreamAsync(connectHeaders, destination, initialPayload, cancellationToken)
                .ConfigureAwait(false);
        }
        finally
        {
            gate.Release();
        }
    }

    public async ValueTask DisposeAsync()
    {
        foreach (var session in _sessions.Values)
        {
            try
            {
                await session.DisposeAsync().ConfigureAwait(false);
            }
            catch
            {
            }
        }

        foreach (var gate in _gates.Values)
        {
            gate.Dispose();
        }

        _sessions.Clear();
        _gates.Clear();
    }

    private void RemoveIfSame(string cacheKey, Http2TunnelSession session)
    {
        if (_sessions.TryGetValue(cacheKey, out var current) &&
            ReferenceEquals(current, session))
        {
            _sessions.TryRemove(cacheKey, out _);
        }
    }
}

using System.Collections.Concurrent;
using System.Net;
using System.Net.Security;
using System.Security.Authentication;
using System.Security.Cryptography.X509Certificates;
using System.Text;

namespace NodePanel.Core.Runtime;

internal interface IRuntimeGrpcClientDialOptions : IRuntimeInternetOptions, IRuntimeRealityHandshakeProviderAccessor
{
    DispatchContext DialContext { get; }

    EndPoint? SourceEndPoint { get; }

    EndPoint? LocalEndPoint { get; }

    string Via { get; }

    string ViaCidr { get; }

    int ServerPort { get; }

    int WebSocketEarlyDataBytes { get; }

    int ConnectTimeoutSeconds { get; }

    int HandshakeTimeoutSeconds { get; }

    Func<CancellationToken, ValueTask<Stream>>? TransportStreamFactory { get; }

    Func<CancellationToken, ValueTask<Stream>>? SplitHttpDownloadTransportStreamFactory { get; }
}

internal sealed class GrpcTunnelSessionPool : IAsyncDisposable
{
    private const double BackgroundReconnectJitter = 0.2;
    private readonly ConcurrentDictionary<string, GrpcTunnelSessionEntry> _sessions = new(StringComparer.Ordinal);
    private readonly ConcurrentDictionary<string, GrpcClientState> _clients = new(StringComparer.Ordinal);
    private readonly CancellationTokenSource _lifetimeCts = new();
    private int _disposed;

    public async ValueTask<RuntimeInternetConnectionContext> OpenOrCreateAsync(
        string cacheKey,
        RuntimeInternetStack stack,
        IRuntimeInternetOptions options,
        Func<CancellationToken, ValueTask<RuntimeInternetConnectionContext>> transportContextFactory,
        CancellationToken cancellationToken)
    {
        ObjectDisposedException.ThrowIf(Volatile.Read(ref _disposed) != 0, this);
        ArgumentException.ThrowIfNullOrWhiteSpace(cacheKey);
        ArgumentNullException.ThrowIfNull(options);
        ArgumentNullException.ThrowIfNull(transportContextFactory);

        var sessionOptions = Http2GrpcTunnel.CreateSessionOptions(options);
        var client = _clients.GetOrAdd(cacheKey, static _ => new GrpcClientState());
        client.Configure(transportContextFactory, sessionOptions);

        while (true)
        {
            var reused = await TryOpenExistingAsync(cacheKey, stack, options, cancellationToken).ConfigureAwait(false);
            if (reused is not null)
            {
                client.MarkReady();
                return reused;
            }

            var observedVersion = client.StateVersion;
            if (client.IsReconnectLoopActive)
            {
                await client.WaitForStateChangeAsync(observedVersion, cancellationToken).ConfigureAwait(false);
                continue;
            }

            var gate = client.Gate;
            await gate.WaitAsync(cancellationToken).ConfigureAwait(false);
            try
            {
                reused = await TryOpenExistingAsync(cacheKey, stack, options, cancellationToken).ConfigureAwait(false);
                if (reused is not null)
                {
                    client.MarkReady();
                    return reused;
                }

                if (client.IsReconnectLoopActive)
                {
                    continue;
                }

                var createdEntry = await CreateSessionEntryAsync(cacheKey, client, cancellationToken).ConfigureAwait(false);
                if (createdEntry is null)
                {
                    continue;
                }

                return await OpenCachedContextAsync(createdEntry, stack, options, cancellationToken)
                    .ConfigureAwait(false);
            }
            finally
            {
                gate.Release();
            }
        }
    }

    private async ValueTask<RuntimeInternetConnectionContext?> TryOpenExistingAsync(
        string cacheKey,
        RuntimeInternetStack stack,
        IRuntimeInternetOptions options,
        CancellationToken cancellationToken)
    {
        if (!_sessions.TryGetValue(cacheKey, out var entry) ||
            !entry.Session.CanOpenNewStream)
        {
            return null;
        }

        try
        {
            return await OpenCachedContextAsync(entry, stack, options, cancellationToken).ConfigureAwait(false);
        }
        catch (ObjectDisposedException)
        {
            RemoveIfSame(cacheKey, entry.Session);
            return null;
        }
        catch (InvalidOperationException) when (entry.Session.CanReuseConnection)
        {
            return null;
        }
        catch (InvalidOperationException)
        {
            RemoveIfSame(cacheKey, entry.Session);
            return null;
        }
        catch
        {
            RemoveIfSame(cacheKey, entry.Session);
            throw;
        }
    }

    public async ValueTask DisposeAsync()
    {
        if (Interlocked.Exchange(ref _disposed, 1) != 0)
        {
            return;
        }

        _lifetimeCts.Cancel();

        foreach (var entry in _sessions.Values)
        {
            try
            {
                await entry.DisposeAsync().ConfigureAwait(false);
            }
            catch
            {
            }
        }

        foreach (var client in _clients.Values)
        {
            client.Dispose();
        }

        _sessions.Clear();
        _clients.Clear();
        _lifetimeCts.Dispose();
    }

    private static async ValueTask<RuntimeInternetConnectionContext> OpenCachedContextAsync(
        GrpcTunnelSessionEntry entry,
        RuntimeInternetStack stack,
        IRuntimeInternetOptions options,
        CancellationToken cancellationToken)
    {
        var applicationStream = await Http2GrpcTunnel
            .OpenAsync(
                entry.Session,
                stack,
                options,
                cancellationToken,
                disposeSessionOnClose: false)
            .ConfigureAwait(false);

        var context = new RuntimeInternetConnectionContext(applicationStream);
        context.SetTransportStream(
            applicationStream,
            entry.SslStream,
            securityState: CloneSecurityState(entry.SecurityState));
        return context;
    }

    private void RemoveIfSame(string cacheKey, Http2TunnelSession session)
    {
        if (_sessions.TryGetValue(cacheKey, out var current) &&
            ReferenceEquals(current.Session, session))
        {
            _sessions.TryRemove(cacheKey, out _);
            current.DisposeMetadata();

            if (_clients.TryGetValue(cacheKey, out var client))
            {
                client.MarkSessionUnavailable();
                ScheduleWarmReconnect(cacheKey, client);
            }
        }
    }

    private void ScheduleWarmReconnect(string cacheKey, GrpcClientState client)
    {
        if (Volatile.Read(ref _disposed) != 0 ||
            _lifetimeCts.IsCancellationRequested ||
            !client.TryBeginWarmReconnect())
        {
            return;
        }

        _ = WarmReconnectAsync(cacheKey, client);
    }

    private async Task WarmReconnectAsync(string cacheKey, GrpcClientState client)
    {
        var retryDelay = RuntimeGrpcClientConnector.InitialConnectRetryDelay;
        try
        {
            while (!_lifetimeCts.IsCancellationRequested &&
                   Volatile.Read(ref _disposed) == 0)
            {
                await client.Gate.WaitAsync(_lifetimeCts.Token).ConfigureAwait(false);
                try
                {
                    if (Volatile.Read(ref _disposed) != 0 ||
                        _lifetimeCts.IsCancellationRequested)
                    {
                        return;
                    }

                    if (HasReusableSession(cacheKey))
                    {
                        client.MarkReady();
                        return;
                    }

                    var createdEntry = await CreateSessionEntryAsync(cacheKey, client, _lifetimeCts.Token)
                        .ConfigureAwait(false);
                    if (createdEntry is not null || HasReusableSession(cacheKey))
                    {
                        client.MarkReady();
                        return;
                    }
                }
                catch (OperationCanceledException) when (_lifetimeCts.IsCancellationRequested)
                {
                    return;
                }
                catch (Exception ex) when (RuntimeGrpcClientConnector.ShouldRetryGrpcTransportOpen(ex))
                {
                    client.MarkTransientFailure(ex);
                }
                catch (Exception ex)
                {
                    client.MarkTransientFailure(ex);
                    return;
                }
                finally
                {
                    client.Gate.Release();
                }

                var delay = GetJitteredBackgroundReconnectDelay(retryDelay);
                await Task.Delay(delay, _lifetimeCts.Token).ConfigureAwait(false);
                retryDelay = RuntimeGrpcClientConnector.GetNextConnectRetryDelay(retryDelay);
            }
        }
        finally
        {
            if (Volatile.Read(ref _disposed) != 0 || _lifetimeCts.IsCancellationRequested)
            {
                client.MarkShutdown();
            }

            client.EndWarmReconnect();
        }
    }

    private bool HasReusableSession(string cacheKey)
        => _sessions.TryGetValue(cacheKey, out var existing) &&
           existing.Session.CanOpenNewStream;

    private async ValueTask<GrpcTunnelSessionEntry?> CreateSessionEntryAsync(
        string cacheKey,
        GrpcClientState client,
        CancellationToken cancellationToken)
    {
        RuntimeInternetConnectionContext? transportContext = null;
        GrpcTunnelSessionEntry? createdEntry = null;
        var transportContextTransferred = false;
        try
        {
            if (HasReusableSession(cacheKey))
            {
                client.MarkReady();
                return null;
            }

            var transportContextFactory = client.TransportContextFactory;
            if (transportContextFactory is null)
            {
                client.MarkSessionUnavailable();
                return null;
            }

            client.MarkConnecting();
            transportContext = await transportContextFactory(cancellationToken).ConfigureAwait(false);
            if (HasReusableSession(cacheKey))
            {
                await DisposeTransportContextAsync(transportContext).ConfigureAwait(false);
                transportContext = null;
                client.MarkReady();
                return null;
            }

            var session = await Http2TunnelSession
                .CreateAsync(
                    transportContext.TransportStream,
                    cancellationToken,
                    client.SessionOptions,
                    terminatedCallback: closed => RemoveIfSame(cacheKey, closed))
                .ConfigureAwait(false);

            createdEntry = new GrpcTunnelSessionEntry(
                session,
                transportContext.SslStream,
                transportContext.SecurityState);
            _sessions[cacheKey] = createdEntry;
            transportContextTransferred = true;
            client.MarkReady();
            return createdEntry;
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            throw;
        }
        catch (Exception ex)
        {
            client.MarkTransientFailure(ex);
            throw;
        }
        finally
        {
            if (!transportContextTransferred && transportContext is not null)
            {
                await DisposeTransportContextAsync(transportContext).ConfigureAwait(false);
            }
        }
    }

    private static TimeSpan GetJitteredBackgroundReconnectDelay(TimeSpan delay)
    {
        var jitterFactor = 1 + ((Random.Shared.NextDouble() * 2) - 1) * BackgroundReconnectJitter;
        var jitteredMilliseconds = Math.Max(0, delay.TotalMilliseconds * jitterFactor);
        return TimeSpan.FromMilliseconds(jitteredMilliseconds);
    }

    private static async ValueTask DisposeTransportContextAsync(RuntimeInternetConnectionContext transportContext)
    {
        try
        {
            await transportContext.TransportStream.DisposeAsync().ConfigureAwait(false);
        }
        catch
        {
        }

        transportContext.SecurityState.RemoteCertificate?.Dispose();
    }

    private static RuntimeInternetSecurityState CloneSecurityState(RuntimeInternetSecurityState securityState)
        => securityState with
        {
            RemoteCertificate = CloneCertificate(securityState.RemoteCertificate)
        };

    private static X509Certificate2? CloneCertificate(X509Certificate2? certificate)
        => certificate is null ? null : new X509Certificate2(certificate);

    private sealed class GrpcTunnelSessionEntry : IAsyncDisposable
    {
        private int _metadataDisposed;

        public GrpcTunnelSessionEntry(
            Http2TunnelSession session,
            SslStream? sslStream,
            RuntimeInternetSecurityState securityState)
        {
            Session = session ?? throw new ArgumentNullException(nameof(session));
            SslStream = sslStream;
            SecurityState = securityState ?? throw new ArgumentNullException(nameof(securityState));
        }

        public Http2TunnelSession Session { get; }

        public SslStream? SslStream { get; }

        public RuntimeInternetSecurityState SecurityState { get; }

        public async ValueTask DisposeAsync()
        {
            try
            {
                await Session.DisposeAsync().ConfigureAwait(false);
            }
            finally
            {
                DisposeMetadata();
            }
        }

        public void DisposeMetadata()
        {
            if (Interlocked.Exchange(ref _metadataDisposed, 1) != 0)
            {
                return;
            }

            SecurityState.RemoteCertificate?.Dispose();
        }
    }

    private sealed class GrpcClientState : IDisposable
    {
        private readonly object _stateLock = new();
        private TaskCompletionSource<long> _stateChangedTcs = new(TaskCreationOptions.RunContinuationsAsynchronously);
        private int _warmReconnectActive;
        private long _stateVersion;

        public SemaphoreSlim Gate { get; } = new(1, 1);

        public Func<CancellationToken, ValueTask<RuntimeInternetConnectionContext>>? TransportContextFactory { get; private set; }

        public Http2TunnelSessionOptions SessionOptions { get; private set; } = Http2TunnelSessionOptions.Default;

        public long StateVersion
        {
            get
            {
                lock (_stateLock)
                {
                    return _stateVersion;
                }
            }
        }

        public bool IsReconnectLoopActive => Volatile.Read(ref _warmReconnectActive) != 0;

        public void Configure(
            Func<CancellationToken, ValueTask<RuntimeInternetConnectionContext>> transportContextFactory,
            Http2TunnelSessionOptions sessionOptions)
        {
            TransportContextFactory = transportContextFactory ?? throw new ArgumentNullException(nameof(transportContextFactory));
            SessionOptions = sessionOptions ?? throw new ArgumentNullException(nameof(sessionOptions));
        }

        public bool TryBeginWarmReconnect()
            => Interlocked.CompareExchange(ref _warmReconnectActive, 1, 0) == 0;

        public void EndWarmReconnect()
            => Volatile.Write(ref _warmReconnectActive, 0);

        public void MarkSessionUnavailable()
            => AdvanceState();

        public void MarkConnecting()
            => AdvanceState();

        public void MarkReady()
            => AdvanceState();

        public void MarkTransientFailure(Exception exception)
        {
            ArgumentNullException.ThrowIfNull(exception);
            AdvanceState();
        }

        public void MarkShutdown()
            => AdvanceState();

        public Task WaitForStateChangeAsync(long observedVersion, CancellationToken cancellationToken)
        {
            Task waitTask;
            lock (_stateLock)
            {
                if (_stateVersion != observedVersion)
                {
                    return Task.CompletedTask;
                }

                waitTask = _stateChangedTcs.Task;
            }

            return waitTask.WaitAsync(cancellationToken);
        }

        private void AdvanceState()
        {
            TaskCompletionSource<long> toComplete;
            long nextVersion;
            lock (_stateLock)
            {
                nextVersion = ++_stateVersion;
                toComplete = _stateChangedTcs;
                _stateChangedTcs = new TaskCompletionSource<long>(TaskCreationOptions.RunContinuationsAsynchronously);
            }

            toComplete.TrySetResult(nextVersion);
        }

        public void Dispose()
            => Gate.Dispose();
    }
}

internal static class RuntimeGrpcClientConnector
{
    private const int ConnectAttempts = 5;
    private const int GrpcTransportOpenAttempts = 2;
    private const double ConnectRetryMultiplier = 1.5;
    internal static readonly TimeSpan InitialConnectRetryDelay = TimeSpan.FromMilliseconds(500);
    private static readonly TimeSpan MaxConnectRetryDelay = TimeSpan.FromSeconds(19);

    public static async ValueTask<RuntimeInternetConnectionContext> OpenAsync<TOptions>(
        TOptions options,
        RuntimeInternetStack internetStack,
        RuntimeInternetProfile internetProfile,
        IDnsResolver dnsResolver,
        byte[]? transportInitializationData,
        CancellationToken cancellationToken)
        where TOptions : class, IRuntimeGrpcClientDialOptions
    {
        ArgumentNullException.ThrowIfNull(options);
        ArgumentNullException.ThrowIfNull(internetProfile);
        ArgumentNullException.ThrowIfNull(dnsResolver);

        if (!string.Equals(internetStack.TransportProtocol, RuntimeInternetTransportProtocols.Grpc, StringComparison.Ordinal))
        {
            if (string.Equals(internetStack.TransportProtocol, RuntimeInternetTransportProtocols.SplitHttp, StringComparison.Ordinal))
            {
                return await RuntimeSplitHttpClientConnector
                    .OpenAsync(
                        options,
                        internetStack,
                        internetProfile,
                        dnsResolver,
                        transportInitializationData,
                        cancellationToken)
                    .ConfigureAwait(false);
            }

            return await OpenNonGrpcAsync(
                    options,
                    internetStack,
                    internetProfile,
                    dnsResolver,
                    transportInitializationData,
                    cancellationToken)
                .ConfigureAwait(false);
        }

        var cacheKey = TryCreateSessionCacheKey(options, internetStack, transportInitializationData);
        return await OpenGrpcAsync(
                options,
                internetStack,
                internetProfile,
                dnsResolver,
                transportInitializationData,
                cacheKey,
                cancellationToken)
            .ConfigureAwait(false);
    }

    private static async ValueTask<RuntimeInternetConnectionContext> OpenGrpcAsync<TOptions>(
        TOptions options,
        RuntimeInternetStack internetStack,
        RuntimeInternetProfile internetProfile,
        IDnsResolver dnsResolver,
        byte[]? transportInitializationData,
        string cacheKey,
        CancellationToken cancellationToken)
        where TOptions : class, IRuntimeGrpcClientDialOptions
    {
        var openAttempt = 0;
        while (true)
        {
            cancellationToken.ThrowIfCancellationRequested();

            try
            {
                if (cacheKey.Length > 0)
                {
                    return await internetProfile.GrpcTunnelSessionPool
                        .OpenOrCreateAsync(
                            cacheKey,
                            internetStack,
                            options,
                            ct => OpenSecuredTransportContextWithRetryAsync(
                                options,
                                internetStack,
                                internetProfile,
                                dnsResolver,
                                ct),
                            cancellationToken)
                        .ConfigureAwait(false);
                }

                return await OpenFreshGrpcTransportAsync(
                        options,
                        internetStack,
                        internetProfile,
                        dnsResolver,
                        transportInitializationData,
                        cancellationToken)
                    .ConfigureAwait(false);
            }
            catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
            {
                throw;
            }
            catch (Exception ex) when (openAttempt < GrpcTransportOpenAttempts - 1 && ShouldRetryGrpcTransportOpen(ex))
            {
                openAttempt++;
            }
        }
    }

    private static async ValueTask<RuntimeInternetConnectionContext> OpenFreshGrpcTransportAsync<TOptions>(
        TOptions options,
        RuntimeInternetStack internetStack,
        RuntimeInternetProfile internetProfile,
        IDnsResolver dnsResolver,
        byte[]? transportInitializationData,
        CancellationToken cancellationToken)
        where TOptions : class, IRuntimeGrpcClientDialOptions
    {
        var securedContext = await OpenSecuredTransportContextWithRetryAsync(
                options,
                internetStack,
                internetProfile,
                dnsResolver,
                cancellationToken)
            .ConfigureAwait(false);

        using var handshakeCts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        handshakeCts.CancelAfter(TimeSpan.FromSeconds(options.HandshakeTimeoutSeconds));

        try
        {
            await internetProfile
                .ApplyTransportAsync(securedContext, internetStack, options, transportInitializationData, handshakeCts.Token)
                .ConfigureAwait(false);
            return securedContext;
        }
        catch
        {
            await DisposeTransportContextAsync(securedContext).ConfigureAwait(false);
            throw;
        }
    }

    private static async ValueTask<RuntimeInternetConnectionContext> OpenNonGrpcAsync<TOptions>(
        TOptions options,
        RuntimeInternetStack internetStack,
        RuntimeInternetProfile internetProfile,
        IDnsResolver dnsResolver,
        byte[]? transportInitializationData,
        CancellationToken cancellationToken)
        where TOptions : class, IRuntimeGrpcClientDialOptions
    {
        using var handshakeCts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        handshakeCts.CancelAfter(TimeSpan.FromSeconds(options.HandshakeTimeoutSeconds));

        var browserContext = await internetProfile
            .TryOpenWithoutBaseTransportAsync(
                internetStack,
                options,
                transportInitializationData,
                handshakeCts.Token)
            .ConfigureAwait(false);
        if (browserContext is not null)
        {
            return browserContext;
        }

        var delayedWebSocketContext = TryCreateDelayedWebSocketContext(
            options,
            internetStack,
            internetProfile,
            dnsResolver,
            transportInitializationData);
        if (delayedWebSocketContext is not null)
        {
            return delayedWebSocketContext;
        }

        Stream? baseStream = null;
        try
        {
            baseStream = string.Equals(
                    internetStack.TransportProtocol,
                    RuntimeInternetTransportProtocols.Mkcp,
                    StringComparison.Ordinal)
                ? await RuntimeKcpStreamFactory.OpenAsync(options, dnsResolver, cancellationToken).ConfigureAwait(false)
                : await OpenBaseTransportStreamAsync(options, dnsResolver, cancellationToken).ConfigureAwait(false);

            return await internetProfile
                .OpenAsync(baseStream, internetStack, options, transportInitializationData, handshakeCts.Token)
                .ConfigureAwait(false);
        }
        catch (Exception ex) when (RuntimeRealityProcessedInvalidConnectionException.ShouldPreserveTransport(ex))
        {
            throw;
        }
        catch
        {
            if (baseStream is not null)
            {
                await baseStream.DisposeAsync().ConfigureAwait(false);
            }

            throw;
        }
    }

    private static RuntimeInternetConnectionContext? TryCreateDelayedWebSocketContext<TOptions>(
        TOptions options,
        RuntimeInternetStack internetStack,
        RuntimeInternetProfile internetProfile,
        IDnsResolver dnsResolver,
        byte[]? transportInitializationData)
        where TOptions : class, IRuntimeGrpcClientDialOptions
    {
        if (!string.Equals(internetStack.TransportProtocol, RuntimeInternetTransportProtocols.Ws, StringComparison.Ordinal) ||
            options.WebSocketEarlyDataBytes <= 0 ||
            transportInitializationData is not null)
        {
            return null;
        }

        RuntimeInternetConnectionContext? delayedContext = null;
        var delayedStream = new RuntimeDelayedOpenStream(
            options.WebSocketEarlyDataBytes,
            async (candidateEarlyData, cancellationToken) =>
            {
                Stream? baseStream = null;
                try
                {
                    baseStream = await OpenBaseTransportStreamAsync(options, dnsResolver, cancellationToken).ConfigureAwait(false);

                    using var handshakeCts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
                    handshakeCts.CancelAfter(TimeSpan.FromSeconds(options.HandshakeTimeoutSeconds));

                    var openedContext = await internetProfile
                        .OpenAsync(
                            baseStream,
                            internetStack,
                            options,
                            candidateEarlyData ?? Array.Empty<byte>(),
                            handshakeCts.Token)
                        .ConfigureAwait(false);

                    delayedContext!.SetTransportStream(
                        openedContext.TransportStream,
                        openedContext.SslStream,
                        securityState: openedContext.SecurityState,
                        updateApplicationStream: false);
                    delayedContext.SetApplicationStream(delayedContext.ApplicationStream, openedContext.WebSocket);
                    return openedContext.ApplicationStream;
                }
                catch (Exception ex) when (RuntimeRealityProcessedInvalidConnectionException.ShouldPreserveTransport(ex))
                {
                    throw;
                }
                catch
                {
                    if (baseStream is not null)
                    {
                        await baseStream.DisposeAsync().ConfigureAwait(false);
                    }

                    throw;
                }
            });

        delayedContext = new RuntimeInternetConnectionContext(delayedStream);
        delayedContext.SetTransportStream(
            delayedStream,
            securityState: CreatePendingSecurityState(internetStack));
        delayedContext.SetApplicationStream(delayedStream);
        return delayedContext;
    }

    internal static async ValueTask<RuntimeInternetConnectionContext> OpenSecuredTransportContextWithRetryAsync<TOptions>(
        TOptions options,
        RuntimeInternetStack internetStack,
        RuntimeInternetProfile internetProfile,
        IDnsResolver dnsResolver,
        CancellationToken cancellationToken)
        where TOptions : class, IRuntimeGrpcClientDialOptions
    {
        Exception? lastError = null;
        var retryDelay = InitialConnectRetryDelay;
        var secureStack = RuntimeInternetStack.Create(
            internetStack.TransportProtocol,
            internetStack.SecurityType);

        for (var attempt = 0; attempt < ConnectAttempts; attempt++)
        {
            cancellationToken.ThrowIfCancellationRequested();

            Stream? baseStream = null;
            try
            {
                baseStream = await OpenBaseTransportStreamAsync(options, dnsResolver, cancellationToken).ConfigureAwait(false);

                using var handshakeCts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
                handshakeCts.CancelAfter(TimeSpan.FromSeconds(options.HandshakeTimeoutSeconds));
                return await internetProfile
                    .SecureAsync(baseStream, secureStack, options, handshakeCts.Token)
                    .ConfigureAwait(false);
            }
            catch (Exception ex) when (RuntimeRealityProcessedInvalidConnectionException.ShouldPreserveTransport(ex))
            {
                throw;
            }
            catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
            {
                if (baseStream is not null)
                {
                    await baseStream.DisposeAsync().ConfigureAwait(false);
                }

                throw;
            }
            catch (Exception ex) when (attempt < ConnectAttempts - 1 && ShouldRetrySecureTransportOpen(ex))
            {
                if (baseStream is not null)
                {
                    await baseStream.DisposeAsync().ConfigureAwait(false);
                }

                lastError = ex;
                await Task.Delay(retryDelay, cancellationToken).ConfigureAwait(false);
                retryDelay = GetNextConnectRetryDelay(retryDelay);
            }
            catch (Exception ex)
            {
                if (baseStream is not null)
                {
                    await baseStream.DisposeAsync().ConfigureAwait(false);
                }

                lastError = ex;
                break;
            }
        }

        throw new IOException("gRPC outbound failed to establish the underlying transport.", lastError);
    }

    internal static async ValueTask<Stream> OpenBaseTransportStreamAsync<TOptions>(
        TOptions options,
        IDnsResolver dnsResolver,
        CancellationToken cancellationToken)
        where TOptions : class, IRuntimeGrpcClientDialOptions
    {
        if (options.TransportStreamFactory is not null)
        {
            return await options.TransportStreamFactory(cancellationToken).ConfigureAwait(false);
        }

        var dialContext = OutboundClientDialContext.Resolve(
            options.DialContext,
            options.SourceEndPoint,
            options.LocalEndPoint);
        using var connectCts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        connectCts.CancelAfter(TimeSpan.FromSeconds(options.ConnectTimeoutSeconds));
        var endPoints = await OutboundSocketDialer.ResolveTcpEndPointsAsync(
            dialContext,
            options.ServerHost,
            options.ServerPort,
            System.Net.Sockets.AddressFamily.Unspecified,
            dnsResolver,
            connectCts.Token).ConfigureAwait(false);
        return await OutboundSocketDialer.OpenTcpStreamAsync(
            dialContext,
            options.Via,
            options.ViaCidr,
            endPoints,
            connectCts.Token).ConfigureAwait(false);
    }

    private static bool ShouldRetrySecureTransportOpen(Exception exception)
        => exception switch
        {
            ArgumentException => false,
            InvalidOperationException => false,
            NotSupportedException => false,
            _ => true
        };

    private static RuntimeInternetSecurityState CreatePendingSecurityState(RuntimeInternetStack internetStack)
        => RuntimeInternetSecurityTypes.IsSecure(internetStack.SecurityType)
            ? RuntimeInternetSecurityState.Create(internetStack.SecurityType, SslProtocols.None)
            : RuntimeInternetSecurityState.None;

    internal static bool ShouldRetryGrpcTransportOpen(Exception exception)
    {
        exception = UnwrapAggregateException(exception);
        return exception switch
        {
            IOException => true,
            ObjectDisposedException => true,
            InvalidOperationException invalidOperation => invalidOperation.Message.StartsWith(
                "HTTP/2 proxy session",
                StringComparison.Ordinal),
            ArgumentException => false,
            InvalidDataException => false,
            NotSupportedException => false,
            OperationCanceledException => false,
            _ => false
        };
    }

    internal static TimeSpan GetNextConnectRetryDelay(TimeSpan currentDelay)
    {
        var nextMilliseconds = Math.Min(
            currentDelay.TotalMilliseconds * ConnectRetryMultiplier,
            MaxConnectRetryDelay.TotalMilliseconds);
        return TimeSpan.FromMilliseconds(nextMilliseconds);
    }

    private static Exception UnwrapAggregateException(Exception exception)
    {
        while (exception is AggregateException { InnerExceptions.Count: 1 } aggregateException &&
               aggregateException.InnerException is not null)
        {
            exception = aggregateException.InnerException;
        }

        return exception;
    }

    internal static async ValueTask DisposeTransportContextAsync(RuntimeInternetConnectionContext transportContext)
    {
        try
        {
            await transportContext.TransportStream.DisposeAsync().ConfigureAwait(false);
        }
        catch
        {
        }

        transportContext.SecurityState.RemoteCertificate?.Dispose();
    }

    private static string TryCreateSessionCacheKey<TOptions>(
        TOptions options,
        RuntimeInternetStack internetStack,
        byte[]? transportInitializationData)
        where TOptions : class, IRuntimeGrpcClientDialOptions
    {
        if (!string.Equals(internetStack.TransportProtocol, RuntimeInternetTransportProtocols.Grpc, StringComparison.Ordinal) ||
            transportInitializationData is { Length: > 0 } ||
            options.TransportStreamFactory is not null ||
            options.CertificateValidationCallback is not null ||
            options.RealityHandshakeProvider is not null)
        {
            return string.Empty;
        }

        var viaIdentity = ResolveViaIdentity(options.Via, options.SourceEndPoint, options.LocalEndPoint);
        if (viaIdentity is null)
        {
            return string.Empty;
        }

        var builder = new StringBuilder(512);
        AppendKeyValue(builder, "transport", internetStack.TransportProtocol);
        AppendKeyValue(builder, "security", internetStack.SecurityType);
        AppendKeyValue(builder, "serverHost", options.ServerHost);
        AppendKeyValue(builder, "serverPort", options.ServerPort.ToString());
        AppendKeyValue(builder, "serverName", string.IsNullOrWhiteSpace(options.ServerName) ? options.ServerHost : options.ServerName);
        AppendKeyValue(builder, "fingerprint", options.Fingerprint);
        AppendKeyValue(builder, "skipCertificateValidation", options.SkipCertificateValidation ? "1" : "0");
        AppendKeyValue(builder, "enabledSslProtocols", ((int)options.EnabledSslProtocols).ToString());
        AppendKeyValue(builder, "via", viaIdentity);
        AppendKeyValue(builder, "viaCidr", options.ViaCidr);
        AppendKeyValue(builder, "grpcServiceName", options.GrpcServiceName);
        AppendKeyValue(builder, "grpcAuthority", options.GrpcAuthority);
        AppendKeyValue(builder, "grpcMultiMode", options.GrpcMultiMode ? "1" : "0");
        AppendKeyValue(builder, "grpcUserAgent", options.GrpcUserAgent);
        AppendKeyValue(builder, "grpcIdleTimeoutSeconds", options.GrpcIdleTimeoutSeconds.ToString());
        AppendKeyValue(builder, "grpcHealthCheckTimeoutSeconds", options.GrpcHealthCheckTimeoutSeconds.ToString());
        AppendKeyValue(builder, "grpcPermitWithoutStream", options.GrpcPermitWithoutStream ? "1" : "0");
        AppendKeyValue(builder, "grpcInitialWindowSize", options.GrpcInitialWindowSize.ToString());

        if (string.Equals(internetStack.SecurityType, RuntimeInternetSecurityTypes.Reality, StringComparison.Ordinal))
        {
            var normalizedReality = RuntimeRealityOptions.Normalize(options.RealityOptions, applyRealityDefaults: true);
            AppendKeyValue(builder, "realityShow", normalizedReality.Show ? "1" : "0");
            AppendKeyValue(builder, "realityMasterKeyLog", normalizedReality.MasterKeyLog);
            AppendKeyValue(builder, "realityFingerprint", normalizedReality.Fingerprint);
            AppendKeyValue(builder, "realityPublicKey", normalizedReality.PublicKey);
            AppendKeyValue(builder, "realityShortId", normalizedReality.ShortId);
            AppendKeyValue(builder, "realityMldsa65Verify", normalizedReality.Mldsa65Verify);
            AppendKeyValue(builder, "realitySpiderX", normalizedReality.SpiderX);
            AppendKeyValue(builder, "realitySpiderY", string.Join(",", normalizedReality.SpiderY));
        }

        return builder.ToString();
    }

    private static string? ResolveViaIdentity(
        string via,
        EndPoint? sourceEndPoint,
        EndPoint? localEndPoint)
    {
        if (string.IsNullOrWhiteSpace(via))
        {
            return string.Empty;
        }

        var normalized = via.Trim();
        if (string.Equals(normalized, "origin", StringComparison.OrdinalIgnoreCase))
        {
            return TryFormatEndPoint(localEndPoint);
        }

        if (string.Equals(normalized, "srcip", StringComparison.OrdinalIgnoreCase))
        {
            return TryFormatEndPoint(sourceEndPoint);
        }

        return normalized;
    }

    private static string? TryFormatEndPoint(EndPoint? endPoint)
        => endPoint switch
        {
            IPEndPoint ipEndPoint => $"{ipEndPoint.Address}|{ipEndPoint.Port}",
            DnsEndPoint dnsEndPoint => $"{dnsEndPoint.Host}|{dnsEndPoint.Port}",
            null => null,
            _ => null
        };

    private static void AppendKeyValue(StringBuilder builder, string key, string? value)
    {
        builder.Append(key);
        builder.Append('=');
        builder.Append(value?.Trim() ?? string.Empty);
        builder.Append('\n');
    }
}

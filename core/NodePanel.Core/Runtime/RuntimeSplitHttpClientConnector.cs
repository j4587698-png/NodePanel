#pragma warning disable CA1416
using System.Globalization;
using System.Net;
using System.Net.Security;
using System.Collections.Concurrent;
using System.Runtime.ExceptionServices;
using System.Security.Authentication;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Threading.Channels;

namespace NodePanel.Core.Runtime;

internal static class RuntimeSplitHttpClientConnector
{
    private const int DefaultScMaxEachPostBytes = 1_000_000;
    private const int DefaultScMinPostsIntervalMs = 30;
    private const int DefaultHeaderPayloadChunkCharactersFrom = 3 * 1000;
    private const int DefaultHeaderPayloadChunkCharactersTo = 4 * 1000;
    private const int DefaultCookiePayloadChunkCharactersFrom = 2 * 1024;
    private const int DefaultCookiePayloadChunkCharactersTo = 3 * 1024;
    private const int MinimumUplinkChunkCharacters = 64;
    private const int UploadPipeSegmentSize = 8 * 1024;
    private const int DefaultXPaddingBytesFrom = 100;
    private const int DefaultXPaddingBytesTo = 1000;
    private const string DefaultXPaddingKey = "x_padding";
    private const string DefaultXPaddingHeader = "X-Padding";
    private const string DefaultXPaddingPlacement = "queryInHeader";
    private const string DefaultXPaddingMethod = "repeat-x";
    private const string DefaultNonObfsXPaddingHeader = "Referer";
    private const string XPaddingBase62Charset = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
    private const double TokenishAverageHuffmanBytesPerCharBase62 = 0.8d;
    private const int TokenishValidationTolerance = 2;
    private const int TokenishMaxIterations = 150;
    private static readonly ConcurrentDictionary<SplitHttpSharedUploadPoolKey, SplitHttpSharedUploadPoolManager> SharedUploadPools = new();
    private static readonly ConcurrentDictionary<SplitHttpSharedUploadPoolKey, SplitHttpHttp3UploadPoolManager> SharedHttp3UploadPools = new();
    private static readonly ConcurrentDictionary<SplitHttpSharedUploadPoolKey, SplitHttpHttp2UploadPoolManager> SharedHttp2UploadPools = new();

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

        if (transportInitializationData is { Length: > 0 })
        {
            throw new NotSupportedException("SplitHTTP transport does not support transport initialization payloads.");
        }

        var downlinkTarget = ResolveDownlinkTarget(options, internetStack);
        var normalizedConfiguredMode = NormalizeMode(options.SplitHttpMode);
        var effectiveMode = ResolveEffectiveMode(
            normalizedConfiguredMode,
            internetStack,
            downlinkTarget.HasDedicatedDownloadSettings);
        var normalizedMethod = NormalizeUplinkHttpMethod(options.SplitHttpUplinkHttpMethod);
        var normalizedSessionPlacement = RuntimeSplitHttpRequestMetadata.NormalizeSessionPlacement(options.SplitHttpSessionPlacement);
        var normalizedSessionKey = RuntimeSplitHttpRequestMetadata.ResolveSessionKey(
            normalizedSessionPlacement,
            options.SplitHttpSessionKey);
        var normalizedSeqPlacement = RuntimeSplitHttpRequestMetadata.NormalizeSeqPlacement(options.SplitHttpSeqPlacement);
        var normalizedSeqKey = RuntimeSplitHttpRequestMetadata.ResolveSeqKey(
            normalizedSeqPlacement,
            options.SplitHttpSeqKey);
        var normalizedUplinkDataPlacement = NormalizeUplinkDataPlacement(options.SplitHttpUplinkDataPlacement);
        var normalizedUplinkDataKey = ResolveUplinkDataKey(normalizedUplinkDataPlacement, options.SplitHttpUplinkDataKey);
        var normalizedScMaxEachPostBytes = NormalizeScMaxEachPostBytes(options.SplitHttpScMaxEachPostBytes);
        var normalizedUplinkChunkSize = NormalizeUplinkChunkSize(
            options.SplitHttpUplinkChunkSize,
            normalizedUplinkDataPlacement,
            normalizedScMaxEachPostBytes);
        var normalizedScMinPostsIntervalMs = NormalizeScMinPostsIntervalMs(options.SplitHttpScMinPostsIntervalMs);
        var normalizedXPaddingOptions = NormalizeXPaddingOptions(options);
        if (downlinkTarget.HasDedicatedDownloadSettings &&
            string.Equals(effectiveMode, "stream-one", StringComparison.Ordinal))
        {
            throw new NotSupportedException("SplitHTTP downloadSettings cannot be used in stream-one mode.");
        }

        if (ResolveBrowserDialer(internetProfile, internetStack) is not null &&
            (string.Equals(effectiveMode, "stream-one", StringComparison.Ordinal) ||
             string.Equals(effectiveMode, "stream-up", StringComparison.Ordinal)))
        {
            throw new NotSupportedException("SplitHTTP browser dialer does not support bidirectional streaming.");
        }

        if (IsExplicitHttp3Requested(internetStack, options))
        {
            if (string.Equals(effectiveMode, "stream-one", StringComparison.Ordinal))
            {
                return await OpenHttp3StreamOneAsync(
                        options,
                        internetStack,
                        internetProfile,
                        dnsResolver,
                        normalizedMethod,
                        normalizedXPaddingOptions,
                        cancellationToken)
                    .ConfigureAwait(false);
            }

            if (string.Equals(effectiveMode, "stream-up", StringComparison.Ordinal))
            {
                return await OpenHttp3StreamUpAsync(
                        options,
                        internetStack,
                        downlinkTarget,
                        internetProfile,
                        dnsResolver,
                        normalizedMethod,
                        normalizedSessionPlacement,
                        normalizedSessionKey,
                        normalizedXPaddingOptions,
                        cancellationToken)
                    .ConfigureAwait(false);
            }

            if (string.Equals(effectiveMode, "packet-up", StringComparison.Ordinal))
            {
                return await OpenHttp3PacketUpAsync(
                        options,
                        internetStack,
                        downlinkTarget,
                        internetProfile,
                        dnsResolver,
                        normalizedMethod,
                        normalizedSessionPlacement,
                        normalizedSessionKey,
                        normalizedSeqPlacement,
                        normalizedSeqKey,
                        normalizedUplinkDataPlacement,
                        normalizedUplinkDataKey,
                        normalizedUplinkChunkSize,
                        normalizedScMaxEachPostBytes,
                        normalizedScMinPostsIntervalMs,
                        normalizedXPaddingOptions,
                        cancellationToken)
                    .ConfigureAwait(false);
            }

            throw new NotSupportedException(
                $"SplitHTTP over HTTP/3 currently supports stream-one, stream-up and packet-up. The resolved mode was '{effectiveMode}'.");
        }

        return effectiveMode switch
        {
            "stream-up" => await OpenStreamUpAsync(
                    options,
                    internetStack,
                    downlinkTarget,
                    internetProfile,
                    dnsResolver,
                    normalizedMethod,
                    normalizedSessionPlacement,
                    normalizedSessionKey,
                    normalizedXPaddingOptions,
                    cancellationToken)
                .ConfigureAwait(false),
            "packet-up" => await OpenPacketUpAsync(
                    options,
                    internetStack,
                    downlinkTarget,
                    internetProfile,
                    dnsResolver,
                    normalizedMethod,
                    normalizedSessionPlacement,
                    normalizedSessionKey,
                    normalizedSeqPlacement,
                    normalizedSeqKey,
                    normalizedUplinkDataPlacement,
                    normalizedUplinkDataKey,
                    normalizedUplinkChunkSize,
                    normalizedScMaxEachPostBytes,
                    normalizedScMinPostsIntervalMs,
                    normalizedXPaddingOptions,
                    cancellationToken)
                .ConfigureAwait(false),
            "stream-one" => await OpenStreamOneAsync(
                    options,
                    internetStack,
                    internetProfile,
                    dnsResolver,
                    normalizedMethod,
                    normalizedXPaddingOptions,
                    cancellationToken)
                .ConfigureAwait(false),
            _ => throw new NotSupportedException(
                $"SplitHTTP mode '{effectiveMode}' is not supported yet. Currently packet-up, stream-up and stream-one are implemented.")
        };
    }

    private static async ValueTask<RuntimeInternetConnectionContext> OpenStreamUpAsync<TOptions>(
        TOptions options,
        RuntimeInternetStack internetStack,
        SplitHttpDownlinkTarget downlinkTarget,
        RuntimeInternetProfile internetProfile,
        IDnsResolver dnsResolver,
        string normalizedMethod,
        string normalizedSessionPlacement,
        string normalizedSessionKey,
        SplitHttpXPaddingRuntimeOptions normalizedXPaddingOptions,
        CancellationToken cancellationToken)
        where TOptions : class, IRuntimeGrpcClientDialOptions
    {
        var pooledContext = await TryOpenSharedHttp2StreamUpAsync(
                options,
                internetStack,
                downlinkTarget,
                internetProfile,
                dnsResolver,
                normalizedMethod,
                normalizedSessionPlacement,
                normalizedSessionKey,
                normalizedXPaddingOptions,
                cancellationToken)
            .ConfigureAwait(false);
        if (pooledContext is not null)
        {
            return pooledContext;
        }

        var sessionId = Guid.NewGuid().ToString();
        RuntimeInternetConnectionContext? sharedContext = null;
        Http2TunnelSession? sharedSession = null;
        RuntimeInternetConnectionContext? downlinkContext = null;
        RuntimeInternetConnectionContext? uploadContext = null;
        try
        {
            if (!downlinkTarget.HasDedicatedDownloadSettings)
            {
                sharedContext = await RuntimeGrpcClientConnector
                    .OpenSecuredTransportContextWithRetryAsync(
                        options,
                        internetStack,
                        internetProfile,
                        dnsResolver,
                        cancellationToken)
                    .ConfigureAwait(false);

                if (ShouldUseHttp2(sharedContext))
                {
                    sharedSession = await Http2TunnelSession
                        .CreateAsync(
                            sharedContext.TransportStream,
                            cancellationToken,
                            CreateSplitHttpHttp2SessionOptions(options.SplitHttpXmux))
                        .ConfigureAwait(false);
                }
                else
                {
                    downlinkContext = sharedContext;
                    sharedContext = null;
                }
            }
            else
            {
                downlinkContext = await RuntimeGrpcClientConnector
                    .OpenSecuredTransportContextWithRetryAsync(
                        downlinkTarget.Options,
                        downlinkTarget.InternetStack,
                        internetProfile,
                        dnsResolver,
                        cancellationToken)
                    .ConfigureAwait(false);
            }

            if (sharedSession is null)
            {
                uploadContext = await RuntimeGrpcClientConnector
                    .OpenSecuredTransportContextWithRetryAsync(
                        options,
                        internetStack,
                        internetProfile,
                        dnsResolver,
                        cancellationToken)
                    .ConfigureAwait(false);
            }

            var downlinkAuthority = ResolveAuthority(downlinkTarget.InternetStack, downlinkTarget.Options);
            var downlinkRequest = BuildStreamRequest(
                downlinkTarget.InternetStack,
                downlinkTarget.Options,
                normalizedXPaddingOptions,
                normalizedSessionPlacement,
                normalizedSessionKey,
                sessionId,
                seqPlacement: string.Empty,
                seqKey: string.Empty,
                seqValue: null);
            var uploadAuthority = ResolveAuthority(internetStack, options);
            var uploadRequest = BuildStreamRequest(
                internetStack,
                options,
                normalizedXPaddingOptions,
                normalizedSessionPlacement,
                normalizedSessionKey,
                sessionId,
                seqPlacement: string.Empty,
                seqKey: string.Empty,
                seqValue: null);

            if (sharedSession is not null)
            {
                var downlinkStream = await OpenDownlinkStreamAsync(
                        sharedSession,
                        downlinkTarget.InternetStack,
                        downlinkAuthority,
                        downlinkRequest.RequestTarget,
                        downlinkRequest.RequestHeaders,
                        cancellationToken)
                    .ConfigureAwait(false);

                var uploadStream = await OpenUploadStreamAsync(
                        sharedSession,
                        internetStack,
                        normalizedMethod,
                        uploadAuthority,
                        uploadRequest.RequestTarget,
                        uploadRequest.RequestHeaders,
                        options.SplitHttpNoGrpcHeader,
                        cancellationToken)
                    .ConfigureAwait(false);

                var duplexStream = new SplitHttpDuplexStream(downlinkStream, uploadStream);
                var ownedStream = new SplitHttpOwnedStream(duplexStream, [sharedSession]);
                var securityState = CloneSecurityState(sharedContext!.SecurityState);
                sharedContext.SecurityState.RemoteCertificate?.Dispose();
                sharedContext = null;
                sharedSession = null;

                var context = new RuntimeInternetConnectionContext(ownedStream);
                context.SetTransportStream(ownedStream, securityState: securityState);
                return context;
            }

            var fallbackDownlinkContext = downlinkContext ??
                throw new InvalidOperationException("SplitHTTP stream-up failed to open the downlink transport context.");
            var fallbackUploadContext = uploadContext ??
                throw new InvalidOperationException("SplitHTTP stream-up failed to open the upload transport context.");

            var fallbackDownlinkStream = await OpenDownlinkStreamAsync(
                    fallbackDownlinkContext,
                    downlinkTarget.InternetStack,
                    downlinkAuthority,
                    downlinkRequest.RequestTarget,
                    downlinkRequest.RequestHeaders,
                    cancellationToken)
                .ConfigureAwait(false);

            var fallbackUploadStream = await OpenUploadStreamAsync(
                    fallbackUploadContext,
                    internetStack,
                    normalizedMethod,
                    uploadAuthority,
                    uploadRequest.RequestTarget,
                    uploadRequest.RequestHeaders,
                    options.SplitHttpNoGrpcHeader,
                    cancellationToken)
                .ConfigureAwait(false);

            var fallbackDuplexStream = new SplitHttpDuplexStream(fallbackDownlinkStream, fallbackUploadStream);
            var fallbackSecurityState = CloneSecurityState(fallbackDownlinkContext.SecurityState);
            fallbackDownlinkContext.SecurityState.RemoteCertificate?.Dispose();
            fallbackUploadContext.SecurityState.RemoteCertificate?.Dispose();

            var fallbackContext = new RuntimeInternetConnectionContext(fallbackDuplexStream);
            fallbackContext.SetTransportStream(fallbackDuplexStream, securityState: fallbackSecurityState);
            return fallbackContext;
        }
        catch
        {
            if (sharedSession is not null)
            {
                await sharedSession.DisposeAsync().ConfigureAwait(false);
            }

            if (sharedContext is not null)
            {
                if (sharedSession is null)
                {
                    await RuntimeGrpcClientConnector.DisposeTransportContextAsync(sharedContext).ConfigureAwait(false);
                }
                else
                {
                    sharedContext.SecurityState.RemoteCertificate?.Dispose();
                }
            }

            if (uploadContext is not null)
            {
                await RuntimeGrpcClientConnector.DisposeTransportContextAsync(uploadContext).ConfigureAwait(false);
            }

            if (downlinkContext is not null)
            {
                await RuntimeGrpcClientConnector.DisposeTransportContextAsync(downlinkContext).ConfigureAwait(false);
            }

            throw;
        }
    }

    private static async ValueTask<RuntimeInternetConnectionContext> OpenPacketUpAsync<TOptions>(
        TOptions options,
        RuntimeInternetStack internetStack,
        SplitHttpDownlinkTarget downlinkTarget,
        RuntimeInternetProfile internetProfile,
        IDnsResolver dnsResolver,
        string normalizedMethod,
        string normalizedSessionPlacement,
        string normalizedSessionKey,
        string normalizedSeqPlacement,
        string normalizedSeqKey,
        string normalizedUplinkDataPlacement,
        string normalizedUplinkDataKey,
        RuntimeInt32Range normalizedUplinkChunkSize,
        RuntimeInt32Range normalizedScMaxEachPostBytes,
        RuntimeInt32Range normalizedScMinPostsIntervalMs,
        SplitHttpXPaddingRuntimeOptions normalizedXPaddingOptions,
        CancellationToken cancellationToken)
        where TOptions : class, IRuntimeGrpcClientDialOptions
    {
        var sessionId = Guid.NewGuid().ToString();
        RuntimeInternetConnectionContext? downlinkContext = null;
        Stream? downlinkStream = null;
        Stream? uploadStream = null;
        try
        {
            var downlinkAuthority = ResolveAuthority(downlinkTarget.InternetStack, downlinkTarget.Options);
            var downlinkRequest = BuildStreamRequest(
                downlinkTarget.InternetStack,
                downlinkTarget.Options,
                normalizedXPaddingOptions,
                normalizedSessionPlacement,
                normalizedSessionKey,
                sessionId,
                seqPlacement: string.Empty,
                seqKey: string.Empty,
                seqValue: null);
            var downlinkBrowserDialer = ResolveBrowserDialer(internetProfile, downlinkTarget.InternetStack);
            if (downlinkBrowserDialer is not null)
            {
                downlinkStream = await OpenBrowserDownlinkStreamAsync(
                        downlinkBrowserDialer,
                        downlinkTarget.InternetStack,
                        downlinkAuthority,
                        downlinkRequest.RequestTarget,
                        downlinkRequest.RequestHeaders,
                        cancellationToken)
                    .ConfigureAwait(false);
            }
            else
            {
                downlinkContext = await RuntimeGrpcClientConnector
                    .OpenSecuredTransportContextWithRetryAsync(
                        downlinkTarget.Options,
                        downlinkTarget.InternetStack,
                        internetProfile,
                        dnsResolver,
                        cancellationToken)
                    .ConfigureAwait(false);

                downlinkStream = await OpenDownlinkStreamAsync(
                        downlinkContext,
                        downlinkTarget.InternetStack,
                        downlinkAuthority,
                        downlinkRequest.RequestTarget,
                        downlinkRequest.RequestHeaders,
                        cancellationToken)
                    .ConfigureAwait(false);
            }

            var uploadAuthority = ResolveAuthority(internetStack, options);
            var uploadBrowserDialer = ResolveBrowserDialer(internetProfile, internetStack);
            uploadStream = uploadBrowserDialer is null
                ? new SplitHttpPacketUploadStream<TOptions>(
                    options,
                    internetStack,
                    internetProfile,
                    dnsResolver,
                    uploadAuthority,
                    normalizedMethod,
                    normalizedSessionPlacement,
                    normalizedSessionKey,
                    sessionId,
                    normalizedSeqPlacement,
                    normalizedSeqKey,
                    normalizedUplinkDataPlacement,
                    normalizedUplinkDataKey,
                    normalizedUplinkChunkSize,
                    normalizedScMaxEachPostBytes,
                    normalizedScMinPostsIntervalMs,
                    normalizedXPaddingOptions)
                : new SplitHttpBrowserPacketUploadStream(
                    uploadBrowserDialer,
                    internetStack,
                    options,
                    uploadAuthority,
                    normalizedMethod,
                    normalizedSessionPlacement,
                    normalizedSessionKey,
                    sessionId,
                    normalizedSeqPlacement,
                    normalizedSeqKey,
                    normalizedUplinkDataPlacement,
                    normalizedUplinkDataKey,
                    normalizedUplinkChunkSize,
                    normalizedScMaxEachPostBytes,
                    normalizedScMinPostsIntervalMs,
                    normalizedXPaddingOptions);

            var duplexStream = new SplitHttpDuplexStream(downlinkStream, uploadStream);
            var securityState = downlinkContext is null
                ? CreateBrowserDialerSecurityState(downlinkTarget.InternetStack)
                : CloneSecurityState(downlinkContext.SecurityState);
            downlinkContext?.SecurityState.RemoteCertificate?.Dispose();

            var context = new RuntimeInternetConnectionContext(duplexStream);
            context.SetTransportStream(duplexStream, securityState: securityState);
            return context;
        }
        catch
        {
            if (uploadStream is not null)
            {
                await uploadStream.DisposeAsync().ConfigureAwait(false);
            }

            if (downlinkContext is not null)
            {
                await RuntimeGrpcClientConnector.DisposeTransportContextAsync(downlinkContext).ConfigureAwait(false);
            }
            else if (downlinkStream is not null)
            {
                await downlinkStream.DisposeAsync().ConfigureAwait(false);
            }

            throw;
        }
    }

    private static async ValueTask<RuntimeInternetConnectionContext> OpenStreamOneAsync<TOptions>(
        TOptions options,
        RuntimeInternetStack internetStack,
        RuntimeInternetProfile internetProfile,
        IDnsResolver dnsResolver,
        string normalizedMethod,
        SplitHttpXPaddingRuntimeOptions normalizedXPaddingOptions,
        CancellationToken cancellationToken)
        where TOptions : class, IRuntimeGrpcClientDialOptions
    {
        var pooledContext = await TryOpenSharedHttp2StreamOneAsync(
                options,
                internetStack,
                internetProfile,
                dnsResolver,
                normalizedMethod,
                normalizedXPaddingOptions,
                cancellationToken)
            .ConfigureAwait(false);
        if (pooledContext is not null)
        {
            return pooledContext;
        }

        RuntimeInternetConnectionContext? context = null;
        try
        {
            context = await RuntimeGrpcClientConnector
                .OpenSecuredTransportContextWithRetryAsync(
                    options,
                    internetStack,
                    internetProfile,
                    dnsResolver,
                    cancellationToken)
                .ConfigureAwait(false);

            var authority = ResolveAuthority(internetStack, options);
            var request = BuildStreamRequest(
                internetStack,
                options,
                normalizedXPaddingOptions,
                sessionPlacement: string.Empty,
                sessionKey: string.Empty,
                sessionId: string.Empty,
                seqPlacement: string.Empty,
                seqKey: string.Empty,
                seqValue: null);
            var duplexStream = await OpenStreamOneStreamAsync(
                    context,
                    internetStack,
                    normalizedMethod,
                    authority,
                    request.RequestTarget,
                    request.RequestHeaders,
                    options.SplitHttpNoGrpcHeader,
                    cancellationToken)
                .ConfigureAwait(false);
            var securityState = CloneSecurityState(context.SecurityState);
            context.SecurityState.RemoteCertificate?.Dispose();

            var runtimeContext = new RuntimeInternetConnectionContext(duplexStream);
            runtimeContext.SetTransportStream(duplexStream, securityState: securityState);
            return runtimeContext;
        }
        catch
        {
            if (context is not null)
            {
                await RuntimeGrpcClientConnector.DisposeTransportContextAsync(context).ConfigureAwait(false);
            }

            throw;
        }
    }

    private static async ValueTask<RuntimeInternetConnectionContext?> TryOpenSharedHttp2StreamUpAsync<TOptions>(
        TOptions options,
        RuntimeInternetStack internetStack,
        SplitHttpDownlinkTarget downlinkTarget,
        RuntimeInternetProfile internetProfile,
        IDnsResolver dnsResolver,
        string normalizedMethod,
        string normalizedSessionPlacement,
        string normalizedSessionKey,
        SplitHttpXPaddingRuntimeOptions normalizedXPaddingOptions,
        CancellationToken cancellationToken)
        where TOptions : class, IRuntimeGrpcClientDialOptions
    {
        var uploadSharedPoolManager = TryGetSharedHttp2UploadPoolManager(
            options,
            internetStack,
            internetProfile,
            dnsResolver);
        if (uploadSharedPoolManager is null)
        {
            return null;
        }

        var usesDedicatedDownlinkPool = downlinkTarget.HasDedicatedDownloadSettings;
        var downlinkSharedPoolManager = usesDedicatedDownlinkPool
            ? TryGetSharedHttp2UploadPoolManager(
                downlinkTarget.Options,
                downlinkTarget.InternetStack,
                internetProfile,
                dnsResolver)
            : uploadSharedPoolManager;
        if (downlinkSharedPoolManager is null)
        {
            return null;
        }

        var sessionId = Guid.NewGuid().ToString();
        var downlinkAuthority = ResolveAuthority(downlinkTarget.InternetStack, downlinkTarget.Options);
        var downlinkRequest = BuildStreamRequest(
            downlinkTarget.InternetStack,
            downlinkTarget.Options,
            normalizedXPaddingOptions,
            normalizedSessionPlacement,
            normalizedSessionKey,
            sessionId,
            seqPlacement: string.Empty,
            seqKey: string.Empty,
            seqValue: null);
        var uploadAuthority = ResolveAuthority(internetStack, options);
        var uploadRequest = BuildStreamRequest(
            internetStack,
            options,
            normalizedXPaddingOptions,
            normalizedSessionPlacement,
            normalizedSessionKey,
            sessionId,
            seqPlacement: string.Empty,
            seqKey: string.Empty,
            seqValue: null);
        var uploadTransportContextFactory =
            (Func<CancellationToken, ValueTask<RuntimeInternetConnectionContext>>)(token =>
                RuntimeGrpcClientConnector.OpenSecuredTransportContextWithRetryAsync(
                    options,
                    internetStack,
                    internetProfile,
                    dnsResolver,
                    token));
        var downlinkTransportContextFactory =
            usesDedicatedDownlinkPool
                ? (Func<CancellationToken, ValueTask<RuntimeInternetConnectionContext>>)(token =>
                    RuntimeGrpcClientConnector.OpenSecuredTransportContextWithRetryAsync(
                        downlinkTarget.Options,
                        downlinkTarget.InternetStack,
                        internetProfile,
                        dnsResolver,
                        token))
                : uploadTransportContextFactory;

        for (var attempt = 0; attempt < 2; attempt++)
        {
            SplitHttpHttp2UploadPoolLease? downlinkLease = null;
            SplitHttpHttp2UploadPoolLease? uploadLease = null;
            Stream? downlinkStream = null;
            Stream? uploadStream = null;
            try
            {
                downlinkLease = downlinkSharedPoolManager.Acquire();
                uploadLease = usesDedicatedDownlinkPool
                    ? uploadSharedPoolManager.Acquire()
                    : downlinkLease;

                downlinkLease.RecordStreamRequest(DateTime.UtcNow);
                downlinkStream = await downlinkLease
                    .OpenRequestStreamAsync(
                        downlinkTransportContextFactory,
                        downlinkTarget.InternetStack,
                        "GET",
                        downlinkAuthority,
                        downlinkRequest.RequestTarget,
                        downlinkRequest.RequestHeaders,
                        includeContentType: false,
                        waitForSuccessfulStatus: true,
                        endStreamOnHeaders: true,
                        cancellationToken)
                    .ConfigureAwait(false);
                if (downlinkStream is null)
                {
                    await downlinkLease.DisposeAsync().ConfigureAwait(false);
                    if (uploadLease is not null &&
                        !ReferenceEquals(uploadLease, downlinkLease))
                    {
                        await uploadLease.DisposeAsync().ConfigureAwait(false);
                    }

                    continue;
                }

                uploadLease.RecordStreamRequest(DateTime.UtcNow);
                uploadStream = await uploadLease
                    .OpenRequestStreamAsync(
                        uploadTransportContextFactory,
                        internetStack,
                        normalizedMethod,
                        uploadAuthority,
                        uploadRequest.RequestTarget,
                        uploadRequest.RequestHeaders,
                        includeContentType: !options.SplitHttpNoGrpcHeader,
                        waitForSuccessfulStatus: false,
                        endStreamOnHeaders: false,
                        cancellationToken)
                    .ConfigureAwait(false);
                if (uploadStream is null)
                {
                    await downlinkStream.DisposeAsync().ConfigureAwait(false);
                    await downlinkLease.DisposeAsync().ConfigureAwait(false);
                    if (!ReferenceEquals(uploadLease, downlinkLease))
                    {
                        await uploadLease.DisposeAsync().ConfigureAwait(false);
                    }

                    continue;
                }

                uploadStream = new SplitHttpResponseDrainingUploadStream(uploadStream);

                var securityState = downlinkLease.CloneSecurityState()
                    ?? throw new InvalidOperationException("Shared SplitHTTP HTTP/2 stream-up lease was missing security metadata.");
                var duplexStream = new SplitHttpDuplexStream(downlinkStream, uploadStream);
                var owners = ReferenceEquals(downlinkLease, uploadLease)
                    ? new IAsyncDisposable[] { downlinkLease }
                    : new IAsyncDisposable[] { downlinkLease, uploadLease };
                var ownedStream = new SplitHttpOwnedStream(duplexStream, owners);
                downlinkLease = null;
                uploadLease = null;
                downlinkStream = null;
                uploadStream = null;

                var context = new RuntimeInternetConnectionContext(ownedStream);
                context.SetTransportStream(ownedStream, securityState: securityState);
                return context;
            }
            finally
            {
                if (uploadStream is not null)
                {
                    await uploadStream.DisposeAsync().ConfigureAwait(false);
                }

                if (downlinkStream is not null)
                {
                    await downlinkStream.DisposeAsync().ConfigureAwait(false);
                }

                if (uploadLease is not null &&
                    !ReferenceEquals(uploadLease, downlinkLease))
                {
                    await uploadLease.DisposeAsync().ConfigureAwait(false);
                }

                if (downlinkLease is not null)
                {
                    await downlinkLease.DisposeAsync().ConfigureAwait(false);
                }
            }
        }

        return null;
    }

    private static async ValueTask<RuntimeInternetConnectionContext?> TryOpenSharedHttp2StreamOneAsync<TOptions>(
        TOptions options,
        RuntimeInternetStack internetStack,
        RuntimeInternetProfile internetProfile,
        IDnsResolver dnsResolver,
        string normalizedMethod,
        SplitHttpXPaddingRuntimeOptions normalizedXPaddingOptions,
        CancellationToken cancellationToken)
        where TOptions : class, IRuntimeGrpcClientDialOptions
    {
        var sharedPoolManager = TryGetSharedHttp2UploadPoolManager(
            options,
            internetStack,
            internetProfile,
            dnsResolver);
        if (sharedPoolManager is null)
        {
            return null;
        }

        var authority = ResolveAuthority(internetStack, options);
        var request = BuildStreamRequest(
            internetStack,
            options,
            normalizedXPaddingOptions,
            sessionPlacement: string.Empty,
            sessionKey: string.Empty,
            sessionId: string.Empty,
            seqPlacement: string.Empty,
            seqKey: string.Empty,
            seqValue: null);

        for (var attempt = 0; attempt < 2; attempt++)
        {
            SplitHttpHttp2UploadPoolLease? lease = null;
            Stream? applicationStream = null;
            try
            {
                lease = sharedPoolManager.Acquire();
                lease.RecordStreamRequest(DateTime.UtcNow);
                applicationStream = await lease
                    .OpenRequestStreamAsync(
                        token => RuntimeGrpcClientConnector.OpenSecuredTransportContextWithRetryAsync(
                            options,
                            internetStack,
                            internetProfile,
                            dnsResolver,
                            token),
                        internetStack,
                        normalizedMethod,
                        authority,
                        request.RequestTarget,
                        request.RequestHeaders,
                        includeContentType: !options.SplitHttpNoGrpcHeader,
                        waitForSuccessfulStatus: false,
                        endStreamOnHeaders: false,
                        cancellationToken)
                    .ConfigureAwait(false);
                if (applicationStream is null)
                {
                    await lease.DisposeAsync().ConfigureAwait(false);
                    continue;
                }

                var securityState = lease.CloneSecurityState()
                    ?? throw new InvalidOperationException("Shared SplitHTTP HTTP/2 stream-one lease was missing security metadata.");
                var ownedStream = new SplitHttpOwnedStream(applicationStream, [lease]);
                lease = null;
                applicationStream = null;

                var context = new RuntimeInternetConnectionContext(ownedStream);
                context.SetTransportStream(ownedStream, securityState: securityState);
                return context;
            }
            finally
            {
                if (applicationStream is not null)
                {
                    await applicationStream.DisposeAsync().ConfigureAwait(false);
                }

                if (lease is not null)
                {
                    await lease.DisposeAsync().ConfigureAwait(false);
                }
            }
        }

        return null;
    }

    private static async ValueTask<RuntimeInternetConnectionContext?> TryOpenSharedHttp3StreamUpAsync<TOptions>(
        TOptions options,
        RuntimeInternetStack internetStack,
        SplitHttpDownlinkTarget downlinkTarget,
        RuntimeInternetProfile internetProfile,
        IDnsResolver dnsResolver,
        string normalizedMethod,
        string normalizedSessionPlacement,
        string normalizedSessionKey,
        SplitHttpXPaddingRuntimeOptions normalizedXPaddingOptions,
        CancellationToken cancellationToken)
        where TOptions : class, IRuntimeGrpcClientDialOptions
    {
        var uploadSharedPoolManager = TryGetSharedHttp3PoolManager(
            options,
            internetStack,
            internetProfile,
            dnsResolver);
        if (uploadSharedPoolManager is null)
        {
            return null;
        }

        var usesDedicatedDownlinkPool = downlinkTarget.HasDedicatedDownloadSettings;
        var downlinkUsesHttp3 = !usesDedicatedDownlinkPool ||
                                IsExplicitHttp3Requested(downlinkTarget.InternetStack, downlinkTarget.Options);
        var downlinkSharedPoolManager = downlinkUsesHttp3
            ? usesDedicatedDownlinkPool
                ? TryGetSharedHttp3PoolManager(
                    downlinkTarget.Options,
                    downlinkTarget.InternetStack,
                    internetProfile,
                    dnsResolver)
                : uploadSharedPoolManager
            : null;

        var sessionId = Guid.NewGuid().ToString();
        var downlinkAuthority = ResolveAuthority(downlinkTarget.InternetStack, downlinkTarget.Options);
        var downlinkRequest = BuildStreamRequest(
            downlinkTarget.InternetStack,
            downlinkTarget.Options,
            normalizedXPaddingOptions,
            normalizedSessionPlacement,
            normalizedSessionKey,
            sessionId,
            seqPlacement: string.Empty,
            seqKey: string.Empty,
            seqValue: null);
        var uploadAuthority = ResolveAuthority(internetStack, options);
        var uploadRequest = BuildStreamRequest(
            internetStack,
            options,
            normalizedXPaddingOptions,
            normalizedSessionPlacement,
            normalizedSessionKey,
            sessionId,
            seqPlacement: string.Empty,
            seqKey: string.Empty,
            seqValue: null);

        for (var attempt = 0; attempt < 2; attempt++)
        {
            SplitHttpHttp3UploadPoolLease? downlinkLease = null;
            SplitHttpHttp3UploadPoolLease? uploadLease = null;
            RuntimeInternetConnectionContext? downlinkContext = null;
            RuntimeHttp3ClientSession? downlinkSession = null;
            Stream? downlinkStream = null;
            Stream? uploadStream = null;
            try
            {
                RuntimeInternetSecurityState securityState;
                if (downlinkSharedPoolManager is not null)
                {
                    downlinkLease = downlinkSharedPoolManager.Acquire();
                    uploadLease = usesDedicatedDownlinkPool
                        ? uploadSharedPoolManager.Acquire()
                        : downlinkLease;

                    downlinkLease.RecordStreamRequest(DateTime.UtcNow);
                    downlinkStream = await downlinkLease
                        .OpenRequestStreamAsync(
                            token => OpenHttp3SessionAsync(
                                downlinkTarget.Options,
                                downlinkTarget.InternetStack,
                                dnsResolver,
                                token),
                            downlinkTarget.InternetStack,
                            "GET",
                            downlinkAuthority,
                            downlinkRequest.RequestTarget,
                            downlinkRequest.RequestHeaders,
                            includeContentType: false,
                            waitForSuccessfulStatus: false,
                            endStreamOnHeaders: true,
                            cancellationToken)
                        .ConfigureAwait(false);
                    if (downlinkStream is null)
                    {
                        await downlinkLease.DisposeAsync().ConfigureAwait(false);
                        if (uploadLease is not null &&
                            !ReferenceEquals(uploadLease, downlinkLease))
                        {
                            await uploadLease.DisposeAsync().ConfigureAwait(false);
                        }

                        continue;
                    }

                    securityState = downlinkLease.CloneSecurityState()
                        ?? throw new InvalidOperationException("Shared SplitHTTP HTTP/3 stream-up lease was missing security metadata.");
                }
                else if (IsExplicitHttp3Requested(downlinkTarget.InternetStack, downlinkTarget.Options))
                {
                    var openedDownlinkSession = await OpenHttp3SessionAsync(
                            downlinkTarget.Options,
                            downlinkTarget.InternetStack,
                            dnsResolver,
                            cancellationToken)
                        .ConfigureAwait(false);
                    downlinkSession = openedDownlinkSession.Session;
                    securityState = openedDownlinkSession.SecurityState;
                    downlinkStream = await downlinkSession
                        .OpenHttpRequestStreamAsync(
                            "GET",
                            downlinkAuthority,
                            ResolveHttpScheme(downlinkTarget.InternetStack),
                            downlinkRequest.RequestTarget,
                            CreateHttp2RequestHeaders(downlinkRequest.RequestHeaders, includeContentType: false),
                            Array.Empty<byte>(),
                            waitForSuccessfulStatus: false,
                            cancellationToken,
                            disposeSessionOnClose: true,
                            endRequestOnHeaders: true)
                        .ConfigureAwait(false);
                    downlinkSession = null;
                }
                else
                {
                    downlinkContext = await RuntimeGrpcClientConnector
                        .OpenSecuredTransportContextWithRetryAsync(
                            downlinkTarget.Options,
                            downlinkTarget.InternetStack,
                            internetProfile,
                            dnsResolver,
                            cancellationToken)
                        .ConfigureAwait(false);
                    securityState = CloneSecurityState(downlinkContext.SecurityState);
                    downlinkStream = await OpenDownlinkStreamAsync(
                            downlinkContext,
                            downlinkTarget.InternetStack,
                            downlinkAuthority,
                            downlinkRequest.RequestTarget,
                            downlinkRequest.RequestHeaders,
                            cancellationToken)
                        .ConfigureAwait(false);
                    downlinkContext.SecurityState.RemoteCertificate?.Dispose();
                    downlinkContext = null;
                }

                uploadLease ??= uploadSharedPoolManager.Acquire();
                uploadLease.RecordStreamRequest(DateTime.UtcNow);
                uploadStream = await uploadLease
                    .OpenRequestStreamAsync(
                        token => OpenHttp3SessionAsync(
                            options,
                            internetStack,
                            dnsResolver,
                            token),
                        internetStack,
                        normalizedMethod,
                        uploadAuthority,
                        uploadRequest.RequestTarget,
                        uploadRequest.RequestHeaders,
                        includeContentType: !options.SplitHttpNoGrpcHeader,
                        waitForSuccessfulStatus: false,
                        endStreamOnHeaders: false,
                        cancellationToken)
                    .ConfigureAwait(false);
                if (uploadStream is null)
                {
                    await downlinkStream.DisposeAsync().ConfigureAwait(false);
                    if (downlinkLease is not null &&
                        ReferenceEquals(downlinkLease, uploadLease))
                    {
                        await downlinkLease.DisposeAsync().ConfigureAwait(false);
                        downlinkLease = null;
                        uploadLease = null;
                    }
                    else
                    {
                        await uploadLease.DisposeAsync().ConfigureAwait(false);
                        uploadLease = null;
                        if (downlinkLease is not null)
                        {
                            await downlinkLease.DisposeAsync().ConfigureAwait(false);
                            downlinkLease = null;
                        }
                    }

                    continue;
                }

                uploadStream = new SplitHttpResponseDrainingUploadStream(uploadStream);

                var duplexStream = new SplitHttpDuplexStream(downlinkStream, uploadStream);
                var activeUploadLease = uploadLease
                    ?? throw new InvalidOperationException("SplitHTTP HTTP/3 stream-up upload lease was unexpectedly missing.");
                var owners = downlinkLease is null
                    ? new IAsyncDisposable[] { activeUploadLease }
                    : ReferenceEquals(downlinkLease, activeUploadLease)
                        ? [downlinkLease]
                        : [downlinkLease, activeUploadLease];
                var ownedStream = new SplitHttpOwnedStream(duplexStream, owners);
                downlinkLease = null;
                uploadLease = null;
                downlinkStream = null;
                uploadStream = null;

                var context = new RuntimeInternetConnectionContext(ownedStream);
                context.SetTransportStream(ownedStream, securityState: securityState);
                return context;
            }
            finally
            {
                if (uploadStream is not null)
                {
                    await uploadStream.DisposeAsync().ConfigureAwait(false);
                }

                if (downlinkStream is not null)
                {
                    await downlinkStream.DisposeAsync().ConfigureAwait(false);
                }

                if (downlinkSession is not null)
                {
                    await downlinkSession.DisposeAsync().ConfigureAwait(false);
                }

                if (downlinkContext is not null)
                {
                    await RuntimeGrpcClientConnector.DisposeTransportContextAsync(downlinkContext).ConfigureAwait(false);
                }

                if (uploadLease is not null &&
                    !ReferenceEquals(uploadLease, downlinkLease))
                {
                    await uploadLease.DisposeAsync().ConfigureAwait(false);
                }

                if (downlinkLease is not null)
                {
                    await downlinkLease.DisposeAsync().ConfigureAwait(false);
                }
            }
        }

        return null;
    }

    private static async ValueTask<RuntimeInternetConnectionContext?> TryOpenSharedHttp3StreamOneAsync<TOptions>(
        TOptions options,
        RuntimeInternetStack internetStack,
        RuntimeInternetProfile internetProfile,
        IDnsResolver dnsResolver,
        string normalizedMethod,
        SplitHttpXPaddingRuntimeOptions normalizedXPaddingOptions,
        CancellationToken cancellationToken)
        where TOptions : class, IRuntimeGrpcClientDialOptions
    {
        var sharedPoolManager = TryGetSharedHttp3PoolManager(
            options,
            internetStack,
            internetProfile,
            dnsResolver);
        if (sharedPoolManager is null)
        {
            return null;
        }

        var authority = ResolveAuthority(internetStack, options);
        var request = BuildStreamRequest(
            internetStack,
            options,
            normalizedXPaddingOptions,
            sessionPlacement: string.Empty,
            sessionKey: string.Empty,
            sessionId: string.Empty,
            seqPlacement: string.Empty,
            seqKey: string.Empty,
            seqValue: null);

        for (var attempt = 0; attempt < 2; attempt++)
        {
            SplitHttpHttp3UploadPoolLease? lease = null;
            Stream? applicationStream = null;
            try
            {
                lease = sharedPoolManager.Acquire();
                lease.RecordStreamRequest(DateTime.UtcNow);
                applicationStream = await lease
                    .OpenRequestStreamAsync(
                        token => OpenHttp3SessionAsync(
                            options,
                            internetStack,
                            dnsResolver,
                            token),
                        internetStack,
                        normalizedMethod,
                        authority,
                        request.RequestTarget,
                        request.RequestHeaders,
                        includeContentType: !options.SplitHttpNoGrpcHeader,
                        waitForSuccessfulStatus: false,
                        endStreamOnHeaders: false,
                        cancellationToken)
                    .ConfigureAwait(false);
                if (applicationStream is null)
                {
                    await lease.DisposeAsync().ConfigureAwait(false);
                    continue;
                }

                var securityState = lease.CloneSecurityState()
                    ?? throw new InvalidOperationException("Shared SplitHTTP HTTP/3 stream-one lease was missing security metadata.");
                var ownedStream = new SplitHttpOwnedStream(applicationStream, [lease]);
                lease = null;
                applicationStream = null;

                var context = new RuntimeInternetConnectionContext(ownedStream);
                context.SetTransportStream(ownedStream, securityState: securityState);
                return context;
            }
            finally
            {
                if (applicationStream is not null)
                {
                    await applicationStream.DisposeAsync().ConfigureAwait(false);
                }

                if (lease is not null)
                {
                    await lease.DisposeAsync().ConfigureAwait(false);
                }
            }
        }

        return null;
    }

    private static async ValueTask<RuntimeInternetConnectionContext> OpenHttp3StreamOneAsync<TOptions>(
        TOptions options,
        RuntimeInternetStack internetStack,
        RuntimeInternetProfile internetProfile,
        IDnsResolver dnsResolver,
        string normalizedMethod,
        SplitHttpXPaddingRuntimeOptions normalizedXPaddingOptions,
        CancellationToken cancellationToken)
        where TOptions : class, IRuntimeGrpcClientDialOptions
    {
        var pooledContext = await TryOpenSharedHttp3StreamOneAsync(
                options,
                internetStack,
                internetProfile,
                dnsResolver,
                normalizedMethod,
                normalizedXPaddingOptions,
                cancellationToken)
            .ConfigureAwait(false);
        if (pooledContext is not null)
        {
            return pooledContext;
        }

        RuntimeHttp3ClientSession? session = null;
        try
        {
            var openedSession = await OpenHttp3SessionAsync(
                    options,
                    internetStack,
                    dnsResolver,
                    cancellationToken)
                .ConfigureAwait(false);
            session = openedSession.Session;
            var securityState = openedSession.SecurityState;

            var authority = ResolveAuthority(internetStack, options);
            var request = BuildStreamRequest(
                internetStack,
                options,
                normalizedXPaddingOptions,
                sessionPlacement: string.Empty,
                sessionKey: string.Empty,
                sessionId: string.Empty,
                seqPlacement: string.Empty,
                seqKey: string.Empty,
                seqValue: null);
            var duplexStream = await session
                .OpenHttpRequestStreamAsync(
                    normalizedMethod,
                    authority,
                    ResolveHttpScheme(internetStack),
                    request.RequestTarget,
                    CreateHttp2RequestHeaders(request.RequestHeaders, includeContentType: !options.SplitHttpNoGrpcHeader),
                    Array.Empty<byte>(),
                    waitForSuccessfulStatus: false,
                    cancellationToken,
                    disposeSessionOnClose: true)
                .ConfigureAwait(false);

            var runtimeContext = new RuntimeInternetConnectionContext(duplexStream);
            runtimeContext.SetTransportStream(duplexStream, securityState: securityState);
            return runtimeContext;
        }
        catch
        {
            if (session is not null)
            {
                await session.DisposeAsync().ConfigureAwait(false);
            }

            throw;
        }
    }

    private static async ValueTask<RuntimeInternetConnectionContext> OpenHttp3StreamUpAsync<TOptions>(
        TOptions options,
        RuntimeInternetStack internetStack,
        SplitHttpDownlinkTarget downlinkTarget,
        RuntimeInternetProfile internetProfile,
        IDnsResolver dnsResolver,
        string normalizedMethod,
        string normalizedSessionPlacement,
        string normalizedSessionKey,
        SplitHttpXPaddingRuntimeOptions normalizedXPaddingOptions,
        CancellationToken cancellationToken)
        where TOptions : class, IRuntimeGrpcClientDialOptions
    {
        var pooledContext = await TryOpenSharedHttp3StreamUpAsync(
                options,
                internetStack,
                downlinkTarget,
                internetProfile,
                dnsResolver,
                normalizedMethod,
                normalizedSessionPlacement,
                normalizedSessionKey,
                normalizedXPaddingOptions,
                cancellationToken)
            .ConfigureAwait(false);
        if (pooledContext is not null)
        {
            return pooledContext;
        }

        var sessionId = Guid.NewGuid().ToString();
        RuntimeHttp3ClientSession? sharedSession = null;
        RuntimeHttp3ClientSession? downlinkSession = null;
        RuntimeHttp3ClientSession? uploadSession = null;
        RuntimeInternetConnectionContext? downlinkContext = null;
        Stream? downlinkStream = null;
        Stream? uploadStream = null;
        try
        {
            RuntimeInternetSecurityState securityState;
            if (!downlinkTarget.HasDedicatedDownloadSettings)
            {
                var openedSession = await OpenHttp3SessionAsync(
                        options,
                        internetStack,
                        dnsResolver,
                        cancellationToken)
                    .ConfigureAwait(false);
                sharedSession = openedSession.Session;
                securityState = openedSession.SecurityState;

                var downlinkAuthority = ResolveAuthority(downlinkTarget.InternetStack, downlinkTarget.Options);
                var downlinkRequest = BuildStreamRequest(
                    downlinkTarget.InternetStack,
                    downlinkTarget.Options,
                    normalizedXPaddingOptions,
                    normalizedSessionPlacement,
                    normalizedSessionKey,
                    sessionId,
                    seqPlacement: string.Empty,
                    seqKey: string.Empty,
                    seqValue: null);
                var uploadAuthority = ResolveAuthority(internetStack, options);
                var uploadRequest = BuildStreamRequest(
                    internetStack,
                    options,
                    normalizedXPaddingOptions,
                    normalizedSessionPlacement,
                    normalizedSessionKey,
                    sessionId,
                    seqPlacement: string.Empty,
                    seqKey: string.Empty,
                    seqValue: null);

                downlinkStream = await sharedSession
                    .OpenHttpRequestStreamAsync(
                        "GET",
                        downlinkAuthority,
                        ResolveHttpScheme(downlinkTarget.InternetStack),
                        downlinkRequest.RequestTarget,
                        CreateHttp2RequestHeaders(downlinkRequest.RequestHeaders, includeContentType: false),
                        Array.Empty<byte>(),
                        waitForSuccessfulStatus: false,
                        cancellationToken,
                        disposeSessionOnClose: false,
                        endRequestOnHeaders: true)
                    .ConfigureAwait(false);
                uploadStream = await sharedSession
                    .OpenHttpRequestStreamAsync(
                        normalizedMethod,
                        uploadAuthority,
                        ResolveHttpScheme(internetStack),
                        uploadRequest.RequestTarget,
                        CreateHttp2RequestHeaders(uploadRequest.RequestHeaders, includeContentType: !options.SplitHttpNoGrpcHeader),
                        Array.Empty<byte>(),
                        waitForSuccessfulStatus: false,
                        cancellationToken,
                        disposeSessionOnClose: false)
                    .ConfigureAwait(false);
                uploadStream = new SplitHttpResponseDrainingUploadStream(uploadStream);
            }
            else
            {
                if (IsExplicitHttp3Requested(downlinkTarget.InternetStack, downlinkTarget.Options))
                {
                    var openedDownlinkSession = await OpenHttp3SessionAsync(
                            downlinkTarget.Options,
                            downlinkTarget.InternetStack,
                            dnsResolver,
                            cancellationToken)
                        .ConfigureAwait(false);
                    downlinkSession = openedDownlinkSession.Session;
                    securityState = openedDownlinkSession.SecurityState;

                    var downlinkAuthority = ResolveAuthority(downlinkTarget.InternetStack, downlinkTarget.Options);
                    var downlinkRequest = BuildStreamRequest(
                        downlinkTarget.InternetStack,
                        downlinkTarget.Options,
                        normalizedXPaddingOptions,
                        normalizedSessionPlacement,
                        normalizedSessionKey,
                        sessionId,
                        seqPlacement: string.Empty,
                        seqKey: string.Empty,
                        seqValue: null);
                    downlinkStream = await downlinkSession
                        .OpenHttpRequestStreamAsync(
                            "GET",
                            downlinkAuthority,
                            ResolveHttpScheme(downlinkTarget.InternetStack),
                            downlinkRequest.RequestTarget,
                            CreateHttp2RequestHeaders(downlinkRequest.RequestHeaders, includeContentType: false),
                            Array.Empty<byte>(),
                            waitForSuccessfulStatus: false,
                            cancellationToken,
                            disposeSessionOnClose: false,
                            endRequestOnHeaders: true)
                        .ConfigureAwait(false);
                }
                else
                {
                    downlinkContext = await RuntimeGrpcClientConnector
                        .OpenSecuredTransportContextWithRetryAsync(
                            downlinkTarget.Options,
                            downlinkTarget.InternetStack,
                            internetProfile,
                            dnsResolver,
                            cancellationToken)
                        .ConfigureAwait(false);
                    securityState = CloneSecurityState(downlinkContext.SecurityState);

                    var downlinkAuthority = ResolveAuthority(downlinkTarget.InternetStack, downlinkTarget.Options);
                    var downlinkRequest = BuildStreamRequest(
                        downlinkTarget.InternetStack,
                        downlinkTarget.Options,
                        normalizedXPaddingOptions,
                        normalizedSessionPlacement,
                        normalizedSessionKey,
                        sessionId,
                        seqPlacement: string.Empty,
                        seqKey: string.Empty,
                        seqValue: null);
                    downlinkStream = await OpenDownlinkStreamAsync(
                            downlinkContext,
                            downlinkTarget.InternetStack,
                            downlinkAuthority,
                            downlinkRequest.RequestTarget,
                            downlinkRequest.RequestHeaders,
                            cancellationToken)
                        .ConfigureAwait(false);
                    downlinkContext.SecurityState.RemoteCertificate?.Dispose();
                    downlinkContext = null;
                }

                var openedUploadSession = await OpenHttp3SessionAsync(
                        options,
                        internetStack,
                        dnsResolver,
                        cancellationToken)
                    .ConfigureAwait(false);
                uploadSession = openedUploadSession.Session;

                var uploadAuthority = ResolveAuthority(internetStack, options);
                var uploadRequest = BuildStreamRequest(
                    internetStack,
                    options,
                    normalizedXPaddingOptions,
                    normalizedSessionPlacement,
                    normalizedSessionKey,
                    sessionId,
                    seqPlacement: string.Empty,
                    seqKey: string.Empty,
                    seqValue: null);
                uploadStream = await uploadSession
                    .OpenHttpRequestStreamAsync(
                        normalizedMethod,
                        uploadAuthority,
                        ResolveHttpScheme(internetStack),
                        uploadRequest.RequestTarget,
                        CreateHttp2RequestHeaders(uploadRequest.RequestHeaders, includeContentType: !options.SplitHttpNoGrpcHeader),
                        Array.Empty<byte>(),
                        waitForSuccessfulStatus: false,
                        cancellationToken,
                        disposeSessionOnClose: false)
                    .ConfigureAwait(false);
                uploadStream = new SplitHttpResponseDrainingUploadStream(uploadStream);
            }

            var duplexStream = new SplitHttpDuplexStream(
                downlinkStream ?? throw new InvalidOperationException("SplitHTTP HTTP/3 stream-up failed to open the downlink stream."),
                uploadStream ?? throw new InvalidOperationException("SplitHTTP HTTP/3 stream-up failed to open the upload stream."));
            var ownedStream = new SplitHttpOwnedStream(
                duplexStream,
                sharedSession is not null
                    ? new IAsyncDisposable[] { sharedSession }
                    : EnumerateOwners(downlinkSession, uploadSession).ToArray());

            var context = new RuntimeInternetConnectionContext(ownedStream);
            context.SetTransportStream(ownedStream, securityState: securityState);
            return context;
        }
        catch
        {
            if (uploadStream is not null)
            {
                await uploadStream.DisposeAsync().ConfigureAwait(false);
            }

            if (downlinkStream is not null &&
                !ReferenceEquals(downlinkStream, uploadStream))
            {
                await downlinkStream.DisposeAsync().ConfigureAwait(false);
            }

            if (sharedSession is not null)
            {
                await sharedSession.DisposeAsync().ConfigureAwait(false);
            }

            if (uploadSession is not null)
            {
                await uploadSession.DisposeAsync().ConfigureAwait(false);
            }

            if (downlinkSession is not null)
            {
                await downlinkSession.DisposeAsync().ConfigureAwait(false);
            }

            if (downlinkContext is not null)
            {
                await RuntimeGrpcClientConnector.DisposeTransportContextAsync(downlinkContext).ConfigureAwait(false);
            }

            throw;
        }
    }

    private static async ValueTask<RuntimeInternetConnectionContext> OpenHttp3PacketUpAsync<TOptions>(
        TOptions options,
        RuntimeInternetStack internetStack,
        SplitHttpDownlinkTarget downlinkTarget,
        RuntimeInternetProfile internetProfile,
        IDnsResolver dnsResolver,
        string normalizedMethod,
        string normalizedSessionPlacement,
        string normalizedSessionKey,
        string normalizedSeqPlacement,
        string normalizedSeqKey,
        string normalizedUplinkDataPlacement,
        string normalizedUplinkDataKey,
        RuntimeInt32Range normalizedUplinkChunkSize,
        RuntimeInt32Range normalizedScMaxEachPostBytes,
        RuntimeInt32Range normalizedScMinPostsIntervalMs,
        SplitHttpXPaddingRuntimeOptions normalizedXPaddingOptions,
        CancellationToken cancellationToken)
        where TOptions : class, IRuntimeGrpcClientDialOptions
    {
        var sessionId = Guid.NewGuid().ToString();
        RuntimeInternetConnectionContext? downlinkContext = null;
        RuntimeHttp3ClientSession? downlinkSession = null;
        SplitHttpPacketUploadStream<TOptions>? uploadStream = null;
        try
        {
            RuntimeInternetSecurityState securityState;
            Stream downlinkStream;
            var downlinkAuthority = ResolveAuthority(downlinkTarget.InternetStack, downlinkTarget.Options);
            var downlinkRequest = BuildStreamRequest(
                downlinkTarget.InternetStack,
                downlinkTarget.Options,
                normalizedXPaddingOptions,
                normalizedSessionPlacement,
                normalizedSessionKey,
                sessionId,
                seqPlacement: string.Empty,
                seqKey: string.Empty,
                seqValue: null);

            if (IsExplicitHttp3Requested(downlinkTarget.InternetStack, downlinkTarget.Options))
            {
                var openedDownlinkSession = await OpenHttp3SessionAsync(
                        downlinkTarget.Options,
                        downlinkTarget.InternetStack,
                        dnsResolver,
                        cancellationToken)
                    .ConfigureAwait(false);
                downlinkSession = openedDownlinkSession.Session;
                securityState = openedDownlinkSession.SecurityState;
                downlinkStream = await downlinkSession
                    .OpenHttpRequestStreamAsync(
                        "GET",
                        downlinkAuthority,
                        ResolveHttpScheme(downlinkTarget.InternetStack),
                        downlinkRequest.RequestTarget,
                        CreateHttp2RequestHeaders(downlinkRequest.RequestHeaders, includeContentType: false),
                        Array.Empty<byte>(),
                        waitForSuccessfulStatus: true,
                        cancellationToken,
                        disposeSessionOnClose: true,
                        endRequestOnHeaders: true)
                    .ConfigureAwait(false);
                downlinkSession = null;
            }
            else
            {
                downlinkContext = await RuntimeGrpcClientConnector
                    .OpenSecuredTransportContextWithRetryAsync(
                        downlinkTarget.Options,
                        downlinkTarget.InternetStack,
                        internetProfile,
                        dnsResolver,
                        cancellationToken)
                    .ConfigureAwait(false);
                securityState = CloneSecurityState(downlinkContext.SecurityState);
                downlinkStream = await OpenDownlinkStreamAsync(
                        downlinkContext,
                        downlinkTarget.InternetStack,
                        downlinkAuthority,
                        downlinkRequest.RequestTarget,
                        downlinkRequest.RequestHeaders,
                        cancellationToken)
                    .ConfigureAwait(false);
                downlinkContext.SecurityState.RemoteCertificate?.Dispose();
                downlinkContext = null;
            }

            var uploadAuthority = ResolveAuthority(internetStack, options);
            uploadStream = new SplitHttpPacketUploadStream<TOptions>(
                options,
                internetStack,
                internetProfile,
                dnsResolver,
                uploadAuthority,
                normalizedMethod,
                normalizedSessionPlacement,
                normalizedSessionKey,
                sessionId,
                normalizedSeqPlacement,
                normalizedSeqKey,
                normalizedUplinkDataPlacement,
                normalizedUplinkDataKey,
                normalizedUplinkChunkSize,
                normalizedScMaxEachPostBytes,
                normalizedScMinPostsIntervalMs,
                normalizedXPaddingOptions);

            var duplexStream = new SplitHttpDuplexStream(downlinkStream, uploadStream);
            uploadStream = null;

            var context = new RuntimeInternetConnectionContext(duplexStream);
            context.SetTransportStream(duplexStream, securityState: securityState);
            return context;
        }
        catch
        {
            if (uploadStream is not null)
            {
                await uploadStream.DisposeAsync().ConfigureAwait(false);
            }

            if (downlinkSession is not null)
            {
                await downlinkSession.DisposeAsync().ConfigureAwait(false);
            }

            if (downlinkContext is not null)
            {
                await RuntimeGrpcClientConnector.DisposeTransportContextAsync(downlinkContext).ConfigureAwait(false);
            }

            throw;
        }
    }

    private static IEnumerable<IAsyncDisposable> EnumerateOwners(params IAsyncDisposable?[] owners)
    {
        foreach (var owner in owners)
        {
            if (owner is not null)
            {
                yield return owner;
            }
        }
    }

    internal static IRuntimeGrpcClientDialOptions ResolveHttp3DialOptions(IRuntimeGrpcClientDialOptions options)
    {
        ArgumentNullException.ThrowIfNull(options);

        var normalizedXmux = NormalizeSplitHttpXmuxOptions(options.SplitHttpXmux);
        if (normalizedXmux.HKeepAlivePeriodSeconds <= 0 ||
            options.QuicOptions.KeepAlivePeriodSeconds > 0)
        {
            return options;
        }

        return new SplitHttpHttp3DialOptions(
            options,
            options.QuicOptions with
            {
                KeepAlivePeriodSeconds = normalizedXmux.HKeepAlivePeriodSeconds
            });
    }

    private static async ValueTask<RuntimeHttp3ClientSession> OpenHttp3SessionOnlyAsync(
        IRuntimeGrpcClientDialOptions options,
        RuntimeInternetStack internetStack,
        IDnsResolver dnsResolver,
        CancellationToken cancellationToken)
    {
        options = ResolveHttp3DialOptions(options);
        RuntimeQuicClientConnection? quicConnection = null;
        try
        {
            quicConnection = await RuntimeQuicClientConnectionFactory
                .OpenAsync(
                    options,
                    internetStack,
                    dnsResolver,
                    cancellationToken)
                .ConfigureAwait(false);
            var session = await RuntimeHttp3ClientSession
                .CreateAsync(quicConnection, cancellationToken)
                .ConfigureAwait(false);
            quicConnection = null;
            return session;
        }
        catch
        {
            if (quicConnection is not null)
            {
                await quicConnection.DisposeAsync().ConfigureAwait(false);
            }

            throw;
        }
    }

    private static async ValueTask<(RuntimeHttp3ClientSession Session, RuntimeInternetSecurityState SecurityState)> OpenHttp3SessionAsync(
        IRuntimeGrpcClientDialOptions options,
        RuntimeInternetStack internetStack,
        IDnsResolver dnsResolver,
        CancellationToken cancellationToken)
    {
        options = ResolveHttp3DialOptions(options);
        RuntimeQuicClientConnection? quicConnection = null;
        try
        {
            quicConnection = await RuntimeQuicClientConnectionFactory
                .OpenAsync(
                    options,
                    internetStack,
                    dnsResolver,
                    cancellationToken)
                .ConfigureAwait(false);
            var securityState = CloneSecurityState(quicConnection.SecurityState);
            var session = await RuntimeHttp3ClientSession
                .CreateAsync(quicConnection, cancellationToken)
                .ConfigureAwait(false);
            quicConnection = null;
            return (session, securityState);
        }
        catch
        {
            if (quicConnection is not null)
            {
                await quicConnection.DisposeAsync().ConfigureAwait(false);
            }

            throw;
        }
    }

    private static async ValueTask<Stream> OpenDownlinkStreamAsync(
        RuntimeInternetConnectionContext transportContext,
        RuntimeInternetStack internetStack,
        string authority,
        string requestTarget,
        IReadOnlyDictionary<string, string> requestHeaders,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(transportContext);

        if (ShouldUseHttp2(transportContext))
        {
            var session = await Http2TunnelSession
                .CreateAsync(transportContext.TransportStream, cancellationToken)
                .ConfigureAwait(false);
            return await session
                .OpenHttpRequestStreamAsync(
                    "GET",
                    authority,
                    ResolveHttpScheme(internetStack),
                    requestTarget,
                    CreateHttp2RequestHeaders(requestHeaders, includeContentType: false),
                    Array.Empty<byte>(),
                    waitForSuccessfulStatus: true,
                    cancellationToken,
                    disposeSessionOnClose: true,
                    endStreamOnHeaders: true)
            .ConfigureAwait(false);
        }

        var request = BuildGetRequest(authority, requestTarget, requestHeaders);
        await transportContext.TransportStream.WriteAsync(request, cancellationToken).ConfigureAwait(false);
        await transportContext.TransportStream.FlushAsync(cancellationToken).ConfigureAwait(false);

        var response = await ReadResponseAsync(
                transportContext.TransportStream,
                "Unexpected EOF during SplitHTTP downlink handshake.",
                cancellationToken)
            .ConfigureAwait(false);
        if (response.StatusCode != 200)
        {
            throw new IOException(
                $"SplitHTTP downlink responded with non-200 status: {response.StatusCode.ToString(CultureInfo.InvariantCulture)}.");
        }

        return CreateResponseBodyStream(transportContext.TransportStream, response.Headers);
    }

    private static async ValueTask<Stream> OpenDownlinkStreamAsync(
        Http2TunnelSession session,
        RuntimeInternetStack internetStack,
        string authority,
        string requestTarget,
        IReadOnlyDictionary<string, string> requestHeaders,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(session);

        return await session
            .OpenHttpRequestStreamAsync(
                "GET",
                authority,
                ResolveHttpScheme(internetStack),
                requestTarget,
                CreateHttp2RequestHeaders(requestHeaders, includeContentType: false),
                Array.Empty<byte>(),
                waitForSuccessfulStatus: true,
                cancellationToken,
                disposeSessionOnClose: false,
                endStreamOnHeaders: true)
            .ConfigureAwait(false);
    }

    private static async ValueTask<Stream> OpenBrowserDownlinkStreamAsync(
        IRuntimeInternetBrowserDialer browserDialer,
        RuntimeInternetStack internetStack,
        string authority,
        string requestTarget,
        IReadOnlyDictionary<string, string> requestHeaders,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(browserDialer);

        return await browserDialer
            .OpenStreamAsync(
                new RuntimeInternetBrowserStreamRequest(
                    BuildRequestUrl(internetStack, authority, requestTarget),
                    CreateEffectiveRequestHeaders(requestHeaders, includeContentType: false)),
                cancellationToken)
            .ConfigureAwait(false);
    }

    private static async ValueTask<Stream> OpenUploadStreamAsync(
        RuntimeInternetConnectionContext transportContext,
        RuntimeInternetStack internetStack,
        string method,
        string authority,
        string requestTarget,
        IReadOnlyDictionary<string, string> requestHeaders,
        bool noGrpcHeader,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(transportContext);

        if (ShouldUseHttp2(transportContext))
        {
            var session = await Http2TunnelSession
                .CreateAsync(transportContext.TransportStream, cancellationToken)
                .ConfigureAwait(false);
            var uploadStream = await session
                .OpenHttpRequestStreamAsync(
                    method,
                    authority,
                    ResolveHttpScheme(internetStack),
                    requestTarget,
                    CreateHttp2RequestHeaders(requestHeaders, includeContentType: !noGrpcHeader),
                    Array.Empty<byte>(),
                    waitForSuccessfulStatus: false,
                    cancellationToken,
                    disposeSessionOnClose: true)
                .ConfigureAwait(false);
            return new SplitHttpResponseDrainingUploadStream(uploadStream);
        }

        var request = BuildStreamUploadRequest(method, authority, requestTarget, requestHeaders, noGrpcHeader);
        await transportContext.TransportStream.WriteAsync(request, cancellationToken).ConfigureAwait(false);
        await transportContext.TransportStream.FlushAsync(cancellationToken).ConfigureAwait(false);
        return new Http11ChunkedUploadStream(transportContext.TransportStream);
    }

    private static async ValueTask<Stream> OpenUploadStreamAsync(
        Http2TunnelSession session,
        RuntimeInternetStack internetStack,
        string method,
        string authority,
        string requestTarget,
        IReadOnlyDictionary<string, string> requestHeaders,
        bool noGrpcHeader,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(session);

        var uploadStream = await session
            .OpenHttpRequestStreamAsync(
                method,
                authority,
                ResolveHttpScheme(internetStack),
                requestTarget,
                CreateHttp2RequestHeaders(requestHeaders, includeContentType: !noGrpcHeader),
                Array.Empty<byte>(),
                waitForSuccessfulStatus: false,
                cancellationToken,
                disposeSessionOnClose: false)
            .ConfigureAwait(false);
        return new SplitHttpResponseDrainingUploadStream(uploadStream);
    }

    private static async ValueTask<Stream> OpenStreamOneStreamAsync(
        RuntimeInternetConnectionContext transportContext,
        RuntimeInternetStack internetStack,
        string method,
        string authority,
        string requestTarget,
        IReadOnlyDictionary<string, string> requestHeaders,
        bool noGrpcHeader,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(transportContext);

        if (ShouldUseHttp2(transportContext))
        {
            var session = await Http2TunnelSession
                .CreateAsync(transportContext.TransportStream, cancellationToken)
                .ConfigureAwait(false);
            return await session
                .OpenHttpRequestStreamAsync(
                    method,
                    authority,
                    ResolveHttpScheme(internetStack),
                    requestTarget,
                    CreateHttp2RequestHeaders(requestHeaders, includeContentType: !noGrpcHeader),
                    Array.Empty<byte>(),
                    waitForSuccessfulStatus: false,
                    cancellationToken,
                    disposeSessionOnClose: true)
                .ConfigureAwait(false);
        }

        var request = BuildStreamUploadRequest(method, authority, requestTarget, requestHeaders, noGrpcHeader);
        await transportContext.TransportStream.WriteAsync(request, cancellationToken).ConfigureAwait(false);
        await transportContext.TransportStream.FlushAsync(cancellationToken).ConfigureAwait(false);
        return new Http11ChunkedStreamOneDuplexStream(transportContext.TransportStream);
    }

    private static byte[] BuildGetRequest(
        string authority,
        string requestTarget,
        IReadOnlyDictionary<string, string> requestHeaders)
    {
        var builder = new StringBuilder(512);
        builder.Append("GET ");
        builder.Append(requestTarget);
        builder.Append(" HTTP/1.1\r\n");
        builder.Append("Host: ");
        builder.Append(authority);
        builder.Append("\r\n");
        AppendHeaders(builder, requestHeaders, includeContentType: false);
        builder.Append("\r\n");
        return Encoding.ASCII.GetBytes(builder.ToString());
    }

    private static byte[] BuildStreamUploadRequest(
        string method,
        string authority,
        string requestTarget,
        IReadOnlyDictionary<string, string> requestHeaders,
        bool noGrpcHeader)
    {
        var builder = new StringBuilder(512);
        builder.Append(method);
        builder.Append(' ');
        builder.Append(requestTarget);
        builder.Append(" HTTP/1.1\r\n");
        builder.Append("Host: ");
        builder.Append(authority);
        builder.Append("\r\n");
        builder.Append("Transfer-Encoding: chunked\r\n");
        AppendHeaders(builder, requestHeaders, includeContentType: !noGrpcHeader);
        builder.Append("\r\n");
        return Encoding.ASCII.GetBytes(builder.ToString());
    }

    private static byte[] BuildPacketRequest(
        string method,
        string authority,
        string requestTarget,
        IReadOnlyDictionary<string, string> requestHeaders,
        int payloadLength)
    {
        var builder = new StringBuilder(512);
        builder.Append(method);
        builder.Append(' ');
        builder.Append(requestTarget);
        builder.Append(" HTTP/1.1\r\n");
        builder.Append("Host: ");
        builder.Append(authority);
        builder.Append("\r\n");
        builder.Append("Content-Length: ");
        builder.Append(payloadLength.ToString(CultureInfo.InvariantCulture));
        builder.Append("\r\n");
        AppendHeaders(builder, requestHeaders, includeContentType: false);
        builder.Append("\r\n");
        return Encoding.ASCII.GetBytes(builder.ToString());
    }

    private static void AppendHeaders(
        StringBuilder builder,
        IReadOnlyDictionary<string, string> requestHeaders,
        bool includeContentType)
    {
        foreach (var (name, value) in CreateEffectiveRequestHeaders(requestHeaders, includeContentType))
        {
            builder.Append(name);
            builder.Append(": ");
            builder.Append(value);
            builder.Append("\r\n");
        }
    }

    private static Dictionary<string, string> CreateEffectiveRequestHeaders(
        IReadOnlyDictionary<string, string> requestHeaders,
        bool includeContentType)
    {
        var headers = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        var wroteUserAgent = false;
        var wroteAcceptEncoding = false;
        var wroteContentType = false;

        foreach (var (name, value) in requestHeaders)
        {
            if (string.IsNullOrWhiteSpace(name) ||
                string.IsNullOrWhiteSpace(value))
            {
                continue;
            }

            if (string.Equals(name, "Host", StringComparison.OrdinalIgnoreCase) ||
                string.Equals(name, "Transfer-Encoding", StringComparison.OrdinalIgnoreCase) ||
                string.Equals(name, "Content-Length", StringComparison.OrdinalIgnoreCase) ||
                string.Equals(name, "Connection", StringComparison.OrdinalIgnoreCase))
            {
                continue;
            }

            if (string.Equals(name, "User-Agent", StringComparison.OrdinalIgnoreCase))
            {
                wroteUserAgent = true;
            }
            else if (string.Equals(name, "Accept-Encoding", StringComparison.OrdinalIgnoreCase))
            {
                wroteAcceptEncoding = true;
            }
            else if (string.Equals(name, "Content-Type", StringComparison.OrdinalIgnoreCase))
            {
                wroteContentType = true;
            }

            headers[name.Trim()] = value.Trim();
        }

        if (!wroteUserAgent)
        {
            headers["User-Agent"] = RuntimeInternetHttpUtilities.DefaultChromeUserAgent;
        }

        if (!wroteAcceptEncoding)
        {
            headers["Accept-Encoding"] = "identity";
        }

        if (includeContentType && !wroteContentType)
        {
            headers["Content-Type"] = "application/grpc";
        }

        return headers;
    }

    private static Dictionary<string, string> CreateHttp2RequestHeaders(
        IReadOnlyDictionary<string, string> requestHeaders,
        bool includeContentType)
    {
        var normalizedHeaders = BuildRequestHeaders(requestHeaders);
        if (!normalizedHeaders.ContainsKey("User-Agent"))
        {
            normalizedHeaders["User-Agent"] = RuntimeInternetHttpUtilities.DefaultChromeUserAgent;
        }

        if (!normalizedHeaders.ContainsKey("Accept-Encoding"))
        {
            normalizedHeaders["Accept-Encoding"] = "identity";
        }

        if (includeContentType &&
            !normalizedHeaders.ContainsKey("Content-Type"))
        {
            normalizedHeaders["Content-Type"] = "application/grpc";
        }

        return normalizedHeaders;
    }

    private static bool ShouldUseHttp2(RuntimeInternetConnectionContext transportContext)
        => string.Equals(transportContext.NegotiatedApplicationProtocol, "h2", StringComparison.OrdinalIgnoreCase);

    private static bool IsExplicitHttp11Requested(IRuntimeInternetOptions options)
        => options.ApplicationProtocols.Count == 1 &&
           string.Equals(options.ApplicationProtocols[0], "http/1.1", StringComparison.OrdinalIgnoreCase);

    private static bool IsExplicitHttp3Requested(
        RuntimeInternetStack internetStack,
        IRuntimeInternetOptions options)
        => string.Equals(internetStack.SecurityType, RuntimeInternetSecurityTypes.Tls, StringComparison.Ordinal) &&
           options.ApplicationProtocols.Count == 1 &&
           string.Equals(options.ApplicationProtocols[0], "h3", StringComparison.OrdinalIgnoreCase);

    private static string ResolveHttpScheme(RuntimeInternetStack internetStack)
        => RuntimeInternetSecurityTypes.IsSecure(internetStack.SecurityType) ? "https" : "http";

    private static Stream CreateResponseBodyStream(
        Stream transportStream,
        IReadOnlyDictionary<string, string> responseHeaders)
    {
        if (responseHeaders.TryGetValue("Transfer-Encoding", out var transferEncoding) &&
            transferEncoding.Contains("chunked", StringComparison.OrdinalIgnoreCase))
        {
            return new Http11ChunkedReadStream(transportStream);
        }

        if (responseHeaders.TryGetValue("Content-Length", out var contentLengthText) &&
            long.TryParse(contentLengthText, NumberStyles.Integer, CultureInfo.InvariantCulture, out var contentLength) &&
            contentLength >= 0)
        {
            return new Http11ContentLengthReadStream(transportStream, contentLength);
        }

        return transportStream;
    }

    private static async ValueTask<Http11Response> ReadResponseAsync(
        Stream transportStream,
        string eofMessage,
        CancellationToken cancellationToken)
    {
        var statusLine = await RuntimeInternetHttpUtilities
            .ReadHttpLineAsync(transportStream, eofMessage, cancellationToken)
            .ConfigureAwait(false);
        if (!TryParseStatusCode(statusLine, out var statusCode))
        {
            throw new InvalidDataException($"SplitHTTP returned an invalid response status line: {statusLine}.");
        }

        var headers = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        while (true)
        {
            var line = await RuntimeInternetHttpUtilities
                .ReadHttpLineAsync(transportStream, eofMessage, cancellationToken)
                .ConfigureAwait(false);
            if (line.Length == 0)
            {
                break;
            }

            var separator = line.IndexOf(':');
            if (separator <= 0)
            {
                continue;
            }

            headers[line[..separator].Trim()] = line[(separator + 1)..].Trim();
        }

        return new Http11Response(statusCode, headers);
    }

    private static Dictionary<string, string> BuildRequestHeaders(
        IReadOnlyDictionary<string, string> sourceHeaders)
    {
        var headers = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        if (sourceHeaders is null)
        {
            return headers;
        }

        foreach (var (name, value) in sourceHeaders)
        {
            if (string.IsNullOrWhiteSpace(name) || string.IsNullOrWhiteSpace(value))
            {
                continue;
            }

            headers[name.Trim()] = value.Trim();
        }

        return headers;
    }

    private static SplitHttpRequestComposition BuildStreamRequest(
        RuntimeInternetStack internetStack,
        IRuntimeInternetOptions options,
        SplitHttpXPaddingRuntimeOptions xPaddingOptions,
        string sessionPlacement,
        string sessionKey,
        string sessionId,
        string seqPlacement,
        string seqKey,
        string? seqValue)
    {
        var requestTarget = RuntimeSplitHttpRequestMetadata.NormalizePath(options.SplitHttpPath);
        var requestHeaders = BuildRequestHeaders(options.SplitHttpHeaders);
        ApplyXPaddingToRequest(internetStack, options, xPaddingOptions, ref requestTarget, requestHeaders);
        RuntimeSplitHttpRequestMetadata.ApplyToRequest(
            ref requestTarget,
            requestHeaders,
            sessionPlacement,
            sessionKey,
            sessionId,
            seqPlacement,
            seqKey,
            seqValue);
        return new SplitHttpRequestComposition(requestTarget, requestHeaders);
    }

    private static void ApplyXPaddingToRequest(
        RuntimeInternetStack internetStack,
        IRuntimeInternetOptions options,
        SplitHttpXPaddingRuntimeOptions xPaddingOptions,
        ref string requestTarget,
        Dictionary<string, string> requestHeaders)
    {
        var paddingLength = GetRandomRangeValue(xPaddingOptions.Bytes);
        if (paddingLength <= 0)
        {
            return;
        }

        var placement = xPaddingOptions.ObfsMode
            ? xPaddingOptions.Placement
            : DefaultXPaddingPlacement;
        var key = xPaddingOptions.ObfsMode
            ? xPaddingOptions.Key
            : DefaultXPaddingKey;
        var header = xPaddingOptions.ObfsMode
            ? xPaddingOptions.Header
            : DefaultNonObfsXPaddingHeader;
        var method = xPaddingOptions.ObfsMode
            ? xPaddingOptions.Method
            : DefaultXPaddingMethod;
        var paddingValue = GenerateXPadding(method, paddingLength);

        switch (placement)
        {
            case "header":
                requestHeaders[header] = paddingValue;
                break;
            case "cookie":
                requestHeaders["Cookie"] = AppendCookie(
                    requestHeaders.TryGetValue("Cookie", out var existingCookie) ? existingCookie : string.Empty,
                    key,
                    paddingValue);
                break;
            case "query":
                requestTarget = SetTargetQueryParameter(requestTarget, key, paddingValue);
                break;
            case "queryInHeader":
                requestHeaders[header] = BuildAbsoluteUrlWithSingleQuery(
                    internetStack,
                    options,
                    requestTarget,
                    key,
                    paddingValue);
                break;
            default:
                throw new NotSupportedException("Unsupported SplitHTTP padding placement: " + placement);
        }
    }

    private static string NormalizeMode(string value)
        => string.IsNullOrWhiteSpace(value)
            ? "auto"
            : value.Trim().ToLowerInvariant() switch
            {
                "auto" => "auto",
                "stream-up" => "stream-up",
                "stream-one" => "stream-one",
                "packet-up" => "packet-up",
                _ => value.Trim().ToLowerInvariant()
            };

    private static string ResolveEffectiveMode(
        string configuredMode,
        RuntimeInternetStack internetStack,
        bool hasDedicatedDownloadSettings)
    {
        if (!string.Equals(configuredMode, "auto", StringComparison.Ordinal))
        {
            return configuredMode;
        }

        return string.Equals(internetStack.SecurityType, RuntimeInternetSecurityTypes.Reality, StringComparison.Ordinal)
            ? hasDedicatedDownloadSettings ? "stream-up" : "stream-one"
            : "packet-up";
    }

    private static SplitHttpDownlinkTarget ResolveDownlinkTarget<TOptions>(
        TOptions options,
        RuntimeInternetStack internetStack)
        where TOptions : class, IRuntimeGrpcClientDialOptions
    {
        if (options.SplitHttpDownloadSettings is null)
        {
            return new SplitHttpDownlinkTarget(options, internetStack, false);
        }

        var downlinkSecurityType = string.IsNullOrWhiteSpace(options.SplitHttpDownloadSettings.TransportSecurity)
            ? internetStack.SecurityType
            : RuntimeInternetSecurityTypes.Normalize(options.SplitHttpDownloadSettings.TransportSecurity);
        return new SplitHttpDownlinkTarget(
            new SplitHttpDownloadDialOptions<TOptions>(options),
            RuntimeInternetStack.Create(RuntimeInternetTransportProtocols.SplitHttp, downlinkSecurityType),
            true);
    }

    private static string NormalizeUplinkHttpMethod(string value)
        => string.IsNullOrWhiteSpace(value) ? "POST" : value.Trim().ToUpperInvariant();

    internal static RuntimeInt32Range NormalizeScMaxEachPostBytes(RuntimeInt32Range? value)
    {
        if (value is null || GetRangeMaximum(value) == 0)
        {
            return new RuntimeInt32Range
            {
                From = DefaultScMaxEachPostBytes,
                To = DefaultScMaxEachPostBytes
            };
        }

        return new RuntimeInt32Range
        {
            From = value.From,
            To = value.To
        };
    }

    internal static RuntimeInt32Range NormalizeScMinPostsIntervalMs(RuntimeInt32Range? value)
    {
        if (value is null || GetRangeMaximum(value) == 0)
        {
            return new RuntimeInt32Range
            {
                From = DefaultScMinPostsIntervalMs,
                To = DefaultScMinPostsIntervalMs
            };
        }

        return new RuntimeInt32Range
        {
            From = value.From,
            To = value.To
        };
    }

    internal static RuntimeInt32Range NormalizeUplinkChunkSize(
        RuntimeInt32Range? value,
        string uplinkDataPlacement,
        RuntimeInt32Range normalizedScMaxEachPostBytes)
    {
        if (value is null || GetRangeMaximum(value) == 0)
        {
            return NormalizeUplinkDataPlacement(uplinkDataPlacement) switch
            {
                "cookie" => new RuntimeInt32Range
                {
                    From = DefaultCookiePayloadChunkCharactersFrom,
                    To = DefaultCookiePayloadChunkCharactersTo
                },
                "header" => new RuntimeInt32Range
                {
                    From = DefaultHeaderPayloadChunkCharactersFrom,
                    To = DefaultHeaderPayloadChunkCharactersTo
                },
                _ => normalizedScMaxEachPostBytes
            };
        }

        if (GetRangeMinimum(value) < MinimumUplinkChunkCharacters)
        {
            return new RuntimeInt32Range
            {
                From = MinimumUplinkChunkCharacters,
                To = Math.Max(MinimumUplinkChunkCharacters, GetRangeMaximum(value))
            };
        }

        return new RuntimeInt32Range
        {
            From = value.From,
            To = value.To
        };
    }

    private static SplitHttpXPaddingRuntimeOptions NormalizeXPaddingOptions(IRuntimeInternetOptions options)
    {
        ArgumentNullException.ThrowIfNull(options);

        return new SplitHttpXPaddingRuntimeOptions(
            NormalizeXPaddingBytes(options.SplitHttpXPaddingBytes),
            options.SplitHttpXPaddingObfsMode,
            NormalizeXPaddingKey(options.SplitHttpXPaddingKey),
            NormalizeXPaddingHeader(options.SplitHttpXPaddingHeader),
            NormalizeXPaddingPlacement(options.SplitHttpXPaddingPlacement),
            NormalizeXPaddingMethod(options.SplitHttpXPaddingMethod));
    }

    private static RuntimeInt32Range NormalizeXPaddingBytes(RuntimeInt32Range value)
    {
        if (value.To <= 0)
        {
            if (value.From != 0)
            {
                throw new InvalidOperationException("SplitHTTP xPaddingBytes cannot be disabled.");
            }

            return new RuntimeInt32Range
            {
                From = DefaultXPaddingBytesFrom,
                To = DefaultXPaddingBytesTo
            };
        }

        if (value.From <= 0)
        {
            throw new InvalidOperationException("SplitHTTP xPaddingBytes cannot be disabled.");
        }

        var from = value.From;
        var to = value.To;
        if (to < from)
        {
            (from, to) = (to, from);
        }

        return new RuntimeInt32Range
        {
            From = from,
            To = to
        };
    }

    private static string NormalizeXPaddingKey(string value)
        => string.IsNullOrWhiteSpace(value) ? DefaultXPaddingKey : value.Trim();

    private static string NormalizeXPaddingHeader(string value)
        => string.IsNullOrWhiteSpace(value) ? DefaultXPaddingHeader : value.Trim();

    private static string NormalizeXPaddingPlacement(string value)
        => string.IsNullOrWhiteSpace(value)
            ? DefaultXPaddingPlacement
            : value.Trim().ToLowerInvariant() switch
            {
                "cookie" => "cookie",
                "header" => "header",
                "query" => "query",
                "queryinheader" => "queryInHeader",
                _ => throw new NotSupportedException("Unsupported SplitHTTP padding placement: " + value.Trim())
            };

    private static string NormalizeXPaddingMethod(string value)
        => string.IsNullOrWhiteSpace(value)
            ? DefaultXPaddingMethod
            : value.Trim().ToLowerInvariant() switch
            {
                "repeat-x" => "repeat-x",
                "tokenish" => "tokenish",
                _ => throw new NotSupportedException("Unsupported SplitHTTP padding method: " + value.Trim())
            };

    private static string NormalizeUplinkDataPlacement(string value)
        => string.IsNullOrWhiteSpace(value)
            ? "auto"
            : value.Trim().ToLowerInvariant() switch
            {
                "auto" => "auto",
                "body" => "body",
                "header" => "header",
                "cookie" => "cookie",
                _ => throw new NotSupportedException("Unsupported SplitHTTP uplink data placement: " + value.Trim())
            };

    internal static bool ShouldDelayPacketUploads(RuntimeInt32Range range)
        => GetRangeMinimum(range) > 0;

    private static string ResolveUplinkDataKey(string placement, string configuredKey)
    {
        if (!string.IsNullOrWhiteSpace(configuredKey))
        {
            return configuredKey.Trim();
        }

        return NormalizeUplinkDataPlacement(placement) switch
        {
            "cookie" => "x_data",
            "auto" or "header" => "X-Data",
            _ => string.Empty
        };
    }

    private static ReadOnlyMemory<byte> PreparePacketPayload(
        Dictionary<string, string> requestHeaders,
        string uplinkDataPlacement,
        string uplinkDataKey,
        RuntimeInt32Range uplinkChunkSize,
        ReadOnlyMemory<byte> payload)
    {
        switch (NormalizeUplinkDataPlacement(uplinkDataPlacement))
        {
            case "header":
                AddHeaderPayload(requestHeaders, uplinkDataKey, uplinkChunkSize, payload);
                return ReadOnlyMemory<byte>.Empty;
            case "cookie":
                AddCookiePayload(requestHeaders, uplinkDataKey, uplinkChunkSize, payload);
                return ReadOnlyMemory<byte>.Empty;
            default:
                return payload;
        }
    }

    private static void AddHeaderPayload(
        Dictionary<string, string> requestHeaders,
        string key,
        RuntimeInt32Range uplinkChunkSize,
        ReadOnlyMemory<byte> payload)
    {
        if (payload.IsEmpty || string.IsNullOrWhiteSpace(key))
        {
            return;
        }

        var encodedPayload = EncodeBase64Url(payload);
        for (int offset = 0, index = 0; offset < encodedPayload.Length; index++)
        {
            var length = Math.Min(GetRandomRangeValue(uplinkChunkSize), encodedPayload.Length - offset);
            requestHeaders[$"{key}-{index.ToString(CultureInfo.InvariantCulture)}"] =
                encodedPayload.Substring(offset, length);
            offset += length;
        }
    }

    private static void AddCookiePayload(
        Dictionary<string, string> requestHeaders,
        string key,
        RuntimeInt32Range uplinkChunkSize,
        ReadOnlyMemory<byte> payload)
    {
        if (payload.IsEmpty || string.IsNullOrWhiteSpace(key))
        {
            return;
        }

        requestHeaders.TryGetValue("Cookie", out var existingCookie);
        var encodedPayload = EncodeBase64Url(payload);
        for (int offset = 0, index = 0; offset < encodedPayload.Length; index++)
        {
            var length = Math.Min(GetRandomRangeValue(uplinkChunkSize), encodedPayload.Length - offset);
            existingCookie = AppendCookie(
                existingCookie ?? string.Empty,
                $"{key}_{index.ToString(CultureInfo.InvariantCulture)}",
                encodedPayload.Substring(offset, length));
            offset += length;
        }

        requestHeaders["Cookie"] = existingCookie ?? string.Empty;
    }

    private static string EncodeBase64Url(ReadOnlyMemory<byte> payload)
        => Convert
            .ToBase64String(payload.ToArray())
            .TrimEnd('=')
            .Replace('+', '-')
            .Replace('/', '_');

    private static string GenerateXPadding(string method, int length)
    {
        if (length <= 0)
        {
            return string.Empty;
        }

        if (!string.Equals(method, "tokenish", StringComparison.Ordinal))
        {
            return new string('X', length);
        }

        var tokenishPadding = GenerateTokenishPadding(length);
        return tokenishPadding.Length == 0
            ? new string('X', length)
            : tokenishPadding;
    }

    private static string GenerateTokenishPadding(int targetHuffmanBytes)
    {
        var characterCount = Math.Max(
            1,
            (int)Math.Ceiling(targetHuffmanBytes / TokenishAverageHuffmanBytesPerCharBase62));
        string randomBase62;
        try
        {
            randomBase62 = GenerateRandomBase62String(characterCount);
        }
        catch (CryptographicException)
        {
            return string.Empty;
        }

        var builder = new StringBuilder(randomBase62);
        var adjustChar = 'X';
        for (var iteration = 0; iteration < TokenishMaxIterations; iteration++)
        {
            var currentLength = RuntimeHpackHuffman.GetBase62EncodedLength(builder.ToString());
            var diff = currentLength - targetHuffmanBytes;
            if (Math.Abs(diff) <= TokenishValidationTolerance)
            {
                return builder.ToString();
            }

            if (diff < 0)
            {
                builder.Append(adjustChar);
                adjustChar = adjustChar == 'X' ? 'Z' : 'X';
                continue;
            }

            if (builder.Length <= 1)
            {
                return builder.ToString();
            }

            builder.Length--;
        }

        return builder.ToString();
    }

    private static string GenerateRandomBase62String(int characterCount)
    {
        var buffer = new char[characterCount];
        for (var index = 0; index < buffer.Length; index++)
        {
            buffer[index] = XPaddingBase62Charset[RandomNumberGenerator.GetInt32(XPaddingBase62Charset.Length)];
        }

        return new string(buffer);
    }

    internal static int GetRandomRangeValue(RuntimeInt32Range range)
    {
        var from = range.From;
        var to = range.To;
        if (from == to)
        {
            return from;
        }

        if (from > to)
        {
            (from, to) = (to, from);
        }

        return Random.Shared.Next(from, to);
    }

    internal static int GetBufferedUploadByteLimit(int maxUploadSize)
        => Math.Max(0, maxUploadSize - UploadPipeSegmentSize);

    private static int GetRangeMinimum(RuntimeInt32Range range)
        => Math.Min(range.From, range.To);

    private static int GetRangeMaximum(RuntimeInt32Range range)
        => Math.Max(range.From, range.To);

    private static string AppendPathSegment(string path, string value)
    {
        if (!path.EndsWith("/", StringComparison.Ordinal))
        {
            path += "/";
        }

        return path + Uri.EscapeDataString(value);
    }

    private static string SetQueryParameter(string query, string key, string value)
    {
        if (string.IsNullOrWhiteSpace(key))
        {
            return query;
        }

        var encodedKey = Uri.EscapeDataString(key);
        var encodedValue = Uri.EscapeDataString(value);
        var segments = query.Length == 0
            ? new List<string>()
            : query
                .Split('&', StringSplitOptions.RemoveEmptyEntries)
                .Where(segment =>
                {
                    var separator = segment.IndexOf('=');
                    var currentKey = separator >= 0 ? segment[..separator] : segment;
                    return !string.Equals(currentKey, encodedKey, StringComparison.Ordinal);
                })
                .ToList();
        segments.Add(encodedKey + "=" + encodedValue);
        return string.Join("&", segments);
    }

    private static string SetTargetQueryParameter(string requestTarget, string key, string value)
    {
        var querySeparator = requestTarget.IndexOf('?');
        var path = querySeparator >= 0 ? requestTarget[..querySeparator] : requestTarget;
        var query = querySeparator >= 0 ? requestTarget[(querySeparator + 1)..] : string.Empty;
        query = SetQueryParameter(query, key, value);
        return query.Length == 0 ? path : path + "?" + query;
    }

    private static string BuildAbsoluteUrlWithSingleQuery(
        RuntimeInternetStack internetStack,
        IRuntimeInternetOptions options,
        string requestTarget,
        string key,
        string value)
    {
        var querySeparator = requestTarget.IndexOf('?');
        var path = querySeparator >= 0 ? requestTarget[..querySeparator] : requestTarget;
        var scheme = RuntimeInternetSecurityTypes.IsSecure(internetStack.SecurityType) ? "https" : "http";
        return scheme +
               "://" +
               ResolveAuthority(internetStack, options) +
               path +
               "?" +
               Uri.EscapeDataString(key) +
               "=" +
               Uri.EscapeDataString(value);
    }

    private static string BuildRequestUrl(
        RuntimeInternetStack internetStack,
        string authority,
        string requestTarget)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(authority);

        if (!requestTarget.StartsWith("/", StringComparison.Ordinal))
        {
            requestTarget = "/" + requestTarget;
        }

        return ResolveHttpScheme(internetStack) +
               "://" +
               NormalizeAuthorityForUri(authority) +
               requestTarget;
    }

    private static string NormalizeAuthorityForUri(string authority)
    {
        var normalized = authority.Trim();
        if (normalized.StartsWith("[", StringComparison.Ordinal))
        {
            return normalized;
        }

        var firstColon = normalized.IndexOf(':');
        if (firstColon < 0)
        {
            return normalized;
        }

        var lastColon = normalized.LastIndexOf(':');
        if (firstColon == lastColon)
        {
            return normalized;
        }

        if (lastColon > 0 &&
            normalized.IndexOf(':') < lastColon &&
            int.TryParse(
                normalized[(lastColon + 1)..],
                NumberStyles.Integer,
                CultureInfo.InvariantCulture,
                out _))
        {
            return "[" + normalized[..lastColon] + "]:" + normalized[(lastColon + 1)..];
        }

        return "[" + normalized + "]";
    }

    private static string AppendCookie(string existingCookie, string key, string value)
        => string.IsNullOrWhiteSpace(existingCookie)
            ? key + "=" + value
            : existingCookie.Trim() + "; " + key + "=" + value;

    private static string ResolveAuthority(
        RuntimeInternetStack stack,
        IRuntimeInternetOptions options)
    {
        if (!string.IsNullOrWhiteSpace(options.SplitHttpHost))
        {
            return options.SplitHttpHost.Trim();
        }

        if (RuntimeInternetSecurityTypes.IsSecure(stack.SecurityType) &&
            !string.IsNullOrWhiteSpace(options.ServerName))
        {
            return options.ServerName.Trim();
        }

        return options.ServerHost.Trim();
    }

    private static IRuntimeInternetBrowserDialer? ResolveBrowserDialer(
        RuntimeInternetProfile internetProfile,
        RuntimeInternetStack internetStack)
        => string.Equals(internetStack.SecurityType, RuntimeInternetSecurityTypes.Reality, StringComparison.Ordinal)
            ? null
            : internetProfile.BrowserDialer;

    private sealed record SplitHttpRequestComposition(
        string RequestTarget,
        Dictionary<string, string> RequestHeaders);

    private sealed record SplitHttpPacketUploadRequest(
        string Method,
        string Authority,
        string RequestTarget,
        Dictionary<string, string> RequestHeaders,
        ReadOnlyMemory<byte> RequestBody);

    private sealed record SplitHttpXPaddingRuntimeOptions(
        RuntimeInt32Range Bytes,
        bool ObfsMode,
        string Key,
        string Header,
        string Placement,
        string Method);

    private sealed record SplitHttpDownlinkTarget(
        IRuntimeGrpcClientDialOptions Options,
        RuntimeInternetStack InternetStack,
        bool HasDedicatedDownloadSettings);

    private sealed class SplitHttpDownloadDialOptions<TOptions> : IRuntimeGrpcClientDialOptions, IRuntimeTlsSessionResumptionOptions
        where TOptions : class, IRuntimeGrpcClientDialOptions
    {
        private readonly TOptions _outerOptions;
        private readonly RuntimeSplitHttpDownloadOptions _settings;

        public SplitHttpDownloadDialOptions(TOptions outerOptions)
        {
            _outerOptions = outerOptions ?? throw new ArgumentNullException(nameof(outerOptions));
            _settings = outerOptions.SplitHttpDownloadSettings
                ?? throw new ArgumentException("SplitHTTP downloadSettings are not configured.", nameof(outerOptions));
        }

        public DispatchContext DialContext => _outerOptions.DialContext;

        public EndPoint? SourceEndPoint => _outerOptions.SourceEndPoint;

        public EndPoint? LocalEndPoint => _outerOptions.LocalEndPoint;

        public string Via => _outerOptions.Via;

        public string ViaCidr => _outerOptions.ViaCidr;

        public string ServerHost => string.IsNullOrWhiteSpace(_settings.ServerHost)
            ? _outerOptions.ServerHost
            : _settings.ServerHost.Trim();

        public int ServerPort => _settings.ServerPort ?? _outerOptions.ServerPort;

        public string ServerName => _settings.ServerName is null ? _outerOptions.ServerName : _settings.ServerName.Trim();

        public string Fingerprint => _settings.Fingerprint is null ? _outerOptions.Fingerprint : _settings.Fingerprint.Trim();

        public string TransportProtocol => RuntimeInternetTransportProtocols.SplitHttp;

        public string SecurityType => RuntimeInternetSecurityTypes.Normalize(_settings.TransportSecurity ?? _outerOptions.SecurityType);

        public RuntimeRealityOptions RealityOptions => _settings.RealityOptions ?? _outerOptions.RealityOptions;

        public string WebSocketPath => _outerOptions.WebSocketPath;

        public IReadOnlyDictionary<string, string> WebSocketHeaders => _outerOptions.WebSocketHeaders;

        public int WebSocketEarlyDataBytes => _outerOptions.WebSocketEarlyDataBytes;

        public int WebSocketHeartbeatPeriodSeconds => _outerOptions.WebSocketHeartbeatPeriodSeconds;

        public string SplitHttpHost => _settings.Host is null ? _outerOptions.SplitHttpHost : _settings.Host.Trim();

        public string SplitHttpPath => _settings.Path ?? _outerOptions.SplitHttpPath;

        public IReadOnlyDictionary<string, string> SplitHttpHeaders => _settings.Headers ?? _outerOptions.SplitHttpHeaders;

        public string SplitHttpMode => _outerOptions.SplitHttpMode;

        public bool SplitHttpNoGrpcHeader => _outerOptions.SplitHttpNoGrpcHeader;

        public RuntimeInt32Range SplitHttpXPaddingBytes => _outerOptions.SplitHttpXPaddingBytes;

        public bool SplitHttpXPaddingObfsMode => _outerOptions.SplitHttpXPaddingObfsMode;

        public string SplitHttpXPaddingKey => _outerOptions.SplitHttpXPaddingKey;

        public string SplitHttpXPaddingHeader => _outerOptions.SplitHttpXPaddingHeader;

        public string SplitHttpXPaddingPlacement => _outerOptions.SplitHttpXPaddingPlacement;

        public string SplitHttpXPaddingMethod => _outerOptions.SplitHttpXPaddingMethod;

        public string SplitHttpUplinkHttpMethod => _outerOptions.SplitHttpUplinkHttpMethod;

        public string SplitHttpSessionPlacement => _outerOptions.SplitHttpSessionPlacement;

        public string SplitHttpSessionKey => _outerOptions.SplitHttpSessionKey;

        public string SplitHttpSeqPlacement => _outerOptions.SplitHttpSeqPlacement;

        public string SplitHttpSeqKey => _outerOptions.SplitHttpSeqKey;

        public string SplitHttpUplinkDataPlacement => _outerOptions.SplitHttpUplinkDataPlacement;

        public string SplitHttpUplinkDataKey => _outerOptions.SplitHttpUplinkDataKey;

        public RuntimeInt32Range SplitHttpUplinkChunkSize => _outerOptions.SplitHttpUplinkChunkSize;

        public RuntimeInt32Range SplitHttpScMaxEachPostBytes => _outerOptions.SplitHttpScMaxEachPostBytes;

        public RuntimeInt32Range SplitHttpScMinPostsIntervalMs => _outerOptions.SplitHttpScMinPostsIntervalMs;

        public int SplitHttpScMaxBufferedPosts => _outerOptions.SplitHttpScMaxBufferedPosts;

        public RuntimeSplitHttpXmuxOptions SplitHttpXmux => _outerOptions.SplitHttpXmux;

        public RuntimeSplitHttpDownloadOptions? SplitHttpDownloadSettings => _settings;

        public IReadOnlyList<string> ApplicationProtocols => _outerOptions.ApplicationProtocols;

        public RuntimeQuicOptions QuicOptions => _outerOptions.QuicOptions;

        public string GrpcServiceName => _outerOptions.GrpcServiceName;

        public string GrpcAuthority => _outerOptions.GrpcAuthority;

        public bool GrpcMultiMode => _outerOptions.GrpcMultiMode;

        public string GrpcUserAgent => _outerOptions.GrpcUserAgent;

        public int GrpcIdleTimeoutSeconds => _outerOptions.GrpcIdleTimeoutSeconds;

        public int GrpcHealthCheckTimeoutSeconds => _outerOptions.GrpcHealthCheckTimeoutSeconds;

        public bool GrpcPermitWithoutStream => _outerOptions.GrpcPermitWithoutStream;

        public int GrpcInitialWindowSize => _outerOptions.GrpcInitialWindowSize;

        public bool SkipCertificateValidation => _settings.SkipCertificateValidation ?? _outerOptions.SkipCertificateValidation;

        public RemoteCertificateValidationCallback? CertificateValidationCallback => _outerOptions.CertificateValidationCallback;

        public SslProtocols EnabledSslProtocols => _outerOptions.EnabledSslProtocols;

        public IRuntimeRealityHandshakeProvider? RealityHandshakeProvider => _outerOptions.RealityHandshakeProvider;

        public int ConnectTimeoutSeconds => _settings.ConnectTimeoutSeconds ?? _outerOptions.ConnectTimeoutSeconds;

        public int HandshakeTimeoutSeconds => _settings.HandshakeTimeoutSeconds ?? _outerOptions.HandshakeTimeoutSeconds;

        public bool EnableTlsSessionResumption => _outerOptions is IRuntimeTlsSessionResumptionOptions accessor &&
                                                  accessor.EnableTlsSessionResumption;

        public Func<CancellationToken, ValueTask<Stream>>? TransportStreamFactory
        {
            get
            {
                if (_outerOptions.SplitHttpDownloadTransportStreamFactory is not null)
                {
                    return _outerOptions.SplitHttpDownloadTransportStreamFactory;
                }

                if (_outerOptions.TransportStreamFactory is null)
                {
                    return null;
                }

                if (string.Equals(ServerHost, _outerOptions.ServerHost, StringComparison.OrdinalIgnoreCase) &&
                    ServerPort == _outerOptions.ServerPort)
                {
                    return _outerOptions.TransportStreamFactory;
                }

                throw new NotSupportedException(
                    "SplitHTTP downloadSettings that override serverHost/serverPort require SplitHttpDownloadTransportStreamFactory when a custom TransportStreamFactory is used.");
            }
        }

        public Func<CancellationToken, ValueTask<Stream>>? SplitHttpDownloadTransportStreamFactory => null;
    }

    private static RuntimeInternetSecurityState CloneSecurityState(RuntimeInternetSecurityState state)
        => state with
        {
            RemoteCertificate = CloneCertificate(state.RemoteCertificate)
        };

    private static RuntimeInternetSecurityState CreateBrowserDialerSecurityState(RuntimeInternetStack stack)
        => RuntimeInternetSecurityTypes.IsSecure(stack.SecurityType)
            ? RuntimeInternetSecurityState.Create(stack.SecurityType, SslProtocols.None)
            : RuntimeInternetSecurityState.None;

    private static X509Certificate2? CloneCertificate(X509Certificate2? certificate)
        => certificate is null ? null : new X509Certificate2(certificate);

    private static bool TryParseStatusCode(string statusLine, out int statusCode)
    {
        statusCode = 0;
        if (string.IsNullOrWhiteSpace(statusLine) ||
            !statusLine.StartsWith("HTTP/", StringComparison.OrdinalIgnoreCase))
        {
            return false;
        }

        var firstSpace = statusLine.IndexOf(' ');
        if (firstSpace <= 0 || firstSpace == statusLine.Length - 1)
        {
            return false;
        }

        var secondSpace = statusLine.IndexOf(' ', firstSpace + 1);
        var codeText = secondSpace > firstSpace
            ? statusLine.Substring(firstSpace + 1, secondSpace - firstSpace - 1)
            : statusLine[(firstSpace + 1)..];
        return int.TryParse(codeText, NumberStyles.Integer, CultureInfo.InvariantCulture, out statusCode);
    }

    private static async ValueTask ReadExactAsync(
        Stream stream,
        Memory<byte> buffer,
        CancellationToken cancellationToken)
    {
        var read = 0;
        while (read < buffer.Length)
        {
            var current = await stream.ReadAsync(buffer[read..], cancellationToken).ConfigureAwait(false);
            if (current == 0)
            {
                throw new EndOfStreamException("Unexpected EOF while reading SplitHTTP payload.");
            }

            read += current;
        }
    }

    private sealed class SplitHttpHttp3DialOptions : IRuntimeGrpcClientDialOptions, IRuntimeTlsSessionResumptionOptions
    {
        private readonly IRuntimeGrpcClientDialOptions _innerOptions;

        public SplitHttpHttp3DialOptions(
            IRuntimeGrpcClientDialOptions innerOptions,
            RuntimeQuicOptions quicOptions)
        {
            _innerOptions = innerOptions ?? throw new ArgumentNullException(nameof(innerOptions));
            QuicOptions = quicOptions ?? throw new ArgumentNullException(nameof(quicOptions));
        }

        public DispatchContext DialContext => _innerOptions.DialContext;

        public EndPoint? SourceEndPoint => _innerOptions.SourceEndPoint;

        public EndPoint? LocalEndPoint => _innerOptions.LocalEndPoint;

        public string Via => _innerOptions.Via;

        public string ViaCidr => _innerOptions.ViaCidr;

        public string ServerHost => _innerOptions.ServerHost;

        public int ServerPort => _innerOptions.ServerPort;

        public string ServerName => _innerOptions.ServerName;

        public string Fingerprint => _innerOptions.Fingerprint;

        public string TransportProtocol => _innerOptions.TransportProtocol;

        public string SecurityType => _innerOptions.SecurityType;

        public RuntimeRealityOptions RealityOptions => _innerOptions.RealityOptions;

        public string WebSocketPath => _innerOptions.WebSocketPath;

        public IReadOnlyDictionary<string, string> WebSocketHeaders => _innerOptions.WebSocketHeaders;

        public int WebSocketEarlyDataBytes => _innerOptions.WebSocketEarlyDataBytes;

        public int WebSocketHeartbeatPeriodSeconds => _innerOptions.WebSocketHeartbeatPeriodSeconds;

        public string SplitHttpHost => _innerOptions.SplitHttpHost;

        public string SplitHttpPath => _innerOptions.SplitHttpPath;

        public IReadOnlyDictionary<string, string> SplitHttpHeaders => _innerOptions.SplitHttpHeaders;

        public string SplitHttpMode => _innerOptions.SplitHttpMode;

        public bool SplitHttpNoGrpcHeader => _innerOptions.SplitHttpNoGrpcHeader;

        public RuntimeInt32Range SplitHttpXPaddingBytes => _innerOptions.SplitHttpXPaddingBytes;

        public bool SplitHttpXPaddingObfsMode => _innerOptions.SplitHttpXPaddingObfsMode;

        public string SplitHttpXPaddingKey => _innerOptions.SplitHttpXPaddingKey;

        public string SplitHttpXPaddingHeader => _innerOptions.SplitHttpXPaddingHeader;

        public string SplitHttpXPaddingPlacement => _innerOptions.SplitHttpXPaddingPlacement;

        public string SplitHttpXPaddingMethod => _innerOptions.SplitHttpXPaddingMethod;

        public string SplitHttpUplinkHttpMethod => _innerOptions.SplitHttpUplinkHttpMethod;

        public string SplitHttpSessionPlacement => _innerOptions.SplitHttpSessionPlacement;

        public string SplitHttpSessionKey => _innerOptions.SplitHttpSessionKey;

        public string SplitHttpSeqPlacement => _innerOptions.SplitHttpSeqPlacement;

        public string SplitHttpSeqKey => _innerOptions.SplitHttpSeqKey;

        public string SplitHttpUplinkDataPlacement => _innerOptions.SplitHttpUplinkDataPlacement;

        public string SplitHttpUplinkDataKey => _innerOptions.SplitHttpUplinkDataKey;

        public RuntimeInt32Range SplitHttpUplinkChunkSize => _innerOptions.SplitHttpUplinkChunkSize;

        public RuntimeInt32Range SplitHttpScMaxEachPostBytes => _innerOptions.SplitHttpScMaxEachPostBytes;

        public RuntimeInt32Range SplitHttpScMinPostsIntervalMs => _innerOptions.SplitHttpScMinPostsIntervalMs;

        public int SplitHttpScMaxBufferedPosts => _innerOptions.SplitHttpScMaxBufferedPosts;

        public RuntimeSplitHttpXmuxOptions SplitHttpXmux => _innerOptions.SplitHttpXmux;

        public RuntimeSplitHttpDownloadOptions? SplitHttpDownloadSettings => _innerOptions.SplitHttpDownloadSettings;

        public IReadOnlyList<string> ApplicationProtocols => _innerOptions.ApplicationProtocols;

        public RuntimeQuicOptions QuicOptions { get; }

        public string GrpcServiceName => _innerOptions.GrpcServiceName;

        public string GrpcAuthority => _innerOptions.GrpcAuthority;

        public bool GrpcMultiMode => _innerOptions.GrpcMultiMode;

        public string GrpcUserAgent => _innerOptions.GrpcUserAgent;

        public int GrpcIdleTimeoutSeconds => _innerOptions.GrpcIdleTimeoutSeconds;

        public int GrpcHealthCheckTimeoutSeconds => _innerOptions.GrpcHealthCheckTimeoutSeconds;

        public bool GrpcPermitWithoutStream => _innerOptions.GrpcPermitWithoutStream;

        public int GrpcInitialWindowSize => _innerOptions.GrpcInitialWindowSize;

        public bool SkipCertificateValidation => _innerOptions.SkipCertificateValidation;

        public RemoteCertificateValidationCallback? CertificateValidationCallback => _innerOptions.CertificateValidationCallback;

        public SslProtocols EnabledSslProtocols => _innerOptions.EnabledSslProtocols;

        public IRuntimeRealityHandshakeProvider? RealityHandshakeProvider => _innerOptions.RealityHandshakeProvider;

        public int ConnectTimeoutSeconds => _innerOptions.ConnectTimeoutSeconds;

        public int HandshakeTimeoutSeconds => _innerOptions.HandshakeTimeoutSeconds;

        public bool EnableTlsSessionResumption => _innerOptions is IRuntimeTlsSessionResumptionOptions accessor &&
                                                  accessor.EnableTlsSessionResumption;

        public Func<CancellationToken, ValueTask<Stream>>? TransportStreamFactory => _innerOptions.TransportStreamFactory;

        public Func<CancellationToken, ValueTask<Stream>>? SplitHttpDownloadTransportStreamFactory
            => _innerOptions.SplitHttpDownloadTransportStreamFactory;
    }

    private static SplitHttpPacketUploadRequest BuildPacketUploadRequest(
        string method,
        string authority,
        RuntimeInternetStack internetStack,
        IRuntimeInternetOptions options,
        SplitHttpXPaddingRuntimeOptions xPaddingOptions,
        string sessionPlacement,
        string sessionKey,
        string sessionId,
        string seqPlacement,
        string seqKey,
        string uplinkDataPlacement,
        string uplinkDataKey,
        RuntimeInt32Range uplinkChunkSize,
        long sequence,
        ReadOnlyMemory<byte> payload)
    {
        var seqValue = sequence.ToString(CultureInfo.InvariantCulture);
        var requestTarget = RuntimeSplitHttpRequestMetadata.NormalizePath(options.SplitHttpPath);
        var requestHeaders = BuildRequestHeaders(options.SplitHttpHeaders);
        var requestBody = PreparePacketPayload(
            requestHeaders,
            uplinkDataPlacement,
            uplinkDataKey,
            uplinkChunkSize,
            payload);
        ApplyXPaddingToRequest(internetStack, options, xPaddingOptions, ref requestTarget, requestHeaders);
        RuntimeSplitHttpRequestMetadata.ApplyToRequest(
            ref requestTarget,
            requestHeaders,
            sessionPlacement,
            sessionKey,
            sessionId,
            seqPlacement,
            seqKey,
            seqValue);
        return new SplitHttpPacketUploadRequest(
            method,
            authority,
            requestTarget,
            requestHeaders,
            requestBody);
    }

    private static async ValueTask<RuntimeInternetConnectionContext> OpenPacketUploadContextAsync<TOptions>(
        TOptions options,
        RuntimeInternetStack internetStack,
        RuntimeInternetProfile internetProfile,
        IDnsResolver dnsResolver,
        CancellationToken cancellationToken)
        where TOptions : class, IRuntimeGrpcClientDialOptions
        => await RuntimeGrpcClientConnector
            .OpenSecuredTransportContextWithRetryAsync(
                options,
                internetStack,
                internetProfile,
                dnsResolver,
                cancellationToken)
            .ConfigureAwait(false);

    private static async ValueTask<bool> SendPacketRequestAsync(
        RuntimeInternetConnectionContext uploadContext,
        RuntimeInternetStack internetStack,
        SplitHttpPacketUploadRequest request,
        Http2TunnelSessionOptions http2SessionOptions,
        CancellationToken cancellationToken)
    {
        if (ShouldUseHttp2(uploadContext))
        {
            Http2TunnelSession? session = null;
            try
            {
                session = await Http2TunnelSession
                    .CreateAsync(
                        uploadContext.TransportStream,
                        cancellationToken,
                        http2SessionOptions)
                    .ConfigureAwait(false);
                await SendPacketRequestAsync(
                        session,
                        internetStack,
                        request,
                        cancellationToken)
                    .ConfigureAwait(false);
                return false;
            }
            catch (Exception ex) when (IsPacketUploadConnectionFailure(ex, cancellationToken))
            {
                throw new PacketUploadConnectionException("Failed to send SplitHTTP packet upload request over HTTP/2.", ex);
            }
            finally
            {
                if (session is not null)
                {
                    try
                    {
                        await session.DisposeAsync().ConfigureAwait(false);
                    }
                    catch
                    {
                    }
                }
            }
        }

        var requestBytes = BuildPacketRequest(
            request.Method,
            request.Authority,
            request.RequestTarget,
            request.RequestHeaders,
            request.RequestBody.Length);

        try
        {
            await uploadContext.TransportStream.WriteAsync(requestBytes, cancellationToken).ConfigureAwait(false);
            if (!request.RequestBody.IsEmpty)
            {
                await uploadContext.TransportStream.WriteAsync(request.RequestBody, cancellationToken).ConfigureAwait(false);
            }

            await uploadContext.TransportStream.FlushAsync(cancellationToken).ConfigureAwait(false);
        }
        catch (Exception ex) when (IsPacketUploadConnectionFailure(ex, cancellationToken))
        {
            throw new PacketUploadConnectionException("Failed to write SplitHTTP packet upload request.", ex);
        }

        Http11Response response;
        try
        {
            response = await ReadResponseAsync(
                    uploadContext.TransportStream,
                    "Unexpected EOF during SplitHTTP packet upload handshake.",
                    cancellationToken)
                .ConfigureAwait(false);
        }
        catch (Exception ex) when (IsPacketUploadConnectionFailure(ex, cancellationToken))
        {
            throw new PacketUploadConnectionException("Failed to read SplitHTTP packet upload response.", ex);
        }

        if (response.StatusCode != 200)
        {
            throw new IOException(
                $"SplitHTTP packet upload responded with non-200 status: {response.StatusCode.ToString(CultureInfo.InvariantCulture)}.");
        }

        var responseBody = CreateResponseBodyStream(uploadContext.TransportStream, response.Headers);
        try
        {
            await responseBody.CopyToAsync(Stream.Null, cancellationToken).ConfigureAwait(false);
        }
        catch (Exception ex) when (IsPacketUploadConnectionFailure(ex, cancellationToken))
        {
            throw new PacketUploadConnectionException("Failed to drain SplitHTTP packet upload response body.", ex);
        }

        return CanReusePacketUploadConnection(response.Headers);
    }

    private static async ValueTask SendPacketRequestAsync(
        Http2TunnelSession session,
        RuntimeInternetStack internetStack,
        SplitHttpPacketUploadRequest request,
        CancellationToken cancellationToken)
    {
        await using var pendingRequest = await StartPacketRequestAsync(
                session,
                internetStack,
                request,
                cancellationToken)
            .ConfigureAwait(false);

        await pendingRequest.DrainResponseAsync(cancellationToken).ConfigureAwait(false);
    }

    private static async ValueTask<Http2TunnelSession.PendingRequest> StartPacketRequestAsync(
        Http2TunnelSession session,
        RuntimeInternetStack internetStack,
        SplitHttpPacketUploadRequest request,
        CancellationToken cancellationToken)
        => await session
            .StartHttpRequestAsync(
                request.Method,
                request.Authority,
                ResolveHttpScheme(internetStack),
                request.RequestTarget,
                CreateHttp2RequestHeaders(request.RequestHeaders, includeContentType: false),
                request.RequestBody.ToArray(),
                cancellationToken,
                disposeSessionOnClose: false,
                endStreamOnHeaders: request.RequestBody.IsEmpty,
                completeRequestAfterInitialPayload: !request.RequestBody.IsEmpty)
            .ConfigureAwait(false);

    private static async ValueTask SendPacketRequestAsync(
        RuntimeHttp3ClientSession session,
        RuntimeInternetStack internetStack,
        SplitHttpPacketUploadRequest request,
        CancellationToken cancellationToken)
    {
        await using var pendingRequest = await StartPacketRequestAsync(
                session,
                internetStack,
                request,
                cancellationToken)
            .ConfigureAwait(false);

        await pendingRequest.DrainResponseAsync(cancellationToken).ConfigureAwait(false);
    }

    private static async ValueTask<RuntimeHttp3ClientSession.PendingRequest> StartPacketRequestAsync(
        RuntimeHttp3ClientSession session,
        RuntimeInternetStack internetStack,
        SplitHttpPacketUploadRequest request,
        CancellationToken cancellationToken)
        => await session
            .StartHttpRequestAsync(
                request.Method,
                request.Authority,
                ResolveHttpScheme(internetStack),
                request.RequestTarget,
                CreateHttp2RequestHeaders(request.RequestHeaders, includeContentType: false),
                request.RequestBody.ToArray(),
                cancellationToken,
                disposeSessionOnClose: false,
                endRequestOnHeaders: request.RequestBody.IsEmpty,
                completeRequestAfterInitialPayload: !request.RequestBody.IsEmpty)
            .ConfigureAwait(false);

    private static bool CanReusePacketUploadConnection(IReadOnlyDictionary<string, string> responseHeaders)
    {
        if (responseHeaders.TryGetValue("Connection", out var connectionValue) &&
            connectionValue.Contains("close", StringComparison.OrdinalIgnoreCase))
        {
            return false;
        }

        if (responseHeaders.TryGetValue("Transfer-Encoding", out var transferEncoding) &&
            transferEncoding.Contains("chunked", StringComparison.OrdinalIgnoreCase))
        {
            return true;
        }

        return responseHeaders.TryGetValue("Content-Length", out var contentLengthText) &&
               long.TryParse(contentLengthText, NumberStyles.Integer, CultureInfo.InvariantCulture, out var contentLength) &&
               contentLength >= 0;
    }

    private static bool IsPacketUploadConnectionFailure(Exception exception, CancellationToken cancellationToken)
        => !cancellationToken.IsCancellationRequested &&
           exception is IOException or EndOfStreamException or InvalidDataException or ObjectDisposedException;

    private sealed class SplitHttpHttp11UploadConnection : IAsyncDisposable
    {
        private readonly RuntimeInternetConnectionContext _context;
        private readonly SemaphoreSlim _writeLock = new(1, 1);
        private readonly object _responseLock = new();
        private Task _responseTail = Task.CompletedTask;
        private Exception? _terminalException;
        private int _acceptRequests = 1;
        private int _disposed;

        public SplitHttpHttp11UploadConnection(RuntimeInternetConnectionContext context)
        {
            _context = context ?? throw new ArgumentNullException(nameof(context));
        }

        public bool CanAcceptRequests
            => Volatile.Read(ref _disposed) == 0 &&
               Volatile.Read(ref _acceptRequests) != 0 &&
               _terminalException is null;

        public async ValueTask<Task> StartSendAsync(
            SplitHttpPacketUploadRequest request,
            CancellationToken cancellationToken)
        {
            ArgumentNullException.ThrowIfNull(request);

            var requestBytes = BuildPacketRequest(
                request.Method,
                request.Authority,
                request.RequestTarget,
                request.RequestHeaders,
                request.RequestBody.Length);

            await _writeLock.WaitAsync(cancellationToken).ConfigureAwait(false);
            try
            {
                ThrowIfWriteUnavailable();

                try
                {
                    await _context.TransportStream.WriteAsync(requestBytes, cancellationToken).ConfigureAwait(false);
                    if (!request.RequestBody.IsEmpty)
                    {
                        await _context.TransportStream.WriteAsync(request.RequestBody, cancellationToken).ConfigureAwait(false);
                    }

                    await _context.TransportStream.FlushAsync(cancellationToken).ConfigureAwait(false);
                }
                catch (Exception ex) when (IsPacketUploadConnectionFailure(ex, cancellationToken))
                {
                    var wrapped = new PacketUploadConnectionException("Failed to write SplitHTTP packet upload request.", ex);
                    SetTerminalException(wrapped);
                    throw wrapped;
                }

                return QueueResponseDrain();
            }
            finally
            {
                _writeLock.Release();
            }
        }

        public async ValueTask DisposeAsync()
        {
            if (Interlocked.Exchange(ref _disposed, 1) != 0)
            {
                return;
            }

            try
            {
                await RuntimeGrpcClientConnector.DisposeTransportContextAsync(_context).ConfigureAwait(false);
            }
            finally
            {
                _writeLock.Dispose();
            }
        }

        public void DisposeWhenResponseCompletes()
        {
            Task responseTail;
            lock (_responseLock)
            {
                responseTail = _responseTail;
            }

            _ = DisposeWhenResponseCompletesCoreAsync(responseTail);
        }

        private Task QueueResponseDrain()
        {
            lock (_responseLock)
            {
                ThrowIfDisposedOrFaulted();
                _responseTail = DrainQueuedResponseAsync(_responseTail);
                return _responseTail;
            }
        }

        private async Task DrainQueuedResponseAsync(Task previousResponseTask)
        {
            await previousResponseTask.ConfigureAwait(false);
            await DrainSingleResponseAsync().ConfigureAwait(false);
        }

        private async Task DisposeWhenResponseCompletesCoreAsync(Task responseTail)
        {
            try
            {
                await responseTail.ConfigureAwait(false);
            }
            catch
            {
            }

            await DisposeAsync().ConfigureAwait(false);
        }

        private async Task DrainSingleResponseAsync()
        {
            Http11Response response;
            try
            {
                response = await ReadResponseAsync(
                        _context.TransportStream,
                        "Unexpected EOF during SplitHTTP packet upload handshake.",
                        CancellationToken.None)
                    .ConfigureAwait(false);
            }
            catch (Exception ex) when (IsPacketUploadConnectionFailure(ex, CancellationToken.None))
            {
                var wrapped = new PacketUploadConnectionException("Failed to read SplitHTTP packet upload response.", ex);
                SetTerminalException(wrapped);
                throw wrapped;
            }

            if (response.StatusCode != 200)
            {
                var exception = new IOException(
                    $"SplitHTTP packet upload responded with non-200 status: {response.StatusCode.ToString(CultureInfo.InvariantCulture)}.");
                SetTerminalException(exception);
                throw exception;
            }

            var responseBody = CreateResponseBodyStream(_context.TransportStream, response.Headers);
            try
            {
                await responseBody.CopyToAsync(Stream.Null, CancellationToken.None).ConfigureAwait(false);
            }
            catch (Exception ex) when (IsPacketUploadConnectionFailure(ex, CancellationToken.None))
            {
                var wrapped = new PacketUploadConnectionException("Failed to drain SplitHTTP packet upload response body.", ex);
                SetTerminalException(wrapped);
                throw wrapped;
            }

            if (!CanReusePacketUploadConnection(response.Headers))
            {
                Interlocked.Exchange(ref _acceptRequests, 0);
            }
        }

        private void ThrowIfWriteUnavailable()
        {
            ThrowIfDisposedOrFaulted();
            if (Volatile.Read(ref _acceptRequests) == 0)
            {
                throw new IOException("SplitHTTP packet upload connection can no longer accept requests.");
            }
        }

        private void ThrowIfDisposedOrFaulted()
        {
            ObjectDisposedException.ThrowIf(Volatile.Read(ref _disposed) != 0, this);
            if (_terminalException is not null)
            {
                ExceptionDispatchInfo.Capture(_terminalException).Throw();
            }
        }

        private void SetTerminalException(Exception exception)
        {
            ArgumentNullException.ThrowIfNull(exception);
            Interlocked.CompareExchange(ref _terminalException, exception, null);
            Interlocked.Exchange(ref _acceptRequests, 0);
        }
    }

    private static SplitHttpSharedUploadPoolManager? TryGetSharedUploadPoolManager<TOptions>(
        TOptions options,
        RuntimeInternetStack internetStack,
        RuntimeInternetProfile internetProfile,
        IDnsResolver dnsResolver)
        where TOptions : class, IRuntimeGrpcClientDialOptions
    {
        if (!TryCreateSharedUploadPoolKey(
                options,
                internetStack,
                internetProfile,
                dnsResolver,
                out var key))
        {
            return null;
        }

        return SharedUploadPools.GetOrAdd(
            key,
            static currentKey => new SplitHttpSharedUploadPoolManager(currentKey.SplitHttpXmux));
    }

    private static SplitHttpHttp2UploadPoolManager? TryGetSharedHttp2UploadPoolManager<TOptions>(
        TOptions options,
        RuntimeInternetStack internetStack,
        RuntimeInternetProfile internetProfile,
        IDnsResolver dnsResolver)
        where TOptions : class, IRuntimeGrpcClientDialOptions
    {
        if (!PrefersHttp2Transport(internetStack, options) ||
            !TryCreateSharedUploadPoolKey(
                options,
                internetStack,
                internetProfile,
                dnsResolver,
                out var key))
        {
            return null;
        }

        return SharedHttp2UploadPools.GetOrAdd(
            key,
            static currentKey => new SplitHttpHttp2UploadPoolManager(currentKey.SplitHttpXmux));
    }

    private static SplitHttpHttp3UploadPoolManager? TryGetSharedHttp3PoolManager<TOptions>(
        TOptions options,
        RuntimeInternetStack internetStack,
        RuntimeInternetProfile internetProfile,
        IDnsResolver dnsResolver)
        where TOptions : class, IRuntimeGrpcClientDialOptions
    {
        if (!PrefersHttp3Transport(internetStack, options) ||
            !TryCreateSharedUploadPoolKey(
                options,
                internetStack,
                internetProfile,
                dnsResolver,
                out var key))
        {
            return null;
        }

        return SharedHttp3UploadPools.GetOrAdd(
            key,
            static currentKey => new SplitHttpHttp3UploadPoolManager(currentKey.SplitHttpXmux));
    }

    private static bool PrefersHttp2Transport(
        RuntimeInternetStack internetStack,
        IRuntimeInternetOptions options)
    {
        if (string.Equals(internetStack.SecurityType, RuntimeInternetSecurityTypes.Reality, StringComparison.Ordinal))
        {
            return true;
        }

        if (!RuntimeInternetSecurityTypes.UsesTlsLikeSemantics(internetStack.SecurityType) ||
            IsExplicitHttp3Requested(internetStack, options) ||
            IsExplicitHttp11Requested(options))
        {
            return false;
        }

        return true;
    }

    private static bool PrefersHttp3Transport(
        RuntimeInternetStack internetStack,
        IRuntimeInternetOptions options)
        => IsExplicitHttp3Requested(internetStack, options);

    private static bool TryCreateSharedUploadPoolKey<TOptions>(
        TOptions options,
        RuntimeInternetStack internetStack,
        RuntimeInternetProfile internetProfile,
        IDnsResolver dnsResolver,
        out SplitHttpSharedUploadPoolKey key)
        where TOptions : class, IRuntimeGrpcClientDialOptions
    {
        if (options.TransportStreamFactory is not null ||
            options.CertificateValidationCallback is not null)
        {
            key = default!;
            return false;
        }

        var normalizedXmux = NormalizeSplitHttpXmuxOptions(options.SplitHttpXmux);
        var signature = string.Join(
            "|",
            internetStack.TransportProtocol,
            internetStack.SecurityType,
            options.ServerHost ?? string.Empty,
            options.ServerPort.ToString(CultureInfo.InvariantCulture),
            options.ServerName ?? string.Empty,
            options.Fingerprint ?? string.Empty,
            options.SplitHttpHost ?? string.Empty,
            options.SplitHttpPath ?? string.Empty,
            SerializeHeaders(options.SplitHttpHeaders),
            options.SplitHttpMode ?? string.Empty,
            options.SplitHttpNoGrpcHeader.ToString(),
            SerializeRange(options.SplitHttpXPaddingBytes),
            options.SplitHttpXPaddingObfsMode.ToString(),
            options.SplitHttpXPaddingKey ?? string.Empty,
            options.SplitHttpXPaddingHeader ?? string.Empty,
            options.SplitHttpXPaddingPlacement ?? string.Empty,
            options.SplitHttpXPaddingMethod ?? string.Empty,
            options.SplitHttpUplinkHttpMethod ?? string.Empty,
            options.SplitHttpSessionPlacement ?? string.Empty,
            options.SplitHttpSessionKey ?? string.Empty,
            options.SplitHttpSeqPlacement ?? string.Empty,
            options.SplitHttpSeqKey ?? string.Empty,
            options.SplitHttpUplinkDataPlacement ?? string.Empty,
            options.SplitHttpUplinkDataKey ?? string.Empty,
            SerializeRange(options.SplitHttpUplinkChunkSize),
            SerializeRange(options.SplitHttpScMaxEachPostBytes),
            SerializeRange(options.SplitHttpScMinPostsIntervalMs),
            SerializeStringList(options.ApplicationProtocols),
            options.ConnectTimeoutSeconds.ToString(CultureInfo.InvariantCulture),
            options.HandshakeTimeoutSeconds.ToString(CultureInfo.InvariantCulture),
            options.EnabledSslProtocols.ToString(),
            options.SkipCertificateValidation.ToString(),
            SerializeRealityOptions(options.RealityOptions),
            options.Via ?? string.Empty,
            options.ViaCidr ?? string.Empty,
            SerializeEndPoint(options.SourceEndPoint),
            SerializeEndPoint(options.LocalEndPoint));

        key = new SplitHttpSharedUploadPoolKey(internetProfile, dnsResolver, signature, normalizedXmux);
        return true;
    }

    private static string SerializeHeaders(IReadOnlyDictionary<string, string> headers)
        => headers is null
            ? string.Empty
            : string.Join(
                "\n",
                headers
                    .OrderBy(static pair => pair.Key, StringComparer.OrdinalIgnoreCase)
                    .Select(static pair => pair.Key + "=" + pair.Value));

    private static string SerializeStringList(IReadOnlyList<string> values)
        => values is null ? string.Empty : string.Join("\n", values);

    private static string SerializeRange(RuntimeInt32Range range)
        => string.Join(
            ",",
            range.From.ToString(CultureInfo.InvariantCulture),
            range.To.ToString(CultureInfo.InvariantCulture));

    private static RuntimeSplitHttpXmuxOptions NormalizeSplitHttpXmuxOptions(RuntimeSplitHttpXmuxOptions? value)
        => RuntimeSplitHttpXmuxNormalizer.NormalizeOrThrow(value);

    private static Http2TunnelSessionOptions CreateSplitHttpHttp2SessionOptions(RuntimeSplitHttpXmuxOptions xmux)
    {
        var normalizedXmux = NormalizeSplitHttpXmuxOptions(xmux);
        var keepAliveInterval = normalizedXmux.HKeepAlivePeriodSeconds > 0
            ? TimeSpan.FromSeconds(normalizedXmux.HKeepAlivePeriodSeconds)
            : TimeSpan.Zero;
        if (keepAliveInterval == TimeSpan.Zero)
        {
            return Http2TunnelSessionOptions.Default;
        }

        return new Http2TunnelSessionOptions
        {
            KeepAliveInterval = keepAliveInterval,
            PermitKeepAliveWithoutStreams = true
        };
    }

    private static string SerializeRealityOptions(RuntimeRealityOptions options)
    {
        var normalized = RuntimeRealityOptions.Normalize(options, applyRealityDefaults: true);
        return string.Join(
            "|",
            normalized.Show ? "1" : "0",
            normalized.MasterKeyLog,
            normalized.Fingerprint,
            normalized.PublicKey,
            normalized.ShortId,
            normalized.Mldsa65Verify,
            normalized.SpiderX,
            string.Join(",", normalized.SpiderY));
    }

    private static string SerializeEndPoint(EndPoint? endPoint)
        => endPoint is null
            ? string.Empty
            : string.Join(
                "|",
                endPoint.GetType().FullName ?? endPoint.GetType().Name,
                endPoint.ToString() ?? string.Empty);

    private sealed record Http11Response(
        int StatusCode,
        IReadOnlyDictionary<string, string> Headers);

    private sealed class PacketUploadConnectionException : IOException
    {
        public PacketUploadConnectionException(string message, Exception innerException)
            : base(message, innerException)
        {
        }
    }

    private sealed class Http11ChunkedReadStream : Stream
    {
        private readonly Stream _inner;
        private long _remainingInChunk;
        private bool _completed;

        public Http11ChunkedReadStream(Stream inner)
        {
            _inner = inner ?? throw new ArgumentNullException(nameof(inner));
        }

        public override bool CanRead => _inner.CanRead;

        public override bool CanSeek => false;

        public override bool CanWrite => false;

        public override long Length => throw new NotSupportedException();

        public override long Position
        {
            get => throw new NotSupportedException();
            set => throw new NotSupportedException();
        }

        public override bool CanTimeout => _inner.CanTimeout;

        public override int ReadTimeout
        {
            get => _inner.ReadTimeout;
            set => _inner.ReadTimeout = value;
        }

        public override int WriteTimeout
        {
            get => _inner.WriteTimeout;
            set => _inner.WriteTimeout = value;
        }

        public override void Flush() => throw new NotSupportedException();

        public override Task FlushAsync(CancellationToken cancellationToken) => Task.CompletedTask;

        public override int Read(byte[] buffer, int offset, int count)
            => ReadAsync(buffer.AsMemory(offset, count), CancellationToken.None).AsTask().GetAwaiter().GetResult();

        public override async ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken cancellationToken = default)
        {
            if (_completed || buffer.Length == 0)
            {
                return 0;
            }

            if (_remainingInChunk == 0)
            {
                var chunkHeader = await RuntimeInternetHttpUtilities
                    .ReadHttpLineAsync(_inner, "Unexpected EOF while reading SplitHTTP chunk header.", cancellationToken)
                    .ConfigureAwait(false);
                var separator = chunkHeader.IndexOf(';');
                var sizeText = separator >= 0 ? chunkHeader[..separator] : chunkHeader;
                if (!long.TryParse(sizeText.Trim(), NumberStyles.HexNumber, CultureInfo.InvariantCulture, out _remainingInChunk) ||
                    _remainingInChunk < 0)
                {
                    throw new InvalidDataException($"SplitHTTP returned an invalid chunk length: {chunkHeader}.");
                }

                if (_remainingInChunk == 0)
                {
                    while (true)
                    {
                        var trailerLine = await RuntimeInternetHttpUtilities
                            .ReadHttpLineAsync(_inner, "Unexpected EOF while reading SplitHTTP response trailers.", cancellationToken)
                            .ConfigureAwait(false);
                        if (trailerLine.Length == 0)
                        {
                            break;
                        }
                    }

                    _completed = true;
                    return 0;
                }
            }

            var readLength = (int)Math.Min(buffer.Length, _remainingInChunk);
            var read = await _inner.ReadAsync(buffer[..readLength], cancellationToken).ConfigureAwait(false);
            if (read == 0)
            {
                throw new EndOfStreamException("Unexpected EOF while reading SplitHTTP chunk payload.");
            }

            _remainingInChunk -= read;
            if (_remainingInChunk == 0)
            {
                var crlf = new byte[2];
                await ReadExactAsync(_inner, crlf, cancellationToken).ConfigureAwait(false);
                if (crlf[0] != '\r' || crlf[1] != '\n')
                {
                    throw new InvalidDataException("SplitHTTP chunk payload was not terminated by CRLF.");
                }
            }

            return read;
        }

        public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();

        public override void SetLength(long value) => throw new NotSupportedException();

        public override void Write(byte[] buffer, int offset, int count) => throw new NotSupportedException();

        public override ValueTask WriteAsync(ReadOnlyMemory<byte> buffer, CancellationToken cancellationToken = default)
            => throw new NotSupportedException();

        protected override void Dispose(bool disposing)
        {
            if (disposing)
            {
                _inner.Dispose();
            }

            base.Dispose(disposing);
        }

        public override ValueTask DisposeAsync() => _inner.DisposeAsync();
    }

    private sealed class Http11ContentLengthReadStream : Stream
    {
        private readonly Stream _inner;
        private long _remaining;

        public Http11ContentLengthReadStream(Stream inner, long length)
        {
            _inner = inner ?? throw new ArgumentNullException(nameof(inner));
            _remaining = length;
        }

        public override bool CanRead => _inner.CanRead;

        public override bool CanSeek => false;

        public override bool CanWrite => false;

        public override long Length => throw new NotSupportedException();

        public override long Position
        {
            get => throw new NotSupportedException();
            set => throw new NotSupportedException();
        }

        public override bool CanTimeout => _inner.CanTimeout;

        public override int ReadTimeout
        {
            get => _inner.ReadTimeout;
            set => _inner.ReadTimeout = value;
        }

        public override int WriteTimeout
        {
            get => _inner.WriteTimeout;
            set => _inner.WriteTimeout = value;
        }

        public override void Flush() => throw new NotSupportedException();

        public override Task FlushAsync(CancellationToken cancellationToken) => Task.CompletedTask;

        public override int Read(byte[] buffer, int offset, int count)
            => ReadAsync(buffer.AsMemory(offset, count), CancellationToken.None).AsTask().GetAwaiter().GetResult();

        public override async ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken cancellationToken = default)
        {
            if (_remaining <= 0 || buffer.Length == 0)
            {
                return 0;
            }

            var readLength = (int)Math.Min(buffer.Length, _remaining);
            var read = await _inner.ReadAsync(buffer[..readLength], cancellationToken).ConfigureAwait(false);
            if (read == 0)
            {
                throw new EndOfStreamException("Unexpected EOF while reading SplitHTTP response body.");
            }

            _remaining -= read;
            return read;
        }

        public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();

        public override void SetLength(long value) => throw new NotSupportedException();

        public override void Write(byte[] buffer, int offset, int count) => throw new NotSupportedException();

        public override ValueTask WriteAsync(ReadOnlyMemory<byte> buffer, CancellationToken cancellationToken = default)
            => throw new NotSupportedException();

        protected override void Dispose(bool disposing)
        {
            if (disposing)
            {
                _inner.Dispose();
            }

            base.Dispose(disposing);
        }

        public override ValueTask DisposeAsync() => _inner.DisposeAsync();
    }

    private sealed class Http11ChunkedUploadStream : Stream
    {
        private static readonly byte[] ChunkTerminator = Encoding.ASCII.GetBytes("\r\n");
        private static readonly byte[] FinalChunk = Encoding.ASCII.GetBytes("0\r\n\r\n");

        private readonly Stream _inner;
        private readonly SemaphoreSlim _writeLock = new(1, 1);
        private readonly CancellationTokenSource _responseCts = new();
        private readonly Task _responseMonitorTask;
        private int _disposed;

        public Http11ChunkedUploadStream(Stream inner)
        {
            _inner = inner ?? throw new ArgumentNullException(nameof(inner));
            _responseMonitorTask = MonitorResponseAsync(_responseCts.Token);
        }

        public override bool CanRead => false;

        public override bool CanSeek => false;

        public override bool CanWrite => _inner.CanWrite;

        public override long Length => throw new NotSupportedException();

        public override long Position
        {
            get => throw new NotSupportedException();
            set => throw new NotSupportedException();
        }

        public override bool CanTimeout => _inner.CanTimeout;

        public override int ReadTimeout
        {
            get => _inner.ReadTimeout;
            set => _inner.ReadTimeout = value;
        }

        public override int WriteTimeout
        {
            get => _inner.WriteTimeout;
            set => _inner.WriteTimeout = value;
        }

        public override void Flush()
            => FlushAsync(CancellationToken.None).GetAwaiter().GetResult();

        public override Task FlushAsync(CancellationToken cancellationToken)
        {
            ThrowIfResponseFaulted();
            return _inner.FlushAsync(cancellationToken);
        }

        public override int Read(byte[] buffer, int offset, int count) => throw new NotSupportedException();

        public override void Write(byte[] buffer, int offset, int count)
            => WriteAsync(buffer.AsMemory(offset, count), CancellationToken.None).AsTask().GetAwaiter().GetResult();

        public override async ValueTask WriteAsync(ReadOnlyMemory<byte> buffer, CancellationToken cancellationToken = default)
        {
            ObjectDisposedException.ThrowIf(Volatile.Read(ref _disposed) != 0, this);
            ThrowIfResponseFaulted();
            if (buffer.Length == 0)
            {
                return;
            }

            await _writeLock.WaitAsync(cancellationToken).ConfigureAwait(false);
            try
            {
                ThrowIfResponseFaulted();
                var chunkHeader = Encoding.ASCII.GetBytes(buffer.Length.ToString("X", CultureInfo.InvariantCulture) + "\r\n");
                await _inner.WriteAsync(chunkHeader, cancellationToken).ConfigureAwait(false);
                await _inner.WriteAsync(buffer, cancellationToken).ConfigureAwait(false);
                await _inner.WriteAsync(ChunkTerminator, cancellationToken).ConfigureAwait(false);
            }
            finally
            {
                _writeLock.Release();
            }
        }

        public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();

        public override void SetLength(long value) => throw new NotSupportedException();

        protected override void Dispose(bool disposing)
        {
            if (disposing)
            {
                DisposeAsync().AsTask().GetAwaiter().GetResult();
            }

            base.Dispose(disposing);
        }

        public override async ValueTask DisposeAsync()
        {
            if (Interlocked.Exchange(ref _disposed, 1) != 0)
            {
                return;
            }

            try
            {
                await _writeLock.WaitAsync(CancellationToken.None).ConfigureAwait(false);
                try
                {
                    await _inner.WriteAsync(FinalChunk, CancellationToken.None).ConfigureAwait(false);
                    await _inner.FlushAsync(CancellationToken.None).ConfigureAwait(false);
                }
                catch
                {
                }
                finally
                {
                    _writeLock.Release();
                }
            }
            finally
            {
                _responseCts.Cancel();
                try
                {
                    await _responseMonitorTask.ConfigureAwait(false);
                }
                catch (OperationCanceledException) when (_responseCts.IsCancellationRequested)
                {
                }
                catch
                {
                }

                _writeLock.Dispose();
                _responseCts.Dispose();
                await _inner.DisposeAsync().ConfigureAwait(false);
            }
        }

        private async Task MonitorResponseAsync(CancellationToken cancellationToken)
        {
            var response = await ReadResponseAsync(
                    _inner,
                    "Unexpected EOF during SplitHTTP uplink handshake.",
                    cancellationToken)
                .ConfigureAwait(false);
            if (response.StatusCode != 200)
            {
                throw new IOException(
                    $"SplitHTTP uplink responded with non-200 status: {response.StatusCode.ToString(CultureInfo.InvariantCulture)}.");
            }
        }

        private void ThrowIfResponseFaulted()
        {
            if (!_responseMonitorTask.IsFaulted)
            {
                return;
            }

            var exception = _responseMonitorTask.Exception?.InnerException ?? _responseMonitorTask.Exception;
            if (exception is not null)
            {
                ExceptionDispatchInfo.Capture(exception).Throw();
            }

            throw new IOException("SplitHTTP uplink response handshake failed.");
        }
    }

    private sealed class SplitHttpResponseDrainingUploadStream : Stream
    {
        private readonly Stream _inner;
        private readonly Task _responseDrainTask;
        private int _disposed;

        public SplitHttpResponseDrainingUploadStream(Stream inner)
        {
            _inner = inner ?? throw new ArgumentNullException(nameof(inner));
            _responseDrainTask = DrainResponseAsync();
        }

        public override bool CanRead => false;

        public override bool CanSeek => false;

        public override bool CanWrite => Volatile.Read(ref _disposed) == 0 && _inner.CanWrite;

        public override long Length => throw new NotSupportedException();

        public override long Position
        {
            get => throw new NotSupportedException();
            set => throw new NotSupportedException();
        }

        public override bool CanTimeout => _inner.CanTimeout;

        public override int ReadTimeout
        {
            get => _inner.ReadTimeout;
            set => _inner.ReadTimeout = value;
        }

        public override int WriteTimeout
        {
            get => _inner.WriteTimeout;
            set => _inner.WriteTimeout = value;
        }

        public override void Flush()
            => FlushAsync(CancellationToken.None).GetAwaiter().GetResult();

        public override Task FlushAsync(CancellationToken cancellationToken)
        {
            ThrowIfResponseFaulted();
            return _inner.FlushAsync(cancellationToken);
        }

        public override int Read(byte[] buffer, int offset, int count) => throw new NotSupportedException();

        public override void Write(byte[] buffer, int offset, int count)
            => WriteAsync(buffer.AsMemory(offset, count), CancellationToken.None).AsTask().GetAwaiter().GetResult();

        public override async ValueTask WriteAsync(ReadOnlyMemory<byte> buffer, CancellationToken cancellationToken = default)
        {
            ObjectDisposedException.ThrowIf(Volatile.Read(ref _disposed) != 0, this);
            ThrowIfResponseFaulted();
            if (buffer.Length == 0)
            {
                return;
            }

            await _inner.WriteAsync(buffer, cancellationToken).ConfigureAwait(false);
        }

        public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();

        public override void SetLength(long value) => throw new NotSupportedException();

        protected override void Dispose(bool disposing)
        {
            if (disposing)
            {
                DisposeAsync().AsTask().GetAwaiter().GetResult();
            }

            base.Dispose(disposing);
        }

        public override async ValueTask DisposeAsync()
        {
            if (Interlocked.Exchange(ref _disposed, 1) != 0)
            {
                return;
            }

            Exception? responseException = null;
            try
            {
                try
                {
                    await _responseDrainTask.ConfigureAwait(false);
                }
                catch (Exception ex)
                {
                    if (!ShouldIgnoreDisposeDrainException(ex))
                    {
                        responseException = ex;
                    }
                }
            }
            finally
            {
                await _inner.DisposeAsync().ConfigureAwait(false);
            }

            if (responseException is not null)
            {
                ExceptionDispatchInfo.Capture(responseException).Throw();
            }
        }

        private async Task DrainResponseAsync()
        {
            var buffer = new byte[1024];
            while (true)
            {
                var read = await _inner.ReadAsync(buffer, CancellationToken.None).ConfigureAwait(false);
                if (read == 0)
                {
                    return;
                }
            }
        }

        private void ThrowIfResponseFaulted()
        {
            if (!_responseDrainTask.IsFaulted)
            {
                return;
            }

            var exception = _responseDrainTask.Exception?.InnerException ?? _responseDrainTask.Exception;
            if (exception is not null)
            {
                ExceptionDispatchInfo.Capture(exception).Throw();
            }

            throw new IOException("SplitHTTP upload response drain failed.");
        }

        private static bool ShouldIgnoreDisposeDrainException(Exception exception)
            => exception is IOException or ObjectDisposedException or InvalidOperationException or System.Net.Quic.QuicException;
    }

    private sealed class Http11ChunkedStreamOneDuplexStream : Stream
    {
        private static readonly byte[] ChunkTerminator = Encoding.ASCII.GetBytes("\r\n");
        private static readonly byte[] FinalChunk = Encoding.ASCII.GetBytes("0\r\n\r\n");

        private readonly Stream _inner;
        private readonly SemaphoreSlim _writeLock = new(1, 1);
        private readonly Task<Stream> _responseBodyTask;
        private int _disposed;

        public Http11ChunkedStreamOneDuplexStream(Stream inner)
        {
            _inner = inner ?? throw new ArgumentNullException(nameof(inner));
            _responseBodyTask = OpenResponseBodyAsync();
        }

        public override bool CanRead => _inner.CanRead;

        public override bool CanSeek => false;

        public override bool CanWrite => _inner.CanWrite;

        public override long Length => throw new NotSupportedException();

        public override long Position
        {
            get => throw new NotSupportedException();
            set => throw new NotSupportedException();
        }

        public override bool CanTimeout => _inner.CanTimeout;

        public override int ReadTimeout
        {
            get => _inner.ReadTimeout;
            set => _inner.ReadTimeout = value;
        }

        public override int WriteTimeout
        {
            get => _inner.WriteTimeout;
            set => _inner.WriteTimeout = value;
        }

        public override void Flush()
            => FlushAsync(CancellationToken.None).GetAwaiter().GetResult();

        public override Task FlushAsync(CancellationToken cancellationToken)
        {
            ThrowIfResponseFaulted();
            return _inner.FlushAsync(cancellationToken);
        }

        public override int Read(byte[] buffer, int offset, int count)
            => ReadAsync(buffer.AsMemory(offset, count), CancellationToken.None).AsTask().GetAwaiter().GetResult();

        public override async ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken cancellationToken = default)
        {
            ObjectDisposedException.ThrowIf(Volatile.Read(ref _disposed) != 0, this);
            var responseBody = await GetResponseBodyAsync().ConfigureAwait(false);
            return await responseBody.ReadAsync(buffer, cancellationToken).ConfigureAwait(false);
        }

        public override void Write(byte[] buffer, int offset, int count)
            => WriteAsync(buffer.AsMemory(offset, count), CancellationToken.None).AsTask().GetAwaiter().GetResult();

        public override async ValueTask WriteAsync(ReadOnlyMemory<byte> buffer, CancellationToken cancellationToken = default)
        {
            ObjectDisposedException.ThrowIf(Volatile.Read(ref _disposed) != 0, this);
            ThrowIfResponseFaulted();
            if (buffer.Length == 0)
            {
                return;
            }

            await _writeLock.WaitAsync(cancellationToken).ConfigureAwait(false);
            try
            {
                ThrowIfResponseFaulted();
                var chunkHeader = Encoding.ASCII.GetBytes(buffer.Length.ToString("X", CultureInfo.InvariantCulture) + "\r\n");
                await _inner.WriteAsync(chunkHeader, cancellationToken).ConfigureAwait(false);
                await _inner.WriteAsync(buffer, cancellationToken).ConfigureAwait(false);
                await _inner.WriteAsync(ChunkTerminator, cancellationToken).ConfigureAwait(false);
            }
            finally
            {
                _writeLock.Release();
            }
        }

        public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();

        public override void SetLength(long value) => throw new NotSupportedException();

        protected override void Dispose(bool disposing)
        {
            if (disposing)
            {
                DisposeAsync().AsTask().GetAwaiter().GetResult();
            }

            base.Dispose(disposing);
        }

        public override async ValueTask DisposeAsync()
        {
            if (Interlocked.Exchange(ref _disposed, 1) != 0)
            {
                return;
            }

            try
            {
                await _writeLock.WaitAsync(CancellationToken.None).ConfigureAwait(false);
                try
                {
                    await _inner.WriteAsync(FinalChunk, CancellationToken.None).ConfigureAwait(false);
                    await _inner.FlushAsync(CancellationToken.None).ConfigureAwait(false);
                }
                catch
                {
                }
                finally
                {
                    _writeLock.Release();
                }

                if (_responseBodyTask.Status == TaskStatus.RanToCompletion)
                {
                    await _responseBodyTask.Result.DisposeAsync().ConfigureAwait(false);
                }
            }
            finally
            {
                _writeLock.Dispose();
                await _inner.DisposeAsync().ConfigureAwait(false);
            }
        }

        private async Task<Stream> OpenResponseBodyAsync()
        {
            var response = await ReadResponseAsync(
                    _inner,
                    "Unexpected EOF during SplitHTTP stream-one response handshake.",
                    CancellationToken.None)
                .ConfigureAwait(false);
            if (response.StatusCode != 200)
            {
                throw new IOException(
                    $"SplitHTTP stream-one responded with non-200 status: {response.StatusCode.ToString(CultureInfo.InvariantCulture)}.");
            }

            return CreateResponseBodyStream(_inner, response.Headers);
        }

        private async ValueTask<Stream> GetResponseBodyAsync()
        {
            try
            {
                return await _responseBodyTask.ConfigureAwait(false);
            }
            catch (Exception ex)
            {
                ExceptionDispatchInfo.Capture(ex).Throw();
                throw;
            }
        }

        private void ThrowIfResponseFaulted()
        {
            if (!_responseBodyTask.IsFaulted)
            {
                return;
            }

            var exception = _responseBodyTask.Exception?.InnerException ?? _responseBodyTask.Exception;
            if (exception is not null)
            {
                ExceptionDispatchInfo.Capture(exception).Throw();
            }

            throw new IOException("SplitHTTP stream-one response handshake failed.");
        }
    }

    private sealed class SplitHttpDuplexStream : Stream
    {
        private readonly Stream _reader;
        private readonly Stream _writer;

        public SplitHttpDuplexStream(Stream reader, Stream writer)
        {
            _reader = reader ?? throw new ArgumentNullException(nameof(reader));
            _writer = writer ?? throw new ArgumentNullException(nameof(writer));
        }

        public override bool CanRead => _reader.CanRead;

        public override bool CanSeek => false;

        public override bool CanWrite => _writer.CanWrite;

        public override long Length => throw new NotSupportedException();

        public override long Position
        {
            get => throw new NotSupportedException();
            set => throw new NotSupportedException();
        }

        public override bool CanTimeout => _reader.CanTimeout || _writer.CanTimeout;

        public override int ReadTimeout
        {
            get => _reader.ReadTimeout;
            set => _reader.ReadTimeout = value;
        }

        public override int WriteTimeout
        {
            get => _writer.WriteTimeout;
            set => _writer.WriteTimeout = value;
        }

        public override void Flush() => _writer.Flush();

        public override Task FlushAsync(CancellationToken cancellationToken)
            => _writer.FlushAsync(cancellationToken);

        public override int Read(byte[] buffer, int offset, int count)
            => _reader.Read(buffer, offset, count);

        public override int Read(Span<byte> buffer)
            => _reader.Read(buffer);

        public override ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken cancellationToken = default)
            => _reader.ReadAsync(buffer, cancellationToken);

        public override Task<int> ReadAsync(byte[] buffer, int offset, int count, CancellationToken cancellationToken)
            => _reader.ReadAsync(buffer, offset, count, cancellationToken);

        public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();

        public override void SetLength(long value) => throw new NotSupportedException();

        public override void Write(byte[] buffer, int offset, int count)
            => _writer.Write(buffer, offset, count);

        public override void Write(ReadOnlySpan<byte> buffer)
            => _writer.Write(buffer);

        public override ValueTask WriteAsync(ReadOnlyMemory<byte> buffer, CancellationToken cancellationToken = default)
            => _writer.WriteAsync(buffer, cancellationToken);

        public override Task WriteAsync(byte[] buffer, int offset, int count, CancellationToken cancellationToken)
            => _writer.WriteAsync(buffer, offset, count, cancellationToken);

        protected override void Dispose(bool disposing)
        {
            if (disposing)
            {
                DisposeAsync().AsTask().GetAwaiter().GetResult();
            }

            base.Dispose(disposing);
        }

        public override async ValueTask DisposeAsync()
        {
            if (!ReferenceEquals(_reader, _writer))
            {
                await _reader.DisposeAsync().ConfigureAwait(false);
            }

            await _writer.DisposeAsync().ConfigureAwait(false);
        }
    }

    private sealed class SplitHttpOwnedStream : Stream
    {
        private readonly Stream _innerStream;
        private readonly IReadOnlyList<IAsyncDisposable> _owners;
        private int _disposed;

        public SplitHttpOwnedStream(
            Stream innerStream,
            IReadOnlyList<IAsyncDisposable> owners)
        {
            _innerStream = innerStream ?? throw new ArgumentNullException(nameof(innerStream));
            _owners = owners ?? throw new ArgumentNullException(nameof(owners));
        }

        public override bool CanRead => Volatile.Read(ref _disposed) == 0 && _innerStream.CanRead;

        public override bool CanSeek => false;

        public override bool CanWrite => Volatile.Read(ref _disposed) == 0 && _innerStream.CanWrite;

        public override long Length => throw new NotSupportedException();

        public override long Position
        {
            get => throw new NotSupportedException();
            set => throw new NotSupportedException();
        }

        public override bool CanTimeout => _innerStream.CanTimeout;

        public override int ReadTimeout
        {
            get => _innerStream.ReadTimeout;
            set => _innerStream.ReadTimeout = value;
        }

        public override int WriteTimeout
        {
            get => _innerStream.WriteTimeout;
            set => _innerStream.WriteTimeout = value;
        }

        public override void Flush()
            => _innerStream.Flush();

        public override Task FlushAsync(CancellationToken cancellationToken)
            => _innerStream.FlushAsync(cancellationToken);

        public override int Read(byte[] buffer, int offset, int count)
            => _innerStream.Read(buffer, offset, count);

        public override int Read(Span<byte> buffer)
            => _innerStream.Read(buffer);

        public override ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken cancellationToken = default)
            => _innerStream.ReadAsync(buffer, cancellationToken);

        public override Task<int> ReadAsync(byte[] buffer, int offset, int count, CancellationToken cancellationToken)
            => _innerStream.ReadAsync(buffer, offset, count, cancellationToken);

        public override long Seek(long offset, SeekOrigin origin)
            => throw new NotSupportedException();

        public override void SetLength(long value)
            => throw new NotSupportedException();

        public override void Write(byte[] buffer, int offset, int count)
            => _innerStream.Write(buffer, offset, count);

        public override void Write(ReadOnlySpan<byte> buffer)
            => _innerStream.Write(buffer);

        public override ValueTask WriteAsync(ReadOnlyMemory<byte> buffer, CancellationToken cancellationToken = default)
            => _innerStream.WriteAsync(buffer, cancellationToken);

        public override Task WriteAsync(byte[] buffer, int offset, int count, CancellationToken cancellationToken)
            => _innerStream.WriteAsync(buffer, offset, count, cancellationToken);

        protected override void Dispose(bool disposing)
        {
            if (disposing)
            {
                DisposeAsync().AsTask().GetAwaiter().GetResult();
            }

            base.Dispose(disposing);
        }

        public override async ValueTask DisposeAsync()
        {
            if (Interlocked.Exchange(ref _disposed, 1) != 0)
            {
                return;
            }

            try
            {
                await _innerStream.DisposeAsync().ConfigureAwait(false);
            }
            finally
            {
                for (var index = 0; index < _owners.Count; index++)
                {
                    await _owners[index].DisposeAsync().ConfigureAwait(false);
                }
            }
        }
    }

    private sealed class SplitHttpBrowserPacketUploadStream : Stream
    {
        private readonly IRuntimeInternetBrowserDialer _browserDialer;
        private readonly RuntimeInternetStack _internetStack;
        private readonly IRuntimeInternetOptions _options;
        private readonly string _authority;
        private readonly string _method;
        private readonly string _sessionPlacement;
        private readonly string _sessionKey;
        private readonly string _sessionId;
        private readonly string _seqPlacement;
        private readonly string _seqKey;
        private readonly string _uplinkDataPlacement;
        private readonly string _uplinkDataKey;
        private readonly RuntimeInt32Range _uplinkChunkSize;
        private readonly RuntimeInt32Range _scMinPostsIntervalMs;
        private readonly SplitHttpXPaddingRuntimeOptions _xPaddingOptions;
        private readonly int _maxUploadSize;
        private readonly MemoryStream _pendingBuffer = new();
        private readonly SemaphoreSlim _writeLock = new(1, 1);
        private Exception? _uploadFault;
        private long _nextSequence;
        private long _lastUploadStartedAtUtcTicks;
        private int _disposed;

        public SplitHttpBrowserPacketUploadStream(
            IRuntimeInternetBrowserDialer browserDialer,
            RuntimeInternetStack internetStack,
            IRuntimeInternetOptions options,
            string authority,
            string method,
            string sessionPlacement,
            string sessionKey,
            string sessionId,
            string seqPlacement,
            string seqKey,
            string uplinkDataPlacement,
            string uplinkDataKey,
            RuntimeInt32Range uplinkChunkSize,
            RuntimeInt32Range scMaxEachPostBytes,
            RuntimeInt32Range scMinPostsIntervalMs,
            SplitHttpXPaddingRuntimeOptions xPaddingOptions)
        {
            _browserDialer = browserDialer ?? throw new ArgumentNullException(nameof(browserDialer));
            _internetStack = internetStack;
            _options = options ?? throw new ArgumentNullException(nameof(options));
            _authority = authority ?? throw new ArgumentNullException(nameof(authority));
            _method = method ?? throw new ArgumentNullException(nameof(method));
            _sessionPlacement = sessionPlacement ?? throw new ArgumentNullException(nameof(sessionPlacement));
            _sessionKey = sessionKey ?? throw new ArgumentNullException(nameof(sessionKey));
            _sessionId = sessionId ?? throw new ArgumentNullException(nameof(sessionId));
            _seqPlacement = seqPlacement ?? throw new ArgumentNullException(nameof(seqPlacement));
            _seqKey = seqKey ?? throw new ArgumentNullException(nameof(seqKey));
            _uplinkDataPlacement = uplinkDataPlacement ?? throw new ArgumentNullException(nameof(uplinkDataPlacement));
            _uplinkDataKey = uplinkDataKey ?? throw new ArgumentNullException(nameof(uplinkDataKey));
            _uplinkChunkSize = uplinkChunkSize ?? throw new ArgumentNullException(nameof(uplinkChunkSize));
            _scMinPostsIntervalMs = scMinPostsIntervalMs ?? throw new ArgumentNullException(nameof(scMinPostsIntervalMs));
            _xPaddingOptions = xPaddingOptions ?? throw new ArgumentNullException(nameof(xPaddingOptions));
            if (GetRangeMinimum(scMaxEachPostBytes ?? throw new ArgumentNullException(nameof(scMaxEachPostBytes))) <= 0)
            {
                throw new InvalidOperationException("SplitHTTP scMaxEachPostBytes should be greater than 0.");
            }

            _maxUploadSize = GetRandomRangeValue(scMaxEachPostBytes);
        }

        public override bool CanRead => false;

        public override bool CanSeek => false;

        public override bool CanWrite => true;

        public override long Length => throw new NotSupportedException();

        public override long Position
        {
            get => throw new NotSupportedException();
            set => throw new NotSupportedException();
        }

        public override void Flush()
            => FlushAsync(CancellationToken.None).GetAwaiter().GetResult();

        public override async Task FlushAsync(CancellationToken cancellationToken)
        {
            ObjectDisposedException.ThrowIf(Volatile.Read(ref _disposed) != 0, this);
            ThrowIfUploadFaulted();

            List<byte[]> payloads;
            await _writeLock.WaitAsync(cancellationToken).ConfigureAwait(false);
            try
            {
                ObjectDisposedException.ThrowIf(Volatile.Read(ref _disposed) != 0, this);
                ThrowIfUploadFaulted();
                payloads = DrainBufferedPayloads(flushAll: true);
            }
            finally
            {
                _writeLock.Release();
            }

            await SendPayloadsAsync(payloads, cancellationToken).ConfigureAwait(false);
            ThrowIfUploadFaulted();
        }

        public override int Read(byte[] buffer, int offset, int count) => throw new NotSupportedException();

        public override void Write(byte[] buffer, int offset, int count)
            => WriteAsync(buffer.AsMemory(offset, count), CancellationToken.None).AsTask().GetAwaiter().GetResult();

        public override async ValueTask WriteAsync(ReadOnlyMemory<byte> buffer, CancellationToken cancellationToken = default)
        {
            ObjectDisposedException.ThrowIf(Volatile.Read(ref _disposed) != 0, this);
            ThrowIfUploadFaulted();
            if (buffer.Length == 0)
            {
                return;
            }

            List<byte[]> payloads;
            await _writeLock.WaitAsync(cancellationToken).ConfigureAwait(false);
            try
            {
                ObjectDisposedException.ThrowIf(Volatile.Read(ref _disposed) != 0, this);
                ThrowIfUploadFaulted();
                _pendingBuffer.Write(buffer.Span);
                payloads = DrainBufferedPayloads(flushAll: false);
            }
            finally
            {
                _writeLock.Release();
            }

            await SendPayloadsAsync(payloads, cancellationToken).ConfigureAwait(false);
        }

        public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();

        public override void SetLength(long value) => throw new NotSupportedException();

        protected override void Dispose(bool disposing)
        {
            if (disposing)
            {
                DisposeAsync().AsTask().GetAwaiter().GetResult();
            }

            base.Dispose(disposing);
        }

        public override ValueTask DisposeAsync()
            => DisposeAsyncCore();

        private async ValueTask DisposeAsyncCore()
        {
            if (Interlocked.Exchange(ref _disposed, 1) != 0)
            {
                return;
            }

            Exception? terminalException = _uploadFault;
            try
            {
                List<byte[]> payloads = [];
                await _writeLock.WaitAsync(CancellationToken.None).ConfigureAwait(false);
                try
                {
                    if (terminalException is null)
                    {
                        payloads = DrainBufferedPayloads(flushAll: true);
                    }
                }
                finally
                {
                    _writeLock.Release();
                }

                if (terminalException is null)
                {
                    await SendPayloadsAsync(payloads, CancellationToken.None).ConfigureAwait(false);
                }
            }
            catch (Exception ex)
            {
                SetUploadFault(ex);
                terminalException = _uploadFault;
            }
            finally
            {
                _pendingBuffer.Dispose();
                _writeLock.Dispose();
            }

            if (terminalException is not null)
            {
                ExceptionDispatchInfo.Capture(terminalException).Throw();
            }
        }

        private List<byte[]> DrainBufferedPayloads(bool flushAll)
        {
            var bufferedLength = checked((int)_pendingBuffer.Length);
            if (bufferedLength == 0)
            {
                return [];
            }

            if (!flushAll && bufferedLength < _maxUploadSize)
            {
                return [];
            }

            var buffered = _pendingBuffer.ToArray();
            var sendLength = flushAll
                ? buffered.Length
                : buffered.Length - (buffered.Length % _maxUploadSize);
            if (sendLength <= 0)
            {
                return [];
            }

            var payloads = new List<byte[]>((sendLength + _maxUploadSize - 1) / _maxUploadSize);
            for (var offset = 0; offset < sendLength; offset += _maxUploadSize)
            {
                var currentLength = Math.Min(_maxUploadSize, sendLength - offset);
                var chunk = new byte[currentLength];
                Buffer.BlockCopy(buffered, offset, chunk, 0, currentLength);
                payloads.Add(chunk);
            }

            _pendingBuffer.SetLength(0);
            if (!flushAll && sendLength < buffered.Length)
            {
                _pendingBuffer.Write(buffered, sendLength, buffered.Length - sendLength);
            }

            return payloads;
        }

        private async Task SendPayloadsAsync(
            IReadOnlyList<byte[]> payloads,
            CancellationToken cancellationToken)
        {
            if (payloads.Count == 0)
            {
                return;
            }

            try
            {
                for (var index = 0; index < payloads.Count; index++)
                {
                    cancellationToken.ThrowIfCancellationRequested();
                    ThrowIfUploadFaulted();
                    await DelayForNextUploadAsync(cancellationToken).ConfigureAwait(false);

                    var sequence = Interlocked.Increment(ref _nextSequence) - 1;
                    var request = BuildPacketUploadRequest(
                        _method,
                        _authority,
                        _internetStack,
                        _options,
                        _xPaddingOptions,
                        _sessionPlacement,
                        _sessionKey,
                        _sessionId,
                        _seqPlacement,
                        _seqKey,
                        _uplinkDataPlacement,
                        _uplinkDataKey,
                        _uplinkChunkSize,
                        sequence,
                        payloads[index]);

                    await _browserDialer
                        .SendPacketAsync(
                            new RuntimeInternetBrowserPacketRequest(
                                request.Method,
                                BuildRequestUrl(_internetStack, request.Authority, request.RequestTarget),
                                CreateEffectiveRequestHeaders(request.RequestHeaders, includeContentType: false)),
                            request.RequestBody,
                            cancellationToken)
                        .ConfigureAwait(false);
                }
            }
            catch (Exception ex)
            {
                SetUploadFault(ex);
                throw;
            }
        }

        private async Task DelayForNextUploadAsync(CancellationToken cancellationToken)
        {
            if (!ShouldDelayPacketUploads(_scMinPostsIntervalMs))
            {
                _lastUploadStartedAtUtcTicks = DateTime.UtcNow.Ticks;
                return;
            }

            var intervalMs = GetRandomRangeValue(_scMinPostsIntervalMs);
            if (intervalMs <= 0)
            {
                _lastUploadStartedAtUtcTicks = DateTime.UtcNow.Ticks;
                return;
            }

            var previousTicks = Interlocked.Read(ref _lastUploadStartedAtUtcTicks);
            if (previousTicks > 0)
            {
                var nextAllowedAt = new DateTime(previousTicks, DateTimeKind.Utc)
                    .AddMilliseconds(intervalMs);
                var delay = nextAllowedAt - DateTime.UtcNow;
                if (delay > TimeSpan.Zero)
                {
                    await Task.Delay(delay, cancellationToken).ConfigureAwait(false);
                }
            }

            Interlocked.Exchange(ref _lastUploadStartedAtUtcTicks, DateTime.UtcNow.Ticks);
        }

        private void ThrowIfUploadFaulted()
        {
            if (_uploadFault is not null)
            {
                ExceptionDispatchInfo.Capture(_uploadFault).Throw();
            }
        }

        private void SetUploadFault(Exception exception)
        {
            ArgumentNullException.ThrowIfNull(exception);
            Interlocked.CompareExchange(ref _uploadFault, exception, null);
        }
    }

    private sealed class SplitHttpPacketUploadStream<TOptions> : Stream
        where TOptions : class, IRuntimeGrpcClientDialOptions
    {
        private readonly TOptions _options;
        private readonly RuntimeInternetStack _internetStack;
        private readonly RuntimeInternetProfile _internetProfile;
        private readonly IDnsResolver _dnsResolver;
        private readonly string _authority;
        private readonly string _method;
        private readonly string _sessionPlacement;
        private readonly string _sessionKey;
        private readonly string _sessionId;
        private readonly string _seqPlacement;
        private readonly string _seqKey;
        private readonly string _uplinkDataPlacement;
        private readonly string _uplinkDataKey;
        private readonly RuntimeInt32Range _uplinkChunkSize;
        private readonly RuntimeInt32Range _scMinPostsIntervalMs;
        private readonly SplitHttpXPaddingRuntimeOptions _xPaddingOptions;
        private readonly RuntimeSplitHttpXmuxOptions _splitHttpXmux;
        private readonly SplitHttpHttp3UploadPoolManager? _sharedHttp3UploadPoolManager;
        private readonly SplitHttpSharedUploadPoolManager? _sharedUploadPoolManager;
        private readonly SplitHttpHttp3UploadPoolManager? _localHttp3UploadPoolManager;
        private readonly SplitHttpHttp2UploadPoolManager? _sharedHttp2UploadPoolManager;
        private readonly SplitHttpHttp2UploadPoolManager? _localHttp2UploadPoolManager;
        private readonly int _maxUploadSize;
        private readonly SplitHttpBufferedUploadPipe _pendingWrites;
        private readonly Task _senderTask;
        private readonly SemaphoreSlim _writeLock = new(1, 1);
        private Exception? _uploadFault;
        private SplitHttpHttp11UploadConnection? _reusableUploadConnection;
        private SplitHttpHttp3UploadPoolLease? _sharedHttp3UploadPoolLease;
        private SplitHttpSharedUploadPoolLease? _sharedUploadPoolLease;
        private SplitHttpHttp3UploadPoolLease? _localHttp3UploadPoolLease;
        private SplitHttpHttp2UploadPoolLease? _sharedHttp2UploadPoolLease;
        private SplitHttpHttp2UploadPoolLease? _localHttp2UploadPoolLease;
        private long _nextSequence;
        private long _lastUploadStartedAtUtcTicks;
        private int _disposed;

        public SplitHttpPacketUploadStream(
            TOptions options,
            RuntimeInternetStack internetStack,
            RuntimeInternetProfile internetProfile,
            IDnsResolver dnsResolver,
            string authority,
            string method,
            string sessionPlacement,
            string sessionKey,
            string sessionId,
            string seqPlacement,
            string seqKey,
            string uplinkDataPlacement,
            string uplinkDataKey,
            RuntimeInt32Range uplinkChunkSize,
            RuntimeInt32Range scMaxEachPostBytes,
            RuntimeInt32Range scMinPostsIntervalMs,
            SplitHttpXPaddingRuntimeOptions xPaddingOptions)
        {
            _options = options ?? throw new ArgumentNullException(nameof(options));
            _internetStack = internetStack;
            _internetProfile = internetProfile ?? throw new ArgumentNullException(nameof(internetProfile));
            _dnsResolver = dnsResolver ?? throw new ArgumentNullException(nameof(dnsResolver));
            _authority = authority ?? throw new ArgumentNullException(nameof(authority));
            _method = method ?? throw new ArgumentNullException(nameof(method));
            _sessionPlacement = sessionPlacement ?? throw new ArgumentNullException(nameof(sessionPlacement));
            _sessionKey = sessionKey ?? throw new ArgumentNullException(nameof(sessionKey));
            _sessionId = sessionId ?? throw new ArgumentNullException(nameof(sessionId));
            _seqPlacement = seqPlacement ?? throw new ArgumentNullException(nameof(seqPlacement));
            _seqKey = seqKey ?? throw new ArgumentNullException(nameof(seqKey));
            _uplinkDataPlacement = uplinkDataPlacement ?? throw new ArgumentNullException(nameof(uplinkDataPlacement));
            _uplinkDataKey = uplinkDataKey ?? throw new ArgumentNullException(nameof(uplinkDataKey));
            _uplinkChunkSize = uplinkChunkSize ?? throw new ArgumentNullException(nameof(uplinkChunkSize));
            _scMinPostsIntervalMs = scMinPostsIntervalMs ?? throw new ArgumentNullException(nameof(scMinPostsIntervalMs));
            _xPaddingOptions = xPaddingOptions ?? throw new ArgumentNullException(nameof(xPaddingOptions));
            _splitHttpXmux = NormalizeSplitHttpXmuxOptions(options.SplitHttpXmux);
            _sharedHttp3UploadPoolManager = TryGetSharedHttp3PoolManager(options, internetStack, internetProfile, dnsResolver);
            _sharedUploadPoolManager = TryGetSharedUploadPoolManager(options, internetStack, internetProfile, dnsResolver);
            _localHttp3UploadPoolManager = _sharedHttp3UploadPoolManager is null && PrefersHttp3Transport(internetStack, options)
                ? new SplitHttpHttp3UploadPoolManager(_splitHttpXmux)
                : null;
            _sharedHttp2UploadPoolManager = TryGetSharedHttp2UploadPoolManager(options, internetStack, internetProfile, dnsResolver);
            _localHttp2UploadPoolManager = _sharedHttp2UploadPoolManager is null && PrefersHttp2Transport(internetStack, options)
                ? new SplitHttpHttp2UploadPoolManager(_splitHttpXmux)
                : null;
            _sharedHttp3UploadPoolLease = _sharedHttp3UploadPoolManager?.Acquire();
            _sharedUploadPoolLease = _sharedUploadPoolManager?.Acquire();
            _localHttp3UploadPoolLease = _localHttp3UploadPoolManager?.Acquire();
            _sharedHttp2UploadPoolLease = _sharedHttp2UploadPoolManager?.Acquire();
            _localHttp2UploadPoolLease = _localHttp2UploadPoolManager?.Acquire();
            if (GetRangeMinimum(scMaxEachPostBytes ?? throw new ArgumentNullException(nameof(scMaxEachPostBytes))) <= 0)
            {
                throw new InvalidOperationException("SplitHTTP scMaxEachPostBytes should be greater than 0.");
            }

            _maxUploadSize = GetRandomRangeValue(scMaxEachPostBytes ?? throw new ArgumentNullException(nameof(scMaxEachPostBytes)));
            _pendingWrites = new SplitHttpBufferedUploadPipe(_maxUploadSize);
            _senderTask = ProcessUploadQueueAsync();
        }

        public override bool CanRead => false;

        public override bool CanSeek => false;

        public override bool CanWrite => true;

        public override long Length => throw new NotSupportedException();

        public override long Position
        {
            get => throw new NotSupportedException();
            set => throw new NotSupportedException();
        }

        public override void Flush()
            => FlushAsync(CancellationToken.None).GetAwaiter().GetResult();

        public override async Task FlushAsync(CancellationToken cancellationToken)
        {
            ObjectDisposedException.ThrowIf(Volatile.Read(ref _disposed) != 0, this);
            ThrowIfUploadFaulted();

            Task flushBoundaryTask;
            await _writeLock.WaitAsync(cancellationToken).ConfigureAwait(false);
            try
            {
                ObjectDisposedException.ThrowIf(Volatile.Read(ref _disposed) != 0, this);
                ThrowIfUploadFaulted();
                flushBoundaryTask = _pendingWrites.FlushAsync(cancellationToken).AsTask();
            }
            finally
            {
                _writeLock.Release();
            }

            await flushBoundaryTask.WaitAsync(cancellationToken).ConfigureAwait(false);
            ObjectDisposedException.ThrowIf(Volatile.Read(ref _disposed) != 0, this);
            ThrowIfUploadFaulted();
        }

        public override int Read(byte[] buffer, int offset, int count) => throw new NotSupportedException();

        public override void Write(byte[] buffer, int offset, int count)
            => WriteAsync(buffer.AsMemory(offset, count), CancellationToken.None).AsTask().GetAwaiter().GetResult();

        public override async ValueTask WriteAsync(ReadOnlyMemory<byte> buffer, CancellationToken cancellationToken = default)
        {
            ObjectDisposedException.ThrowIf(Volatile.Read(ref _disposed) != 0, this);
            ThrowIfUploadFaulted();
            if (buffer.Length == 0)
            {
                return;
            }

            await _writeLock.WaitAsync(cancellationToken).ConfigureAwait(false);
            try
            {
                ObjectDisposedException.ThrowIf(Volatile.Read(ref _disposed) != 0, this);
                ThrowIfUploadFaulted();
                await _pendingWrites.WriteAsync(buffer, cancellationToken).ConfigureAwait(false);
            }
            finally
            {
                _writeLock.Release();
            }
        }

        public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();

        public override void SetLength(long value) => throw new NotSupportedException();

        protected override void Dispose(bool disposing)
        {
            if (disposing)
            {
                DisposeAsync().AsTask().GetAwaiter().GetResult();
            }

            base.Dispose(disposing);
        }

        public override ValueTask DisposeAsync()
        {
            return DisposeAsyncCore();
        }

        private async ValueTask DisposeAsyncCore()
        {
            if (Interlocked.Exchange(ref _disposed, 1) != 0)
            {
                return;
            }

            _pendingWrites.Complete(new ObjectDisposedException(typeof(SplitHttpPacketUploadStream<TOptions>).FullName));
            try
            {
                await _senderTask.ConfigureAwait(false);
            }
            finally
            {
                if (_sharedHttp3UploadPoolLease is not null)
                {
                    await _sharedHttp3UploadPoolLease.DisposeAsync().ConfigureAwait(false);
                    _sharedHttp3UploadPoolLease = null;
                }

                if (_reusableUploadConnection is not null)
                {
                    if (_sharedUploadPoolLease is null)
                    {
                        _reusableUploadConnection.DisposeWhenResponseCompletes();
                    }
                    else
                    {
                        await _sharedUploadPoolLease.ReturnAsync(_reusableUploadConnection).ConfigureAwait(false);
                    }

                    _reusableUploadConnection = null;
                }

                if (_sharedUploadPoolLease is not null)
                {
                    await _sharedUploadPoolLease.DisposeAsync().ConfigureAwait(false);
                    _sharedUploadPoolLease = null;
                }

                if (_localHttp3UploadPoolLease is not null)
                {
                    await _localHttp3UploadPoolLease.DisposeAsync().ConfigureAwait(false);
                    _localHttp3UploadPoolLease = null;
                }

                if (_sharedHttp2UploadPoolLease is not null)
                {
                    await _sharedHttp2UploadPoolLease.DisposeAsync().ConfigureAwait(false);
                    _sharedHttp2UploadPoolLease = null;
                }

                if (_localHttp2UploadPoolLease is not null)
                {
                    await _localHttp2UploadPoolLease.DisposeAsync().ConfigureAwait(false);
                    _localHttp2UploadPoolLease = null;
                }

                _writeLock.Dispose();
            }
        }

        private async Task ProcessUploadQueueAsync()
        {
            try
            {
                while (true)
                {
                    ThrowIfUploadFaulted();
                    var firstChunk = await _pendingWrites.ReadAsync(CancellationToken.None).ConfigureAwait(false);
                    if (firstChunk is null)
                    {
                        break;
                    }

                    var bufferedChunks = new List<byte[]> { firstChunk };
                    var bufferedLength = firstChunk.Length;
                    var idleYieldsRemaining = 2;

                    await Task.Yield();
                    while (true)
                    {
                        var hasAvailableChunk = _pendingWrites.TryReadAvailable(
                            out var nextChunk,
                            out var encounteredFlushBoundary);
                        if (hasAvailableChunk)
                        {
                            if (nextChunk is not null)
                            {
                                idleYieldsRemaining = 2;
                                bufferedChunks.Add(nextChunk);
                                bufferedLength += nextChunk.Length;
                            }

                            if (encounteredFlushBoundary)
                            {
                                break;
                            }

                            if (nextChunk is not null)
                            {
                                continue;
                            }
                        }

                        if (encounteredFlushBoundary)
                        {
                            break;
                        }

                        if (_writeLock.CurrentCount == 0 || idleYieldsRemaining > 0)
                        {
                            idleYieldsRemaining--;
                            await Task.Yield();
                            continue;
                        }

                        break;
                    }

                    var bufferedPayload = CombineChunks(bufferedChunks, bufferedLength);
                    for (var offset = 0; offset < bufferedPayload.Length; offset += _maxUploadSize)
                    {
                        var currentLength = Math.Min(_maxUploadSize, bufferedPayload.Length - offset);
                        await DelayForNextUploadAsync().ConfigureAwait(false);
                        ThrowIfUploadFaulted();
                        var payload = bufferedPayload.Slice(offset, currentLength);
                        var sequence = _nextSequence++;
                        await SendPacketWithRetryAsync(sequence, payload).ConfigureAwait(false);
                    }
                }
            }
            catch (Exception ex)
            {
                SetUploadFault(ex);
                throw;
            }
        }

        private async Task SendPacketWithRetryAsync(long sequence, ReadOnlyMemory<byte> payload)
        {
            var request = BuildPacketUploadRequest(
                _method,
                _authority,
                _internetStack,
                _options,
                _xPaddingOptions,
                _sessionPlacement,
                _sessionKey,
                _sessionId,
                _seqPlacement,
                _seqKey,
                _uplinkDataPlacement,
                _uplinkDataKey,
                _uplinkChunkSize,
                sequence,
                payload);

            if (PrefersHttp3Transport(_internetStack, _options))
            {
                if (_sharedHttp3UploadPoolManager is not null)
                {
                    await EnsureSharedHttp3UploadPoolLeaseAsync().ConfigureAwait(false);
                }

                if (_sharedHttp3UploadPoolLease is not null &&
                    await TrySendOnSharedHttp3ConnectionAsync(request).ConfigureAwait(false))
                {
                    return;
                }

                if (_localHttp3UploadPoolManager is not null)
                {
                    await EnsureLocalHttp3UploadPoolLeaseAsync().ConfigureAwait(false);
                }

                if (_localHttp3UploadPoolLease is not null &&
                    await TrySendOnLocalHttp3ConnectionAsync(request).ConfigureAwait(false))
                {
                    return;
                }

                await SendOnFreshHttp3ConnectionAsync(request).ConfigureAwait(false);
                return;
            }

            if (_sharedHttp2UploadPoolManager is not null)
            {
                await EnsureSharedHttp2UploadPoolLeaseAsync().ConfigureAwait(false);
            }

            if (_sharedHttp2UploadPoolLease is not null &&
                await TrySendOnSharedHttp2ConnectionAsync(request).ConfigureAwait(false))
            {
                return;
            }

            if (_localHttp2UploadPoolManager is not null)
            {
                await EnsureLocalHttp2UploadPoolLeaseAsync().ConfigureAwait(false);
            }

            if (_localHttp2UploadPoolLease is not null &&
                await TrySendOnLocalHttp2ConnectionAsync(request).ConfigureAwait(false))
            {
                return;
            }

            if (await TrySendOnReusableConnectionAsync(request).ConfigureAwait(false))
            {
                return;
            }

            if (_sharedUploadPoolManager is not null)
            {
                await EnsureSharedUploadPoolLeaseAsync().ConfigureAwait(false);
            }

            if (_sharedUploadPoolLease is not null &&
                await TrySendOnSharedConnectionAsync(request).ConfigureAwait(false))
            {
                return;
            }

            await SendOnFreshConnectionAsync(request).ConfigureAwait(false);
        }

        private async Task<bool> TrySendOnReusableConnectionAsync(
            SplitHttpPacketUploadRequest request)
        {
            if (_reusableUploadConnection is null)
            {
                return false;
            }

            var reusableConnection = _reusableUploadConnection;
            _reusableUploadConnection = null;
            if (reusableConnection is null)
            {
                return false;
            }

            try
            {
                if (!reusableConnection.CanAcceptRequests)
                {
                    await reusableConnection.DisposeAsync().ConfigureAwait(false);
                    return false;
                }

                var responseTask = await reusableConnection
                    .StartSendAsync(request, CancellationToken.None)
                    .ConfigureAwait(false);
                ObserveBackgroundUploadResponse(responseTask);
                if (reusableConnection.CanAcceptRequests)
                {
                    _reusableUploadConnection = reusableConnection;
                }
                else
                {
                    reusableConnection.DisposeWhenResponseCompletes();
                }

                return true;
            }
            catch (PacketUploadConnectionException)
            {
                await reusableConnection.DisposeAsync().ConfigureAwait(false);
                return false;
            }
        }

        private async Task<bool> TrySendOnSharedConnectionAsync(
            SplitHttpPacketUploadRequest request)
        {
            var sharedUploadPool = _sharedUploadPoolLease?.Pool;
            if (sharedUploadPool is null)
            {
                return false;
            }

            while (sharedUploadPool.TryRent(out var pooledConnection))
            {
                try
                {
                    if (!pooledConnection.CanAcceptRequests)
                    {
                        await pooledConnection.DisposeAsync().ConfigureAwait(false);
                        continue;
                    }

                    var responseTask = await pooledConnection
                        .StartSendAsync(request, CancellationToken.None)
                        .ConfigureAwait(false);
                    ObserveBackgroundUploadResponse(responseTask);
                    if (pooledConnection.CanAcceptRequests)
                    {
                        await sharedUploadPool.ReturnAsync(pooledConnection).ConfigureAwait(false);
                    }
                    else
                    {
                        pooledConnection.DisposeWhenResponseCompletes();
                    }

                    return true;
                }
                catch (PacketUploadConnectionException)
                {
                    await pooledConnection.DisposeAsync().ConfigureAwait(false);
                }
            }

            return false;
        }

        private async Task SendOnFreshConnectionAsync(
            SplitHttpPacketUploadRequest request)
        {
            RuntimeInternetConnectionContext? freshContext = null;
            SplitHttpHttp11UploadConnection? freshConnection = null;
            try
            {
                freshContext = await OpenPacketUploadContextAsync(
                        _options,
                        _internetStack,
                        _internetProfile,
                        _dnsResolver,
                        CancellationToken.None)
                    .ConfigureAwait(false);

                if (ShouldUseHttp2(freshContext))
                {
                    await SendPacketRequestAsync(
                            freshContext,
                            _internetStack,
                            request,
                            CreateSplitHttpHttp2SessionOptions(_splitHttpXmux),
                            CancellationToken.None)
                        .ConfigureAwait(false);
                    return;
                }

                freshConnection = new SplitHttpHttp11UploadConnection(freshContext);
                freshContext = null;
                var responseTask = await freshConnection
                    .StartSendAsync(request, CancellationToken.None)
                    .ConfigureAwait(false);
                ObserveBackgroundUploadResponse(responseTask);
                if (_sharedUploadPoolLease is null)
                {
                    _reusableUploadConnection = freshConnection;
                }
                else
                {
                    await _sharedUploadPoolLease.ReturnAsync(freshConnection).ConfigureAwait(false);
                }

                freshConnection = null;
            }
            finally
            {
                if (freshConnection is not null)
                {
                    await freshConnection.DisposeAsync().ConfigureAwait(false);
                }

                if (freshContext is not null)
                {
                    await RuntimeGrpcClientConnector.DisposeTransportContextAsync(freshContext).ConfigureAwait(false);
                }
            }
        }

        private async Task SendOnFreshHttp3ConnectionAsync(
            SplitHttpPacketUploadRequest request)
        {
            RuntimeHttp3ClientSession? session = null;
            try
            {
                session = await OpenHttp3SessionOnlyAsync(
                        _options,
                        _internetStack,
                        _dnsResolver,
                        CancellationToken.None)
                    .ConfigureAwait(false);
                await SendPacketRequestAsync(
                        session,
                        _internetStack,
                        request,
                        CancellationToken.None)
                    .ConfigureAwait(false);
                session = null;
            }
            finally
            {
                if (session is not null)
                {
                    await session.DisposeAsync().ConfigureAwait(false);
                }
            }
        }

        private async Task<bool> TrySendOnSharedHttp3ConnectionAsync(
            SplitHttpPacketUploadRequest request)
        {
            const int maxAttempts = 2;
            for (var attempt = 0; attempt < maxAttempts; attempt++)
            {
                await EnsureSharedHttp3UploadPoolLeaseAsync().ConfigureAwait(false);
                var lease = _sharedHttp3UploadPoolLease;
                if (lease is null)
                {
                    return false;
                }

                var responseTask = await lease
                    .StartSendAsync(
                        ct => OpenHttp3SessionAsync(
                            _options,
                            _internetStack,
                            _dnsResolver,
                            ct),
                        _internetStack,
                        request,
                        CancellationToken.None)
                    .ConfigureAwait(false);
                if (responseTask is not null)
                {
                    ObserveBackgroundUploadResponse(responseTask);
                    return true;
                }

                await lease.DisposeAsync().ConfigureAwait(false);
                if (ReferenceEquals(_sharedHttp3UploadPoolLease, lease))
                {
                    _sharedHttp3UploadPoolLease = null;
                }
            }

            return false;
        }

        private async Task<bool> TrySendOnLocalHttp3ConnectionAsync(
            SplitHttpPacketUploadRequest request)
        {
            const int maxAttempts = 2;
            for (var attempt = 0; attempt < maxAttempts; attempt++)
            {
                await EnsureLocalHttp3UploadPoolLeaseAsync().ConfigureAwait(false);
                var lease = _localHttp3UploadPoolLease;
                if (lease is null)
                {
                    return false;
                }

                var responseTask = await lease
                    .StartSendAsync(
                        ct => OpenHttp3SessionAsync(
                            _options,
                            _internetStack,
                            _dnsResolver,
                            ct),
                        _internetStack,
                        request,
                        CancellationToken.None)
                    .ConfigureAwait(false);
                if (responseTask is not null)
                {
                    ObserveBackgroundUploadResponse(responseTask);
                    return true;
                }

                await lease.DisposeAsync().ConfigureAwait(false);
                if (ReferenceEquals(_localHttp3UploadPoolLease, lease))
                {
                    _localHttp3UploadPoolLease = null;
                }
            }

            return false;
        }

        private async Task<bool> TrySendOnSharedHttp2ConnectionAsync(
            SplitHttpPacketUploadRequest request)
        {
            const int maxAttempts = 2;
            for (var attempt = 0; attempt < maxAttempts; attempt++)
            {
                await EnsureSharedHttp2UploadPoolLeaseAsync().ConfigureAwait(false);
                var lease = _sharedHttp2UploadPoolLease;
                if (lease is null)
                {
                    return false;
                }

                var responseTask = await lease
                    .StartSendAsync(
                        ct => OpenPacketUploadContextAsync(
                            _options,
                            _internetStack,
                            _internetProfile,
                            _dnsResolver,
                            ct),
                        _internetStack,
                        request,
                        CancellationToken.None)
                    .ConfigureAwait(false);
                if (responseTask is not null)
                {
                    ObserveBackgroundUploadResponse(responseTask);
                    return true;
                }

                await lease.DisposeAsync().ConfigureAwait(false);
                if (ReferenceEquals(_sharedHttp2UploadPoolLease, lease))
                {
                    _sharedHttp2UploadPoolLease = null;
                }
            }

            return false;
        }

        private async Task<bool> TrySendOnLocalHttp2ConnectionAsync(
            SplitHttpPacketUploadRequest request)
        {
            const int maxAttempts = 2;
            for (var attempt = 0; attempt < maxAttempts; attempt++)
            {
                await EnsureLocalHttp2UploadPoolLeaseAsync().ConfigureAwait(false);
                var lease = _localHttp2UploadPoolLease;
                if (lease is null)
                {
                    return false;
                }

                var responseTask = await lease
                    .StartSendAsync(
                        ct => OpenPacketUploadContextAsync(
                            _options,
                            _internetStack,
                            _internetProfile,
                            _dnsResolver,
                            ct),
                        _internetStack,
                        request,
                        CancellationToken.None)
                    .ConfigureAwait(false);
                if (responseTask is not null)
                {
                    ObserveBackgroundUploadResponse(responseTask);
                    return true;
                }

                await lease.DisposeAsync().ConfigureAwait(false);
                if (ReferenceEquals(_localHttp2UploadPoolLease, lease))
                {
                    _localHttp2UploadPoolLease = null;
                }
            }

            return false;
        }

        private async ValueTask EnsureSharedHttp3UploadPoolLeaseAsync()
        {
            if (_sharedHttp3UploadPoolManager is null)
            {
                return;
            }

            while (true)
            {
                _sharedHttp3UploadPoolLease ??= _sharedHttp3UploadPoolManager.Acquire();
                if (_sharedHttp3UploadPoolLease.TryBeginRequest(DateTime.UtcNow))
                {
                    return;
                }

                await _sharedHttp3UploadPoolLease.DisposeAsync().ConfigureAwait(false);
                _sharedHttp3UploadPoolLease = null;
            }
        }

        private async ValueTask EnsureSharedUploadPoolLeaseAsync()
        {
            if (_sharedUploadPoolManager is null)
            {
                return;
            }

            while (true)
            {
                _sharedUploadPoolLease ??= _sharedUploadPoolManager.Acquire();
                if (_sharedUploadPoolLease.TryBeginRequest(DateTime.UtcNow))
                {
                    return;
                }

                await _sharedUploadPoolLease.DisposeAsync().ConfigureAwait(false);
                _sharedUploadPoolLease = null;
            }
        }

        private async ValueTask EnsureSharedHttp2UploadPoolLeaseAsync()
        {
            if (_sharedHttp2UploadPoolManager is null)
            {
                return;
            }

            while (true)
            {
                _sharedHttp2UploadPoolLease ??= _sharedHttp2UploadPoolManager.Acquire();
                if (_sharedHttp2UploadPoolLease.TryBeginRequest(DateTime.UtcNow))
                {
                    return;
                }

                await _sharedHttp2UploadPoolLease.DisposeAsync().ConfigureAwait(false);
                _sharedHttp2UploadPoolLease = null;
            }
        }

        private async ValueTask EnsureLocalHttp3UploadPoolLeaseAsync()
        {
            if (_localHttp3UploadPoolManager is null)
            {
                return;
            }

            while (true)
            {
                _localHttp3UploadPoolLease ??= _localHttp3UploadPoolManager.Acquire();
                if (_localHttp3UploadPoolLease.TryBeginRequest(DateTime.UtcNow))
                {
                    return;
                }

                await _localHttp3UploadPoolLease.DisposeAsync().ConfigureAwait(false);
                _localHttp3UploadPoolLease = null;
            }
        }

        private async ValueTask EnsureLocalHttp2UploadPoolLeaseAsync()
        {
            if (_localHttp2UploadPoolManager is null)
            {
                return;
            }

            while (true)
            {
                _localHttp2UploadPoolLease ??= _localHttp2UploadPoolManager.Acquire();
                if (_localHttp2UploadPoolLease.TryBeginRequest(DateTime.UtcNow))
                {
                    return;
                }

                await _localHttp2UploadPoolLease.DisposeAsync().ConfigureAwait(false);
                _localHttp2UploadPoolLease = null;
            }
        }

        private async Task DelayForNextUploadAsync()
        {
            if (!ShouldDelayPacketUploads(_scMinPostsIntervalMs))
            {
                _lastUploadStartedAtUtcTicks = DateTime.UtcNow.Ticks;
                return;
            }

            var intervalMs = GetRandomRangeValue(_scMinPostsIntervalMs);
            if (intervalMs <= 0)
            {
                _lastUploadStartedAtUtcTicks = DateTime.UtcNow.Ticks;
                return;
            }

            var previousTicks = Interlocked.Read(ref _lastUploadStartedAtUtcTicks);
            if (previousTicks > 0)
            {
                var nextAllowedAt = new DateTime(previousTicks, DateTimeKind.Utc)
                    .AddMilliseconds(intervalMs);
                var delay = nextAllowedAt - DateTime.UtcNow;
                if (delay > TimeSpan.Zero)
                {
                    await Task.Delay(delay).ConfigureAwait(false);
                }
            }

            Interlocked.Exchange(ref _lastUploadStartedAtUtcTicks, DateTime.UtcNow.Ticks);
        }

        private static ReadOnlyMemory<byte> CombineChunks(IReadOnlyList<byte[]> chunks, int totalLength)
        {
            if (chunks.Count == 1)
            {
                return chunks[0];
            }

            var combined = new byte[totalLength];
            var offset = 0;
            foreach (var chunk in chunks)
            {
                Buffer.BlockCopy(chunk, 0, combined, offset, chunk.Length);
                offset += chunk.Length;
            }

            return combined;
        }

        private void ThrowIfUploadFaulted()
        {
            if (_uploadFault is not null)
            {
                ExceptionDispatchInfo.Capture(_uploadFault).Throw();
            }
        }

        private void ObserveBackgroundUploadResponse(Task responseTask)
        {
            _ = ObserveBackgroundUploadResponseCoreAsync(responseTask);
        }

        private async Task ObserveBackgroundUploadResponseCoreAsync(Task responseTask)
        {
            try
            {
                await responseTask.ConfigureAwait(false);
            }
            catch (Exception ex)
            {
                if (Volatile.Read(ref _disposed) == 0)
                {
                    SetUploadFault(ex);
                }
            }
        }

        private void SetUploadFault(Exception exception)
        {
            ArgumentNullException.ThrowIfNull(exception);
            if (Interlocked.CompareExchange(ref _uploadFault, exception, null) is null)
            {
                _pendingWrites.Complete(exception);
            }
        }
    }

    internal sealed class SplitHttpBufferedUploadPipe
    {
        private readonly object _syncRoot = new();
        private readonly Channel<SplitHttpBufferedUploadEntry> _segments = Channel.CreateUnbounded<SplitHttpBufferedUploadEntry>(
            new UnboundedChannelOptions
            {
                SingleReader = true,
                SingleWriter = false
            });
        private readonly TaskCompletionSource<bool> _completionSignal = new(TaskCreationOptions.RunContinuationsAsynchronously);
        private readonly int _bufferedByteLimit;
        private TaskCompletionSource<bool>? _spaceAvailable;
        private int _bufferedBytes;
        private bool _completed;
        private Exception? _completionException;

        public SplitHttpBufferedUploadPipe(int maxUploadSize)
        {
            if (maxUploadSize <= 0)
            {
                throw new ArgumentOutOfRangeException(nameof(maxUploadSize));
            }

            _bufferedByteLimit = GetBufferedUploadByteLimit(maxUploadSize);
        }

        public int BufferedByteLimit => _bufferedByteLimit;

        public async ValueTask WriteAsync(ReadOnlyMemory<byte> buffer, CancellationToken cancellationToken)
        {
            if (buffer.Length == 0)
            {
                return;
            }

            for (var offset = 0; offset < buffer.Length; offset += UploadPipeSegmentSize)
            {
                var currentLength = Math.Min(UploadPipeSegmentSize, buffer.Length - offset);
                await WaitForSpaceAsync(cancellationToken).ConfigureAwait(false);

                lock (_syncRoot)
                {
                    ThrowIfCompletedNoLock();
                    _bufferedBytes += currentLength;
                }

                if (_segments.Writer.TryWrite(
                        SplitHttpBufferedUploadEntry.CreateSegment(buffer.Slice(offset, currentLength).ToArray())))
                {
                    continue;
                }

                lock (_syncRoot)
                {
                    _bufferedBytes -= currentLength;
                    ThrowIfCompletedNoLock();
                }

                throw new InvalidOperationException("SplitHTTP upload pipe rejected a buffered write.");
            }
        }

        public async ValueTask FlushAsync(CancellationToken cancellationToken)
        {
            Task barrierTask;
            lock (_syncRoot)
            {
                ThrowIfCompletedNoLock();

                var barrier = new TaskCompletionSource<bool>(TaskCreationOptions.RunContinuationsAsynchronously);
                barrierTask = barrier.Task;
                if (!_segments.Writer.TryWrite(SplitHttpBufferedUploadEntry.CreateFlushBoundary(barrier)))
                {
                    ThrowIfCompletedNoLock();
                    throw new InvalidOperationException("SplitHTTP upload pipe rejected a flush boundary.");
                }
            }

            if (barrierTask.IsCompleted)
            {
                await barrierTask.WaitAsync(cancellationToken).ConfigureAwait(false);
                return;
            }

            var completedTask = await Task.WhenAny(barrierTask, _completionSignal.Task)
                .WaitAsync(cancellationToken)
                .ConfigureAwait(false);
            if (ReferenceEquals(completedTask, barrierTask))
            {
                await barrierTask.WaitAsync(cancellationToken).ConfigureAwait(false);
                return;
            }

            lock (_syncRoot)
            {
                if (_completionException is not null)
                {
                    ExceptionDispatchInfo.Capture(_completionException).Throw();
                }
            }
        }

        public async ValueTask<byte[]?> ReadAsync(CancellationToken cancellationToken)
        {
            while (await _segments.Reader.WaitToReadAsync(cancellationToken).ConfigureAwait(false))
            {
                while (_segments.Reader.TryRead(out var entry))
                {
                    if (entry.TryCompleteFlushBoundary())
                    {
                        continue;
                    }

                    var firstSegment = entry.Segment!;
                    lock (_syncRoot)
                    {
                        _bufferedBytes -= firstSegment.Length;
                        SignalSpaceAvailableNoLock();
                    }

                    return firstSegment;
                }
            }

            return null;
        }

        public bool TryReadAvailable(out byte[]? chunk, out bool encounteredFlushBoundary)
        {
            List<byte[]>? segments = null;
            var totalLength = 0;
            encounteredFlushBoundary = false;
            while (_segments.Reader.TryRead(out var entry))
            {
                if (entry.TryCompleteFlushBoundary())
                {
                    encounteredFlushBoundary = true;
                    break;
                }

                var segment = entry.Segment!;
                (segments ??= []).Add(segment);
                totalLength += segment.Length;
            }

            if (segments is null)
            {
                chunk = null;
                return false;
            }

            lock (_syncRoot)
            {
                _bufferedBytes -= totalLength;
                SignalSpaceAvailableNoLock();
            }

            if (segments.Count == 1)
            {
                chunk = segments[0];
                return true;
            }

            chunk = new byte[totalLength];
            var offset = 0;
            foreach (var segment in segments)
            {
                Buffer.BlockCopy(segment, 0, chunk, offset, segment.Length);
                offset += segment.Length;
            }

            return true;
        }

        public void Complete(Exception? exception = null)
        {
            TaskCompletionSource<bool>? waiter = null;
            lock (_syncRoot)
            {
                if (!_completed)
                {
                    _completed = true;
                }

                if (_completionException is null && exception is not null)
                {
                    _completionException = exception;
                }

                waiter = _spaceAvailable;
                _spaceAvailable = null;
            }

            waiter?.TrySetResult(true);
            _segments.Writer.TryComplete();
            _completionSignal.TrySetResult(true);
        }

        private async ValueTask WaitForSpaceAsync(CancellationToken cancellationToken)
        {
            while (true)
            {
                Task waitTask;
                lock (_syncRoot)
                {
                    ThrowIfCompletedNoLock();
                    if (_bufferedBytes <= _bufferedByteLimit)
                    {
                        return;
                    }

                    _spaceAvailable ??= new TaskCompletionSource<bool>(TaskCreationOptions.RunContinuationsAsynchronously);
                    waitTask = _spaceAvailable.Task;
                }

                await waitTask.WaitAsync(cancellationToken).ConfigureAwait(false);
            }
        }

        private void SignalSpaceAvailableNoLock()
        {
            if (_bufferedBytes > _bufferedByteLimit ||
                _spaceAvailable is null)
            {
                return;
            }

            var waiter = _spaceAvailable;
            _spaceAvailable = null;
            waiter.TrySetResult(true);
        }

        private void ThrowIfCompletedNoLock()
        {
            if (_completionException is not null)
            {
                ExceptionDispatchInfo.Capture(_completionException).Throw();
            }

            if (_completed)
            {
                throw new InvalidOperationException("SplitHTTP upload pipe is completed.");
            }
        }

        private sealed class SplitHttpBufferedUploadEntry
        {
            private SplitHttpBufferedUploadEntry(byte[]? segment, TaskCompletionSource<bool>? flushBoundary)
            {
                Segment = segment;
                FlushBoundary = flushBoundary;
            }

            public byte[]? Segment { get; }

            private TaskCompletionSource<bool>? FlushBoundary { get; }

            public static SplitHttpBufferedUploadEntry CreateSegment(byte[] segment)
            {
                ArgumentNullException.ThrowIfNull(segment);
                return new SplitHttpBufferedUploadEntry(segment, flushBoundary: null);
            }

            public static SplitHttpBufferedUploadEntry CreateFlushBoundary(TaskCompletionSource<bool> flushBoundary)
            {
                ArgumentNullException.ThrowIfNull(flushBoundary);
                return new SplitHttpBufferedUploadEntry(segment: null, flushBoundary: flushBoundary);
            }

            public bool TryCompleteFlushBoundary()
            {
                if (FlushBoundary is null)
                {
                    return false;
                }

                FlushBoundary.TrySetResult(true);
                return true;
            }
        }
    }

    private sealed class SplitHttpHttp3UploadPoolManager
    {
        private readonly object _syncRoot = new();
        private readonly RuntimeSplitHttpXmuxOptions _xmux;
        private readonly int _maxConcurrency;
        private readonly int _maxConnections;
        private readonly List<SplitHttpHttp3UploadPool> _pools = [];

        public SplitHttpHttp3UploadPoolManager(RuntimeSplitHttpXmuxOptions xmux)
        {
            _xmux = NormalizeSplitHttpXmuxOptions(xmux);
            _maxConcurrency = GetRandomRangeValue(_xmux.MaxConcurrency);
            _maxConnections = GetRandomRangeValue(_xmux.MaxConnections);
        }

        public SplitHttpHttp3UploadPoolLease Acquire()
        {
            SplitHttpHttp3UploadPool pool;
            List<SplitHttpHttp3UploadPool>? poolsToDispose = null;

            lock (_syncRoot)
            {
                PrunePools(DateTime.UtcNow, ref poolsToDispose);

                if (_pools.Count == 0)
                {
                    pool = CreatePool();
                    pool.AcquireNewLease();
                }
                else
                {
                    var selectablePools = _pools
                        .Where(currentPool => currentPool.CanAcceptLease(DateTime.UtcNow))
                        .ToList();

                    if (_maxConnections > 0 &&
                        selectablePools.Count < _maxConnections)
                    {
                        pool = CreatePool();
                        pool.AcquireNewLease();
                    }
                    else
                    {
                        var candidates = _maxConcurrency > 0
                            ? selectablePools.Where(currentPool => currentPool.OpenUsage < _maxConcurrency).ToList()
                            : selectablePools;
                        if (candidates.Count == 0)
                        {
                            pool = CreatePool();
                            pool.AcquireNewLease();
                        }
                        else
                        {
                            pool = candidates[Random.Shared.Next(candidates.Count)];
                            pool.AcquireExistingLease();
                        }
                    }
                }
            }

            DisposePoolsSynchronously(poolsToDispose);
            return new SplitHttpHttp3UploadPoolLease(this, pool);
        }

        public async ValueTask ReleaseAsync(SplitHttpHttp3UploadPool pool)
        {
            ArgumentNullException.ThrowIfNull(pool);

            List<SplitHttpHttp3UploadPool>? poolsToDispose = null;
            lock (_syncRoot)
            {
                pool.ReleaseLease();
                PrunePools(DateTime.UtcNow, ref poolsToDispose);
            }

            await DisposePoolsAsync(poolsToDispose).ConfigureAwait(false);
        }

        private SplitHttpHttp3UploadPool CreatePool()
        {
            var cMaxReuseTimes = GetRandomRangeValue(_xmux.CMaxReuseTimes);
            var hMaxRequestTimes = GetRandomRangeValue(_xmux.HMaxRequestTimes);
            var hMaxReusableSecs = GetRandomRangeValue(_xmux.HMaxReusableSecs);
            var pool = new SplitHttpHttp3UploadPool(
                remainingLeaseReuses: cMaxReuseTimes > 0 ? cMaxReuseTimes - 1 : -1,
                remainingRequests: hMaxRequestTimes > 0 ? hMaxRequestTimes : int.MaxValue,
                unreusableAtUtcTicks: hMaxReusableSecs > 0
                    ? DateTime.UtcNow.AddSeconds(hMaxReusableSecs).Ticks
                    : 0);
            _pools.Add(pool);
            return pool;
        }

        private void PrunePools(
            DateTime utcNow,
            ref List<SplitHttpHttp3UploadPool>? poolsToDispose)
        {
            for (var index = _pools.Count - 1; index >= 0; index--)
            {
                var pool = _pools[index];
                if (!pool.ShouldRemove(utcNow))
                {
                    continue;
                }

                _pools.RemoveAt(index);
                (poolsToDispose ??= []).Add(pool);
            }
        }

        private static void DisposePoolsSynchronously(IReadOnlyList<SplitHttpHttp3UploadPool>? pools)
        {
            if (pools is null)
            {
                return;
            }

            foreach (var pool in pools)
            {
                pool.DisposeAsync().AsTask().GetAwaiter().GetResult();
            }
        }

        private static async ValueTask DisposePoolsAsync(IReadOnlyList<SplitHttpHttp3UploadPool>? pools)
        {
            if (pools is null)
            {
                return;
            }

            foreach (var pool in pools)
            {
                await pool.DisposeAsync().ConfigureAwait(false);
            }
        }
    }

    private sealed class SplitHttpHttp3UploadPoolLease : IAsyncDisposable
    {
        private readonly SplitHttpHttp3UploadPoolManager _manager;
        private int _disposed;

        public SplitHttpHttp3UploadPoolLease(
            SplitHttpHttp3UploadPoolManager manager,
            SplitHttpHttp3UploadPool pool)
        {
            _manager = manager ?? throw new ArgumentNullException(nameof(manager));
            Pool = pool ?? throw new ArgumentNullException(nameof(pool));
        }

        public SplitHttpHttp3UploadPool Pool { get; }

        public bool TryBeginRequest(DateTime utcNow)
            => Pool.TryBeginRequest(utcNow);

        public void RecordStreamRequest(DateTime utcNow)
            => Pool.RecordStreamRequest(utcNow);

        public RuntimeInternetSecurityState? CloneSecurityState()
            => Pool.CloneSecurityState();

        public ValueTask<Stream?> OpenRequestStreamAsync(
            Func<CancellationToken, ValueTask<(RuntimeHttp3ClientSession Session, RuntimeInternetSecurityState SecurityState)>> sessionFactory,
            RuntimeInternetStack internetStack,
            string method,
            string authority,
            string requestTarget,
            IReadOnlyDictionary<string, string> requestHeaders,
            bool includeContentType,
            bool waitForSuccessfulStatus,
            bool endStreamOnHeaders,
            CancellationToken cancellationToken)
            => Pool.OpenRequestStreamAsync(
                sessionFactory,
                internetStack,
                method,
                authority,
                requestTarget,
                requestHeaders,
                includeContentType,
                waitForSuccessfulStatus,
                endStreamOnHeaders,
                cancellationToken);

        public ValueTask<Task?> StartSendAsync(
            Func<CancellationToken, ValueTask<(RuntimeHttp3ClientSession Session, RuntimeInternetSecurityState SecurityState)>> sessionFactory,
            RuntimeInternetStack internetStack,
            SplitHttpPacketUploadRequest request,
            CancellationToken cancellationToken)
            => Pool.StartSendAsync(sessionFactory, internetStack, request, cancellationToken);

        public async ValueTask DisposeAsync()
        {
            if (Interlocked.Exchange(ref _disposed, 1) != 0)
            {
                return;
            }

            await _manager.ReleaseAsync(Pool).ConfigureAwait(false);
        }
    }

    private sealed class SplitHttpHttp3UploadPool : IAsyncDisposable
    {
        private readonly SemaphoreSlim _sessionGate = new(1, 1);
        private readonly long _unreusableAtUtcTicks;
        private RuntimeHttp3ClientSession? _session;
        private RuntimeInternetSecurityState? _securityState;
        private int _openUsage;
        private int _remainingLeaseReuses;
        private int _remainingRequests;
        private int _acceptNewLeases;
        private int _acceptRequests = 1;
        private int _disposed;

        public SplitHttpHttp3UploadPool(
            int remainingLeaseReuses,
            int remainingRequests,
            long unreusableAtUtcTicks)
        {
            _remainingLeaseReuses = remainingLeaseReuses;
            _remainingRequests = remainingRequests;
            _unreusableAtUtcTicks = unreusableAtUtcTicks;
            _acceptNewLeases = remainingLeaseReuses == 0 ? 0 : 1;
        }

        public int OpenUsage => Volatile.Read(ref _openUsage);

        public bool CanAcceptLease(DateTime utcNow)
        {
            RefreshLifetime(utcNow);
            return Volatile.Read(ref _acceptNewLeases) != 0;
        }

        public void AcquireNewLease()
            => Interlocked.Increment(ref _openUsage);

        public void AcquireExistingLease()
        {
            Interlocked.Increment(ref _openUsage);
            if (_remainingLeaseReuses < 0)
            {
                return;
            }

            if (_remainingLeaseReuses == 0)
            {
                Interlocked.Exchange(ref _acceptNewLeases, 0);
                return;
            }

            if (Interlocked.Decrement(ref _remainingLeaseReuses) <= 0)
            {
                Interlocked.Exchange(ref _acceptNewLeases, 0);
            }
        }

        public void ReleaseLease()
            => Interlocked.Decrement(ref _openUsage);

        public bool TryBeginRequest(DateTime utcNow)
        {
            RefreshLifetime(utcNow);
            if (Volatile.Read(ref _acceptRequests) == 0)
            {
                return false;
            }

            if (_remainingRequests == int.MaxValue)
            {
                return true;
            }

            var remainingRequests = Interlocked.Decrement(ref _remainingRequests);
            if (remainingRequests < 0)
            {
                Interlocked.Exchange(ref _acceptRequests, 0);
                Interlocked.Exchange(ref _acceptNewLeases, 0);
                return false;
            }

            if (remainingRequests == 0)
            {
                Interlocked.Exchange(ref _acceptRequests, 0);
                Interlocked.Exchange(ref _acceptNewLeases, 0);
            }

            return true;
        }

        public void RecordStreamRequest(DateTime utcNow)
        {
            RefreshLifetime(utcNow);
            if (_remainingRequests == int.MaxValue)
            {
                return;
            }

            var remainingRequests = Interlocked.Decrement(ref _remainingRequests);
            if (remainingRequests <= 0)
            {
                Interlocked.Exchange(ref _acceptRequests, 0);
                Interlocked.Exchange(ref _acceptNewLeases, 0);
            }
        }

        public RuntimeInternetSecurityState? CloneSecurityState()
            => _securityState is null
                ? null
                : RuntimeSplitHttpClientConnector.CloneSecurityState(_securityState);

        public async ValueTask<Stream?> OpenRequestStreamAsync(
            Func<CancellationToken, ValueTask<(RuntimeHttp3ClientSession Session, RuntimeInternetSecurityState SecurityState)>> sessionFactory,
            RuntimeInternetStack internetStack,
            string method,
            string authority,
            string requestTarget,
            IReadOnlyDictionary<string, string> requestHeaders,
            bool includeContentType,
            bool waitForSuccessfulStatus,
            bool endStreamOnHeaders,
            CancellationToken cancellationToken)
        {
            ArgumentNullException.ThrowIfNull(sessionFactory);
            ArgumentException.ThrowIfNullOrWhiteSpace(method);
            ArgumentException.ThrowIfNullOrWhiteSpace(authority);
            ArgumentException.ThrowIfNullOrWhiteSpace(requestTarget);
            ArgumentNullException.ThrowIfNull(requestHeaders);

            for (var attempt = 0; attempt < 2; attempt++)
            {
                var session = await GetOrCreateSessionAsync(sessionFactory, cancellationToken).ConfigureAwait(false);
                if (session is null)
                {
                    return null;
                }

                try
                {
                    return await session
                        .OpenHttpRequestStreamAsync(
                            method,
                            authority,
                            ResolveHttpScheme(internetStack),
                            requestTarget,
                            CreateHttp2RequestHeaders(requestHeaders, includeContentType),
                            Array.Empty<byte>(),
                            waitForSuccessfulStatus,
                            cancellationToken,
                            disposeSessionOnClose: false,
                            endRequestOnHeaders: endStreamOnHeaders)
                        .ConfigureAwait(false);
                }
                catch (ObjectDisposedException)
                {
                    await ResetSessionAsync().ConfigureAwait(false);
                }
                catch (System.Net.Quic.QuicException)
                {
                    await ResetSessionAsync().ConfigureAwait(false);
                }
                catch (IOException)
                {
                    await ResetSessionAsync().ConfigureAwait(false);
                }
                catch (InvalidOperationException)
                {
                    await ResetSessionAsync().ConfigureAwait(false);
                }
            }

            return null;
        }

        public bool ShouldRemove(DateTime utcNow)
        {
            RefreshLifetime(utcNow);
            return Volatile.Read(ref _openUsage) == 0 &&
                   Volatile.Read(ref _acceptNewLeases) == 0;
        }

        public async ValueTask<Task?> StartSendAsync(
            Func<CancellationToken, ValueTask<(RuntimeHttp3ClientSession Session, RuntimeInternetSecurityState SecurityState)>> sessionFactory,
            RuntimeInternetStack internetStack,
            SplitHttpPacketUploadRequest request,
            CancellationToken cancellationToken)
        {
            ArgumentNullException.ThrowIfNull(sessionFactory);
            ArgumentNullException.ThrowIfNull(request);

            var session = await GetOrCreateSessionAsync(sessionFactory, cancellationToken).ConfigureAwait(false);
            if (session is null)
            {
                return null;
            }

            try
            {
                var pendingRequest = await StartPacketRequestAsync(
                        session,
                        internetStack,
                        request,
                        cancellationToken)
                    .ConfigureAwait(false);
                return CompleteStartedRequestAsync(pendingRequest);
            }
            catch (ObjectDisposedException)
            {
                await ResetSessionAsync().ConfigureAwait(false);
                return null;
            }
            catch (System.Net.Quic.QuicException)
            {
                await ResetSessionAsync().ConfigureAwait(false);
                return null;
            }
            catch (IOException)
            {
                await ResetSessionAsync().ConfigureAwait(false);
                return null;
            }
            catch (InvalidOperationException)
            {
                await ResetSessionAsync().ConfigureAwait(false);
                return null;
            }
        }

        public async ValueTask DisposeAsync()
        {
            if (Interlocked.Exchange(ref _disposed, 1) != 0)
            {
                return;
            }

            await ResetSessionAsync().ConfigureAwait(false);
            _sessionGate.Dispose();
        }

        private async ValueTask<RuntimeHttp3ClientSession?> GetOrCreateSessionAsync(
            Func<CancellationToken, ValueTask<(RuntimeHttp3ClientSession Session, RuntimeInternetSecurityState SecurityState)>> sessionFactory,
            CancellationToken cancellationToken)
        {
            await _sessionGate.WaitAsync(cancellationToken).ConfigureAwait(false);
            try
            {
                if (_session is not null &&
                    _session.CanOpenNewRequest)
                {
                    return _session;
                }

                await ResetSessionCoreAsync().ConfigureAwait(false);
                var openedSession = await sessionFactory(cancellationToken).ConfigureAwait(false);
                _session = openedSession.Session;
                _securityState = openedSession.SecurityState;
                return _session;
            }
            finally
            {
                _sessionGate.Release();
            }
        }

        private async ValueTask ResetSessionAsync()
        {
            await _sessionGate.WaitAsync().ConfigureAwait(false);
            try
            {
                await ResetSessionCoreAsync().ConfigureAwait(false);
            }
            finally
            {
                _sessionGate.Release();
            }
        }

        private async Task CompleteStartedRequestAsync(RuntimeHttp3ClientSession.PendingRequest pendingRequest)
        {
            await using var request = pendingRequest;
            try
            {
                await pendingRequest.DrainResponseAsync(CancellationToken.None).ConfigureAwait(false);
            }
            catch
            {
                await ResetSessionAsync().ConfigureAwait(false);
                throw;
            }
        }

        private async ValueTask ResetSessionCoreAsync()
        {
            if (_session is not null)
            {
                try
                {
                    await _session.DisposeAsync().ConfigureAwait(false);
                }
                catch
                {
                }

                _session = null;
            }

            if (_securityState is not null)
            {
                _securityState.RemoteCertificate?.Dispose();
                _securityState = null;
            }
        }

        private void RefreshLifetime(DateTime utcNow)
        {
            if (_unreusableAtUtcTicks == 0 ||
                utcNow.Ticks <= _unreusableAtUtcTicks)
            {
                return;
            }

            Interlocked.Exchange(ref _acceptRequests, 0);
            Interlocked.Exchange(ref _acceptNewLeases, 0);
        }
    }

    private sealed class SplitHttpSharedUploadPoolManager
    {
        private readonly object _syncRoot = new();
        private readonly RuntimeSplitHttpXmuxOptions _xmux;
        private readonly int _maxConcurrency;
        private readonly int _maxConnections;
        private readonly List<SplitHttpSharedUploadPool> _pools = [];

        public SplitHttpSharedUploadPoolManager(RuntimeSplitHttpXmuxOptions xmux)
        {
            _xmux = NormalizeSplitHttpXmuxOptions(xmux);
            _maxConcurrency = GetRandomRangeValue(_xmux.MaxConcurrency);
            _maxConnections = GetRandomRangeValue(_xmux.MaxConnections);
        }

        public SplitHttpSharedUploadPoolLease Acquire()
        {
            SplitHttpSharedUploadPool pool;
            List<SplitHttpSharedUploadPool>? poolsToDispose = null;

            lock (_syncRoot)
            {
                PrunePools(DateTime.UtcNow, ref poolsToDispose);

                if (_pools.Count == 0)
                {
                    pool = CreatePool();
                    pool.AcquireNewLease();
                }
                else
                {
                    var selectablePools = _pools
                        .Where(currentPool => currentPool.CanAcceptLease(DateTime.UtcNow))
                        .ToList();

                    if (_maxConnections > 0 &&
                        selectablePools.Count < _maxConnections)
                    {
                        pool = CreatePool();
                        pool.AcquireNewLease();
                    }
                    else
                    {
                        var candidates = _maxConcurrency > 0
                            ? selectablePools.Where(currentPool => currentPool.OpenUsage < _maxConcurrency).ToList()
                            : selectablePools;
                        if (candidates.Count == 0)
                        {
                            pool = CreatePool();
                            pool.AcquireNewLease();
                        }
                        else
                        {
                            pool = candidates[Random.Shared.Next(candidates.Count)];
                            pool.AcquireExistingLease();
                        }
                    }
                }
            }

            DisposePoolsSynchronously(poolsToDispose);
            return new SplitHttpSharedUploadPoolLease(this, pool);
        }

        public async ValueTask ReleaseAsync(SplitHttpSharedUploadPool pool)
        {
            ArgumentNullException.ThrowIfNull(pool);

            List<SplitHttpSharedUploadPool>? poolsToDispose = null;
            lock (_syncRoot)
            {
                pool.ReleaseLease();
                PrunePools(DateTime.UtcNow, ref poolsToDispose);
            }

            await DisposePoolsAsync(poolsToDispose).ConfigureAwait(false);
        }

        private SplitHttpSharedUploadPool CreatePool()
        {
            var cMaxReuseTimes = GetRandomRangeValue(_xmux.CMaxReuseTimes);
            var hMaxRequestTimes = GetRandomRangeValue(_xmux.HMaxRequestTimes);
            var hMaxReusableSecs = GetRandomRangeValue(_xmux.HMaxReusableSecs);
            var pool = new SplitHttpSharedUploadPool(
                remainingLeaseReuses: cMaxReuseTimes > 0 ? cMaxReuseTimes - 1 : -1,
                remainingRequests: hMaxRequestTimes > 0 ? hMaxRequestTimes : int.MaxValue,
                unreusableAtUtcTicks: hMaxReusableSecs > 0
                    ? DateTime.UtcNow.AddSeconds(hMaxReusableSecs).Ticks
                    : 0);
            _pools.Add(pool);
            return pool;
        }

        private void PrunePools(
            DateTime utcNow,
            ref List<SplitHttpSharedUploadPool>? poolsToDispose)
        {
            for (var index = _pools.Count - 1; index >= 0; index--)
            {
                var pool = _pools[index];
                if (!pool.ShouldRemove(utcNow))
                {
                    continue;
                }

                _pools.RemoveAt(index);
                (poolsToDispose ??= []).Add(pool);
            }
        }

        private static void DisposePoolsSynchronously(IReadOnlyList<SplitHttpSharedUploadPool>? pools)
        {
            if (pools is null)
            {
                return;
            }

            foreach (var pool in pools)
            {
                pool.DisposeIdleConnectionsAsync().AsTask().GetAwaiter().GetResult();
            }
        }

        private static async ValueTask DisposePoolsAsync(IReadOnlyList<SplitHttpSharedUploadPool>? pools)
        {
            if (pools is null)
            {
                return;
            }

            foreach (var pool in pools)
            {
                await pool.DisposeIdleConnectionsAsync().ConfigureAwait(false);
            }
        }
    }

    private sealed class SplitHttpSharedUploadPoolLease : IAsyncDisposable
    {
        private readonly SplitHttpSharedUploadPoolManager _manager;
        private int _disposed;

        public SplitHttpSharedUploadPoolLease(
            SplitHttpSharedUploadPoolManager manager,
            SplitHttpSharedUploadPool pool)
        {
            _manager = manager ?? throw new ArgumentNullException(nameof(manager));
            Pool = pool ?? throw new ArgumentNullException(nameof(pool));
        }

        public SplitHttpSharedUploadPool Pool { get; }

        public bool TryBeginRequest(DateTime utcNow)
            => Pool.TryBeginRequest(utcNow);

        public ValueTask ReturnAsync(SplitHttpHttp11UploadConnection connection)
            => Pool.ReturnAsync(connection);

        public async ValueTask DisposeAsync()
        {
            if (Interlocked.Exchange(ref _disposed, 1) != 0)
            {
                return;
            }

            await _manager.ReleaseAsync(Pool).ConfigureAwait(false);
        }
    }

    private sealed class SplitHttpSharedUploadPool
    {
        private readonly ConcurrentBag<SplitHttpHttp11UploadConnection> _connections = [];
        private readonly long _unreusableAtUtcTicks;
        private int _openUsage;
        private int _remainingLeaseReuses;
        private int _remainingRequests;
        private int _acceptNewLeases;
        private int _acceptRequests = 1;

        public SplitHttpSharedUploadPool(
            int remainingLeaseReuses,
            int remainingRequests,
            long unreusableAtUtcTicks)
        {
            _remainingLeaseReuses = remainingLeaseReuses;
            _remainingRequests = remainingRequests;
            _unreusableAtUtcTicks = unreusableAtUtcTicks;
            _acceptNewLeases = remainingLeaseReuses == 0 ? 0 : 1;
        }

        public int OpenUsage => Volatile.Read(ref _openUsage);

        public bool CanAcceptLease(DateTime utcNow)
        {
            RefreshLifetime(utcNow);
            return Volatile.Read(ref _acceptNewLeases) != 0;
        }

        public void AcquireNewLease()
            => Interlocked.Increment(ref _openUsage);

        public void AcquireExistingLease()
        {
            Interlocked.Increment(ref _openUsage);
            if (_remainingLeaseReuses < 0)
            {
                return;
            }

            if (_remainingLeaseReuses == 0)
            {
                Interlocked.Exchange(ref _acceptNewLeases, 0);
                return;
            }

            if (Interlocked.Decrement(ref _remainingLeaseReuses) <= 0)
            {
                Interlocked.Exchange(ref _acceptNewLeases, 0);
            }
        }

        public void ReleaseLease()
            => Interlocked.Decrement(ref _openUsage);

        public bool TryBeginRequest(DateTime utcNow)
        {
            RefreshLifetime(utcNow);
            if (Volatile.Read(ref _acceptRequests) == 0)
            {
                return false;
            }

            if (_remainingRequests == int.MaxValue)
            {
                return true;
            }

            var remainingRequests = Interlocked.Decrement(ref _remainingRequests);
            if (remainingRequests < 0)
            {
                Interlocked.Exchange(ref _acceptRequests, 0);
                Interlocked.Exchange(ref _acceptNewLeases, 0);
                return false;
            }

            if (remainingRequests == 0)
            {
                Interlocked.Exchange(ref _acceptRequests, 0);
                Interlocked.Exchange(ref _acceptNewLeases, 0);
            }

            return true;
        }

        public bool TryRent(out SplitHttpHttp11UploadConnection connection)
            => _connections.TryTake(out connection!);

        public async ValueTask ReturnAsync(SplitHttpHttp11UploadConnection connection)
        {
            ArgumentNullException.ThrowIfNull(connection);

            if (Volatile.Read(ref _acceptRequests) == 0 ||
                !connection.CanAcceptRequests)
            {
                connection.DisposeWhenResponseCompletes();
                return;
            }

            _connections.Add(connection);
        }

        public bool ShouldRemove(DateTime utcNow)
        {
            RefreshLifetime(utcNow);
            return Volatile.Read(ref _openUsage) == 0 &&
                   Volatile.Read(ref _acceptNewLeases) == 0;
        }

        public ValueTask DisposeIdleConnectionsAsync()
        {
            while (_connections.TryTake(out var connection))
            {
                connection.DisposeWhenResponseCompletes();
            }

            return ValueTask.CompletedTask;
        }

        private void RefreshLifetime(DateTime utcNow)
        {
            if (_unreusableAtUtcTicks == 0 ||
                utcNow.Ticks <= _unreusableAtUtcTicks)
            {
                return;
            }

            Interlocked.Exchange(ref _acceptRequests, 0);
            Interlocked.Exchange(ref _acceptNewLeases, 0);
        }
    }

    private sealed class SplitHttpHttp2UploadPoolManager
    {
        private readonly object _syncRoot = new();
        private readonly RuntimeSplitHttpXmuxOptions _xmux;
        private readonly Http2TunnelSessionOptions _sessionOptions;
        private readonly int _maxConcurrency;
        private readonly int _maxConnections;
        private readonly List<SplitHttpHttp2UploadPool> _pools = [];

        public SplitHttpHttp2UploadPoolManager(RuntimeSplitHttpXmuxOptions xmux)
        {
            _xmux = NormalizeSplitHttpXmuxOptions(xmux);
            _sessionOptions = CreateSplitHttpHttp2SessionOptions(_xmux);
            _maxConcurrency = GetRandomRangeValue(_xmux.MaxConcurrency);
            _maxConnections = GetRandomRangeValue(_xmux.MaxConnections);
        }

        public SplitHttpHttp2UploadPoolLease Acquire()
        {
            SplitHttpHttp2UploadPool pool;
            List<SplitHttpHttp2UploadPool>? poolsToDispose = null;

            lock (_syncRoot)
            {
                PrunePools(DateTime.UtcNow, ref poolsToDispose);

                if (_pools.Count == 0)
                {
                    pool = CreatePool();
                    pool.AcquireNewLease();
                }
                else
                {
                    var selectablePools = _pools
                        .Where(currentPool => currentPool.CanAcceptLease(DateTime.UtcNow))
                        .ToList();

                    if (_maxConnections > 0 &&
                        selectablePools.Count < _maxConnections)
                    {
                        pool = CreatePool();
                        pool.AcquireNewLease();
                    }
                    else
                    {
                        var candidates = _maxConcurrency > 0
                            ? selectablePools.Where(currentPool => currentPool.OpenUsage < _maxConcurrency).ToList()
                            : selectablePools;
                        if (candidates.Count == 0)
                        {
                            pool = CreatePool();
                            pool.AcquireNewLease();
                        }
                        else
                        {
                            pool = candidates[Random.Shared.Next(candidates.Count)];
                            pool.AcquireExistingLease();
                        }
                    }
                }
            }

            DisposePoolsSynchronously(poolsToDispose);
            return new SplitHttpHttp2UploadPoolLease(this, pool);
        }

        public async ValueTask ReleaseAsync(SplitHttpHttp2UploadPool pool)
        {
            ArgumentNullException.ThrowIfNull(pool);

            List<SplitHttpHttp2UploadPool>? poolsToDispose = null;
            lock (_syncRoot)
            {
                pool.ReleaseLease();
                PrunePools(DateTime.UtcNow, ref poolsToDispose);
            }

            await DisposePoolsAsync(poolsToDispose).ConfigureAwait(false);
        }

        private SplitHttpHttp2UploadPool CreatePool()
        {
            var cMaxReuseTimes = GetRandomRangeValue(_xmux.CMaxReuseTimes);
            var hMaxRequestTimes = GetRandomRangeValue(_xmux.HMaxRequestTimes);
            var hMaxReusableSecs = GetRandomRangeValue(_xmux.HMaxReusableSecs);
            var pool = new SplitHttpHttp2UploadPool(
                _sessionOptions,
                remainingLeaseReuses: cMaxReuseTimes > 0 ? cMaxReuseTimes - 1 : -1,
                remainingRequests: hMaxRequestTimes > 0 ? hMaxRequestTimes : int.MaxValue,
                unreusableAtUtcTicks: hMaxReusableSecs > 0
                    ? DateTime.UtcNow.AddSeconds(hMaxReusableSecs).Ticks
                    : 0);
            _pools.Add(pool);
            return pool;
        }

        private void PrunePools(
            DateTime utcNow,
            ref List<SplitHttpHttp2UploadPool>? poolsToDispose)
        {
            for (var index = _pools.Count - 1; index >= 0; index--)
            {
                var pool = _pools[index];
                if (!pool.ShouldRemove(utcNow))
                {
                    continue;
                }

                _pools.RemoveAt(index);
                (poolsToDispose ??= []).Add(pool);
            }
        }

        private static void DisposePoolsSynchronously(IReadOnlyList<SplitHttpHttp2UploadPool>? pools)
        {
            if (pools is null)
            {
                return;
            }

            foreach (var pool in pools)
            {
                pool.DisposeAsync().AsTask().GetAwaiter().GetResult();
            }
        }

        private static async ValueTask DisposePoolsAsync(IReadOnlyList<SplitHttpHttp2UploadPool>? pools)
        {
            if (pools is null)
            {
                return;
            }

            foreach (var pool in pools)
            {
                await pool.DisposeAsync().ConfigureAwait(false);
            }
        }
    }

    private sealed class SplitHttpHttp2UploadPoolLease : IAsyncDisposable
    {
        private readonly SplitHttpHttp2UploadPoolManager _manager;
        private int _disposed;

        public SplitHttpHttp2UploadPoolLease(
            SplitHttpHttp2UploadPoolManager manager,
            SplitHttpHttp2UploadPool pool)
        {
            _manager = manager ?? throw new ArgumentNullException(nameof(manager));
            Pool = pool ?? throw new ArgumentNullException(nameof(pool));
        }

        public SplitHttpHttp2UploadPool Pool { get; }

        public bool TryBeginRequest(DateTime utcNow)
            => Pool.TryBeginRequest(utcNow);

        public void RecordStreamRequest(DateTime utcNow)
            => Pool.RecordStreamRequest(utcNow);

        public RuntimeInternetSecurityState? CloneSecurityState()
            => Pool.CloneSecurityState();

        public ValueTask<Stream?> OpenRequestStreamAsync(
            Func<CancellationToken, ValueTask<RuntimeInternetConnectionContext>> transportContextFactory,
            RuntimeInternetStack internetStack,
            string method,
            string authority,
            string requestTarget,
            IReadOnlyDictionary<string, string> requestHeaders,
            bool includeContentType,
            bool waitForSuccessfulStatus,
            bool endStreamOnHeaders,
            CancellationToken cancellationToken)
            => Pool.OpenRequestStreamAsync(
                transportContextFactory,
                internetStack,
                method,
                authority,
                requestTarget,
                requestHeaders,
                includeContentType,
                waitForSuccessfulStatus,
                endStreamOnHeaders,
                cancellationToken);

        public ValueTask<bool> SendAsync(
            Func<CancellationToken, ValueTask<RuntimeInternetConnectionContext>> transportContextFactory,
            RuntimeInternetStack internetStack,
            SplitHttpPacketUploadRequest request,
            CancellationToken cancellationToken)
            => Pool.SendAsync(transportContextFactory, internetStack, request, cancellationToken);

        public ValueTask<Task?> StartSendAsync(
            Func<CancellationToken, ValueTask<RuntimeInternetConnectionContext>> transportContextFactory,
            RuntimeInternetStack internetStack,
            SplitHttpPacketUploadRequest request,
            CancellationToken cancellationToken)
            => Pool.StartSendAsync(transportContextFactory, internetStack, request, cancellationToken);

        public async ValueTask DisposeAsync()
        {
            if (Interlocked.Exchange(ref _disposed, 1) != 0)
            {
                return;
            }

            await _manager.ReleaseAsync(Pool).ConfigureAwait(false);
        }
    }

    private sealed class SplitHttpHttp2UploadPool : IAsyncDisposable
    {
        private readonly SemaphoreSlim _sessionGate = new(1, 1);
        private readonly Http2TunnelSessionOptions _sessionOptions;
        private readonly long _unreusableAtUtcTicks;
        private RuntimeInternetConnectionContext? _context;
        private Http2TunnelSession? _session;
        private int _openUsage;
        private int _remainingLeaseReuses;
        private int _remainingRequests;
        private int _acceptNewLeases;
        private int _acceptRequests = 1;
        private int _disposed;

        public SplitHttpHttp2UploadPool(
            Http2TunnelSessionOptions sessionOptions,
            int remainingLeaseReuses,
            int remainingRequests,
            long unreusableAtUtcTicks)
        {
            _sessionOptions = sessionOptions ?? throw new ArgumentNullException(nameof(sessionOptions));
            _remainingLeaseReuses = remainingLeaseReuses;
            _remainingRequests = remainingRequests;
            _unreusableAtUtcTicks = unreusableAtUtcTicks;
            _acceptNewLeases = remainingLeaseReuses == 0 ? 0 : 1;
        }

        public int OpenUsage => Volatile.Read(ref _openUsage);

        public bool CanAcceptLease(DateTime utcNow)
        {
            RefreshLifetime(utcNow);
            return Volatile.Read(ref _acceptNewLeases) != 0;
        }

        public void AcquireNewLease()
            => Interlocked.Increment(ref _openUsage);

        public void AcquireExistingLease()
        {
            Interlocked.Increment(ref _openUsage);
            if (_remainingLeaseReuses < 0)
            {
                return;
            }

            if (_remainingLeaseReuses == 0)
            {
                Interlocked.Exchange(ref _acceptNewLeases, 0);
                return;
            }

            if (Interlocked.Decrement(ref _remainingLeaseReuses) <= 0)
            {
                Interlocked.Exchange(ref _acceptNewLeases, 0);
            }
        }

        public void ReleaseLease()
            => Interlocked.Decrement(ref _openUsage);

        public bool TryBeginRequest(DateTime utcNow)
        {
            RefreshLifetime(utcNow);
            if (Volatile.Read(ref _acceptRequests) == 0)
            {
                return false;
            }

            if (_remainingRequests == int.MaxValue)
            {
                return true;
            }

            var remainingRequests = Interlocked.Decrement(ref _remainingRequests);
            if (remainingRequests < 0)
            {
                Interlocked.Exchange(ref _acceptRequests, 0);
                Interlocked.Exchange(ref _acceptNewLeases, 0);
                return false;
            }

            if (remainingRequests == 0)
            {
                Interlocked.Exchange(ref _acceptRequests, 0);
                Interlocked.Exchange(ref _acceptNewLeases, 0);
            }

            return true;
        }

        public void RecordStreamRequest(DateTime utcNow)
        {
            RefreshLifetime(utcNow);
            if (_remainingRequests == int.MaxValue)
            {
                return;
            }

            var remainingRequests = Interlocked.Decrement(ref _remainingRequests);
            if (remainingRequests <= 0)
            {
                Interlocked.Exchange(ref _acceptRequests, 0);
                Interlocked.Exchange(ref _acceptNewLeases, 0);
            }
        }

        public RuntimeInternetSecurityState? CloneSecurityState()
        {
            var context = _context;
            return context is null
                ? null
                : RuntimeSplitHttpClientConnector.CloneSecurityState(context.SecurityState);
        }

        public async ValueTask<Stream?> OpenRequestStreamAsync(
            Func<CancellationToken, ValueTask<RuntimeInternetConnectionContext>> transportContextFactory,
            RuntimeInternetStack internetStack,
            string method,
            string authority,
            string requestTarget,
            IReadOnlyDictionary<string, string> requestHeaders,
            bool includeContentType,
            bool waitForSuccessfulStatus,
            bool endStreamOnHeaders,
            CancellationToken cancellationToken)
        {
            ArgumentNullException.ThrowIfNull(transportContextFactory);
            ArgumentException.ThrowIfNullOrWhiteSpace(method);
            ArgumentException.ThrowIfNullOrWhiteSpace(authority);
            ArgumentException.ThrowIfNullOrWhiteSpace(requestTarget);
            ArgumentNullException.ThrowIfNull(requestHeaders);

            for (var attempt = 0; attempt < 2; attempt++)
            {
                var session = await GetOrCreateSessionAsync(transportContextFactory, cancellationToken).ConfigureAwait(false);
                if (session is null)
                {
                    return null;
                }

                try
                {
                    return await session
                        .OpenHttpRequestStreamAsync(
                            method,
                            authority,
                            ResolveHttpScheme(internetStack),
                            requestTarget,
                            CreateHttp2RequestHeaders(requestHeaders, includeContentType),
                            Array.Empty<byte>(),
                            waitForSuccessfulStatus,
                            cancellationToken,
                            disposeSessionOnClose: false,
                            endStreamOnHeaders: endStreamOnHeaders)
                        .ConfigureAwait(false);
                }
                catch (ObjectDisposedException)
                {
                    await ResetSessionAsync().ConfigureAwait(false);
                }
                catch (IOException)
                {
                    await ResetSessionAsync().ConfigureAwait(false);
                }
                catch (InvalidOperationException) when (session.CanReuseConnection)
                {
                    return null;
                }
                catch (InvalidOperationException)
                {
                    await ResetSessionAsync().ConfigureAwait(false);
                }
            }

            return null;
        }

        public async ValueTask<bool> SendAsync(
            Func<CancellationToken, ValueTask<RuntimeInternetConnectionContext>> transportContextFactory,
            RuntimeInternetStack internetStack,
            SplitHttpPacketUploadRequest request,
            CancellationToken cancellationToken)
        {
            ArgumentNullException.ThrowIfNull(transportContextFactory);
            ArgumentNullException.ThrowIfNull(request);

            var session = await GetOrCreateSessionAsync(transportContextFactory, cancellationToken).ConfigureAwait(false);
            if (session is null)
            {
                return false;
            }

            try
            {
                await SendPacketRequestAsync(session, internetStack, request, cancellationToken).ConfigureAwait(false);
                return true;
            }
            catch (ObjectDisposedException)
            {
                await ResetSessionAsync().ConfigureAwait(false);
                return false;
            }
            catch (IOException)
            {
                await ResetSessionAsync().ConfigureAwait(false);
                return false;
            }
            catch (InvalidOperationException) when (session.CanReuseConnection)
            {
                return false;
            }
            catch (InvalidOperationException)
            {
                await ResetSessionAsync().ConfigureAwait(false);
                return false;
            }
        }

        public async ValueTask<Task?> StartSendAsync(
            Func<CancellationToken, ValueTask<RuntimeInternetConnectionContext>> transportContextFactory,
            RuntimeInternetStack internetStack,
            SplitHttpPacketUploadRequest request,
            CancellationToken cancellationToken)
        {
            ArgumentNullException.ThrowIfNull(transportContextFactory);
            ArgumentNullException.ThrowIfNull(request);

            var session = await GetOrCreateSessionAsync(transportContextFactory, cancellationToken).ConfigureAwait(false);
            if (session is null)
            {
                return null;
            }

            try
            {
                var pendingRequest = await StartPacketRequestAsync(
                        session,
                        internetStack,
                        request,
                        cancellationToken)
                    .ConfigureAwait(false);
                return CompleteStartedRequestAsync(pendingRequest);
            }
            catch (ObjectDisposedException)
            {
                await ResetSessionAsync().ConfigureAwait(false);
                return null;
            }
            catch (IOException)
            {
                await ResetSessionAsync().ConfigureAwait(false);
                return null;
            }
            catch (InvalidOperationException) when (session.CanReuseConnection)
            {
                return null;
            }
            catch (InvalidOperationException)
            {
                await ResetSessionAsync().ConfigureAwait(false);
                return null;
            }
        }

        public bool ShouldRemove(DateTime utcNow)
        {
            RefreshLifetime(utcNow);
            return Volatile.Read(ref _openUsage) == 0 &&
                   Volatile.Read(ref _acceptNewLeases) == 0;
        }

        public async ValueTask DisposeAsync()
        {
            if (Interlocked.Exchange(ref _disposed, 1) != 0)
            {
                return;
            }

            await ResetSessionAsync().ConfigureAwait(false);
            _sessionGate.Dispose();
        }

        private async ValueTask<Http2TunnelSession?> GetOrCreateSessionAsync(
            Func<CancellationToken, ValueTask<RuntimeInternetConnectionContext>> transportContextFactory,
            CancellationToken cancellationToken)
        {
            await _sessionGate.WaitAsync(cancellationToken).ConfigureAwait(false);
            try
            {
                if (_session is not null &&
                    _session.CanOpenNewStream)
                {
                    return _session;
                }

                await ResetSessionCoreAsync().ConfigureAwait(false);

                var context = await transportContextFactory(cancellationToken).ConfigureAwait(false);
                if (!ShouldUseHttp2(context))
                {
                    await RuntimeGrpcClientConnector.DisposeTransportContextAsync(context).ConfigureAwait(false);
                    return null;
                }

                try
                {
                    _session = await Http2TunnelSession
                        .CreateAsync(
                            context.TransportStream,
                            cancellationToken,
                            _sessionOptions)
                        .ConfigureAwait(false);
                    _context = context;
                    return _session;
                }
                catch
                {
                    await RuntimeGrpcClientConnector.DisposeTransportContextAsync(context).ConfigureAwait(false);
                    throw;
                }
            }
            finally
            {
                _sessionGate.Release();
            }
        }

        private async ValueTask ResetSessionAsync()
        {
            await _sessionGate.WaitAsync().ConfigureAwait(false);
            try
            {
                await ResetSessionCoreAsync().ConfigureAwait(false);
            }
            finally
            {
                _sessionGate.Release();
            }
        }

        private async Task CompleteStartedRequestAsync(Http2TunnelSession.PendingRequest pendingRequest)
        {
            await using var request = pendingRequest;
            try
            {
                await pendingRequest.DrainResponseAsync(CancellationToken.None).ConfigureAwait(false);
            }
            catch
            {
                await ResetSessionAsync().ConfigureAwait(false);
                throw;
            }
        }

        private async ValueTask ResetSessionCoreAsync()
        {
            if (_session is not null)
            {
                try
                {
                    await _session.DisposeAsync().ConfigureAwait(false);
                }
                catch
                {
                }

                _session = null;
            }

            if (_context is not null)
            {
                _context.SecurityState.RemoteCertificate?.Dispose();
                _context = null;
            }
        }

        private void RefreshLifetime(DateTime utcNow)
        {
            if (_unreusableAtUtcTicks == 0 ||
                utcNow.Ticks <= _unreusableAtUtcTicks)
            {
                return;
            }

            Interlocked.Exchange(ref _acceptRequests, 0);
            Interlocked.Exchange(ref _acceptNewLeases, 0);
        }
    }

    private sealed record SplitHttpSharedUploadPoolKey(
        RuntimeInternetProfile InternetProfile,
        IDnsResolver DnsResolver,
        string Signature,
        RuntimeSplitHttpXmuxOptions SplitHttpXmux);
}

#pragma warning restore CA1416

using System.Globalization;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Authentication;
using System.Text;

namespace NodePanel.Core.Runtime;

public sealed class HttpOutboundHandler : IOutboundHandler
{
    private const int TunnelOpenAttempts = 5;
    private static readonly TimeSpan InitialTunnelRetryDelay = TimeSpan.FromMilliseconds(100);

    private readonly Http2TunnelSessionPool _http2TunnelSessionPool;
    private readonly IOutboundCommonSettingsProvider _commonSettingsProvider;
    private readonly IDnsResolver _dnsResolver;
    private readonly RuntimeInternetProfile _internetProfile;
    private readonly IRuntimeOutboundSettingsProvider _runtimeSettingsProvider;
    private readonly IServiceProvider? _serviceProvider;

    public HttpOutboundHandler(
        IOutboundCommonSettingsProvider commonSettingsProvider,
        IRuntimeOutboundSettingsProvider runtimeSettingsProvider,
        IServiceProvider? serviceProvider = null,
        IDnsResolver? dnsResolver = null)
        : this(
            commonSettingsProvider,
            runtimeSettingsProvider,
            serviceProvider,
            dnsResolver,
            internetProfile: null,
            http2TunnelSessionPool: null)
    {
    }

    internal HttpOutboundHandler(
        IOutboundCommonSettingsProvider commonSettingsProvider,
        IRuntimeOutboundSettingsProvider runtimeSettingsProvider,
        IServiceProvider? serviceProvider,
        IDnsResolver? dnsResolver,
        RuntimeInternetProfile? internetProfile,
        Http2TunnelSessionPool? http2TunnelSessionPool = null)
    {
        _commonSettingsProvider = commonSettingsProvider ?? throw new ArgumentNullException(nameof(commonSettingsProvider));
        _runtimeSettingsProvider = runtimeSettingsProvider ?? throw new ArgumentNullException(nameof(runtimeSettingsProvider));
        _serviceProvider = serviceProvider;
        _dnsResolver = dnsResolver ?? SystemDnsResolver.Instance;
        _internetProfile = internetProfile ?? RuntimeInternetProfile.Default;
        _http2TunnelSessionPool = http2TunnelSessionPool ?? new Http2TunnelSessionPool();
    }

    public string Protocol => OutboundProtocols.Http;

    public async ValueTask<Stream> OpenTcpAsync(
        DispatchContext context,
        DispatchDestination destination,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(destination);
        if (destination.Network != DispatchNetwork.Tcp)
        {
            throw new NotSupportedException($"HTTP outbound does not support TCP open for network '{destination.Network}'.");
        }

        var settings = ResolveSettings(context);
        var resolvedDestination = await OutboundTargetStrategyResolver.ResolveAsync(
            context,
            destination,
            settings.Common.TargetStrategy,
            _dnsResolver,
            cancellationToken).ConfigureAwait(false);

        return await OpenTcpWithRetryAsync(
                context,
                settings,
                resolvedDestination,
                cancellationToken)
            .ConfigureAwait(false);
    }

    public ValueTask<IOutboundUdpTransport> OpenUdpAsync(
        DispatchContext context,
        CancellationToken cancellationToken)
        => throw new NotSupportedException("HTTP outbound does not support UDP.");

    internal HttpResolvedSettings ResolveSettings(DispatchContext context)
    {
        if (!_commonSettingsProvider.TryResolve(context, out var commonSettings) ||
            !string.Equals(commonSettings.Protocol, OutboundProtocols.Http, StringComparison.Ordinal))
        {
            throw new InvalidOperationException("HTTP outbound common settings could not be resolved for the current dispatch context.");
        }

        if (!_runtimeSettingsProvider.TryResolve(context, out RuntimeHttpOutboundOptions runtimeSettings) ||
            !string.Equals(runtimeSettings.Protocol, OutboundProtocols.Http, StringComparison.Ordinal))
        {
            throw new InvalidOperationException("HTTP outbound settings could not be resolved for the current dispatch context.");
        }

        return new HttpResolvedSettings
        {
            Common = commonSettings,
            Outbound = runtimeSettings
        };
    }

    internal async ValueTask<Stream> OpenServerTcpStreamAsync(
        DispatchContext context,
        HttpResolvedSettings settings,
        CancellationToken cancellationToken)
        => (await OpenServerConnectionAsync(context, settings, cancellationToken).ConfigureAwait(false)).ApplicationStream;

    internal async ValueTask<RuntimeInternetConnectionContext> OpenServerConnectionAsync(
        DispatchContext context,
        HttpResolvedSettings settings,
        CancellationToken cancellationToken)
    {
        Stream baseStream;
        if (!string.IsNullOrWhiteSpace(settings.Common.ProxyOutboundTag))
        {
            baseStream = await ResolveDispatcher().DispatchTcpAsync(
                CreateProxyContext(
                    context,
                    settings.Outbound.ServerHost,
                    settings.Outbound.ServerPort,
                    settings.Common.ProxyOutboundTag),
                new DispatchDestination
                {
                    Host = settings.Outbound.ServerHost,
                    Port = settings.Outbound.ServerPort,
                    Network = DispatchNetwork.Tcp
                },
                cancellationToken).ConfigureAwait(false);
        }
        else
        {
            using var connectCts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
            connectCts.CancelAfter(TimeSpan.FromSeconds(ResolveTimeout(
                settings.Outbound.ConnectTimeoutSeconds,
                context.ConnectTimeoutSeconds)));
            var endPoints = await OutboundSocketDialer.ResolveTcpEndPointsAsync(
                context,
                settings.Outbound.ServerHost,
                settings.Outbound.ServerPort,
                AddressFamily.Unspecified,
                _dnsResolver,
                connectCts.Token).ConfigureAwait(false);
            baseStream = await OutboundSocketDialer.OpenTcpStreamAsync(
                context,
                settings.Common.Via,
                settings.Common.ViaCidr,
                endPoints,
                connectCts.Token).ConfigureAwait(false);
        }

        RuntimeInternetConnectionContext? transportConnection = null;
        try
        {
            transportConnection = await OpenTransportConnectionAsync(
                baseStream,
                settings.Outbound,
                cancellationToken).ConfigureAwait(false);
            EnsureSupportedNegotiatedProtocol(transportConnection);
            return transportConnection;
        }
        catch (Exception ex) when (RuntimeRealityProcessedInvalidConnectionException.ShouldPreserveTransport(ex))
        {
            throw;
        }
        catch
        {
            if (transportConnection is not null &&
                !ReferenceEquals(transportConnection.ApplicationStream, baseStream))
            {
                await transportConnection.ApplicationStream.DisposeAsync().ConfigureAwait(false);
            }
            else
            {
                await baseStream.DisposeAsync().ConfigureAwait(false);
            }

            throw;
        }
    }

    internal IDispatcher ResolveDispatcher()
        => _serviceProvider?.GetService(typeof(IDispatcher)) as IDispatcher
           ?? throw new InvalidOperationException("HTTP outbound proxy chaining requires an active dispatcher.");

    internal async ValueTask<Stream> OpenTransportStreamAsync(
        Stream baseStream,
        RuntimeHttpOutboundOptions settings,
        CancellationToken cancellationToken)
        => (await OpenTransportConnectionAsync(baseStream, settings, cancellationToken).ConfigureAwait(false)).ApplicationStream;

    internal async ValueTask<RuntimeInternetConnectionContext> OpenTransportConnectionAsync(
        Stream baseStream,
        RuntimeHttpOutboundOptions settings,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(baseStream);
        ArgumentNullException.ThrowIfNull(settings);

        var stack = ResolveInternetStack(settings.Transport);
        if (stack.TransportProtocol == RuntimeInternetTransportProtocols.Tcp &&
            stack.SecurityType == RuntimeInternetSecurityTypes.None)
        {
            return new RuntimeInternetConnectionContext(baseStream);
        }

        return await _internetProfile
            .OpenAsync(
                baseStream,
                stack,
                new HttpInternetOptions(settings),
                transportInitializationData: null,
                cancellationToken)
            .ConfigureAwait(false);
    }

    internal static byte[] BuildConnectRequest(
        IReadOnlyDictionary<string, string> headers,
        DispatchDestination destination)
    {
        ArgumentNullException.ThrowIfNull(headers);
        ArgumentNullException.ThrowIfNull(destination);

        var authority = FormatAuthority(destination.Host, destination.Port);

        var builder = new StringBuilder(256);
        builder.Append("CONNECT ");
        builder.Append(authority);
        builder.Append(" HTTP/1.1\r\n");
        builder.Append("Host: ");
        builder.Append(authority);
        builder.Append("\r\n");

        foreach (var (name, value) in headers)
        {
            if (string.Equals(name, "Host", StringComparison.OrdinalIgnoreCase))
            {
                continue;
            }

            builder.Append(name);
            builder.Append(": ");
            builder.Append(value);
            builder.Append("\r\n");
        }

        builder.Append("\r\n");
        return Encoding.ASCII.GetBytes(builder.ToString());
    }

    internal static async Task ReadConnectResponseAsync(
        Stream stream,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(stream);

        var statusLine = await RuntimeInternetHttpUtilities
            .ReadHttpLineAsync(
                stream,
                "Unexpected EOF during HTTP CONNECT handshake.",
                cancellationToken)
            .ConfigureAwait(false);

        if (!TryParseStatusCode(statusLine, out var statusCode))
        {
            throw new InvalidDataException($"HTTP proxy returned an invalid response status line: {statusLine}.");
        }

        while (true)
        {
            var line = await RuntimeInternetHttpUtilities
                .ReadHttpLineAsync(
                    stream,
                    "Unexpected EOF during HTTP CONNECT handshake.",
                    cancellationToken)
                .ConfigureAwait(false);
            if (line.Length == 0)
            {
                break;
            }
        }

        if (statusCode != 200)
        {
            throw new IOException($"HTTP proxy responded with non-200 status: {statusLine}.");
        }
    }

    internal static Dictionary<string, string> BuildConnectHeaders(
        RuntimeHttpOutboundOptions settings,
        DispatchContext context,
        DispatchDestination destination,
        bool includeProxyConnection)
    {
        ArgumentNullException.ThrowIfNull(settings);
        ArgumentNullException.ThrowIfNull(destination);

        var headers = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);

        if (!string.IsNullOrWhiteSpace(settings.Username) ||
            !string.IsNullOrWhiteSpace(settings.Password))
        {
            var credentials = Encoding.UTF8.GetBytes($"{settings.Username}:{settings.Password}");
            headers["Proxy-Authorization"] = "Basic " + Convert.ToBase64String(credentials);
        }

        foreach (var (name, value) in settings.Headers)
        {
            if (string.IsNullOrWhiteSpace(name))
            {
                continue;
            }

            var trimmedValue = value.Trim();
            headers[name.Trim()] = HttpHeaderTemplateRenderer.Render(trimmedValue, context, destination);
        }

        if (!headers.TryGetValue("User-Agent", out var userAgent) ||
            string.IsNullOrWhiteSpace(userAgent))
        {
            headers["User-Agent"] = RuntimeInternetHttpUtilities.DefaultChromeUserAgent;
        }

        if (includeProxyConnection)
        {
            headers["Proxy-Connection"] = "Keep-Alive";
        }

        return headers;
    }

    internal static ValueTask<Stream> OpenHttp2ConnectAsync(
        Stream transportStream,
        IReadOnlyDictionary<string, string> connectHeaders,
        DispatchDestination destination,
        byte[] initialPayload,
        CancellationToken cancellationToken)
        => Http2ConnectTunnel.OpenAsync(transportStream, connectHeaders, destination, initialPayload, cancellationToken);

    internal async ValueTask<Stream?> TryOpenCachedHttp2ConnectAsync(
        string cacheKey,
        IReadOnlyDictionary<string, string> connectHeaders,
        DispatchDestination destination,
        byte[] initialPayload,
        CancellationToken cancellationToken)
    {
        if (string.IsNullOrWhiteSpace(cacheKey))
        {
            return null;
        }

        return await _http2TunnelSessionPool
            .TryOpenAsync(cacheKey, connectHeaders, destination, initialPayload, cancellationToken)
            .ConfigureAwait(false);
    }

    internal async ValueTask<Stream> OpenCachedOrFreshHttp2ConnectAsync(
        string cacheKey,
        Stream transportStream,
        IReadOnlyDictionary<string, string> connectHeaders,
        DispatchDestination destination,
        byte[] initialPayload,
        CancellationToken cancellationToken)
    {
        if (string.IsNullOrWhiteSpace(cacheKey))
        {
            return await OpenHttp2ConnectAsync(
                    transportStream,
                    connectHeaders,
                    destination,
                    initialPayload,
                    cancellationToken)
                .ConfigureAwait(false);
        }

        return await _http2TunnelSessionPool
            .AttachOrOpenAsync(
                cacheKey,
                transportStream,
                connectHeaders,
                destination,
                initialPayload,
                cancellationToken)
            .ConfigureAwait(false);
    }

    private async ValueTask<Stream> OpenTcpWithRetryAsync(
        DispatchContext context,
        HttpResolvedSettings settings,
        DispatchDestination resolvedDestination,
        CancellationToken cancellationToken)
    {
        Exception? lastError = null;
        var delay = InitialTunnelRetryDelay;

        for (var attempt = 0; attempt < TunnelOpenAttempts; attempt++)
        {
            cancellationToken.ThrowIfCancellationRequested();

            try
            {
                return await OpenTcpCoreAsync(
                        context,
                        settings,
                        resolvedDestination,
                        cancellationToken)
                    .ConfigureAwait(false);
            }
            catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
            {
                throw;
            }
            catch (Exception ex) when (attempt < TunnelOpenAttempts - 1 && ShouldRetryTunnelOpen(ex))
            {
                lastError = ex;
                await Task.Delay(delay, cancellationToken).ConfigureAwait(false);
                delay = TimeSpan.FromMilliseconds(delay.TotalMilliseconds * 2);
            }
            catch (Exception ex)
            {
                lastError = ex;
                break;
            }
        }

        throw new IOException("HTTP outbound failed to establish CONNECT tunnel.", lastError);
    }

    private async ValueTask<Stream> OpenTcpCoreAsync(
        DispatchContext context,
        HttpResolvedSettings settings,
        DispatchDestination resolvedDestination,
        CancellationToken cancellationToken)
    {
        var http2CacheKey = BuildHttp2SessionCacheKey(settings);
        var http2ConnectHeaders = ShouldUseHttp2SessionCache(http2CacheKey, settings.Outbound)
            ? BuildConnectHeaders(settings.Outbound, context, resolvedDestination, includeProxyConnection: false)
            : null;

        if (http2ConnectHeaders is not null)
        {
            var cachedHttp2Stream = await TryOpenCachedHttp2ConnectAsync(
                http2CacheKey,
                http2ConnectHeaders,
                resolvedDestination,
                context.InitialPayload,
                cancellationToken).ConfigureAwait(false);
            if (cachedHttp2Stream is not null)
            {
                return cachedHttp2Stream;
            }
        }

        var connection = await OpenServerConnectionAsync(context, settings, cancellationToken).ConfigureAwait(false);
        try
        {
            using var handshakeCts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
            handshakeCts.CancelAfter(TimeSpan.FromSeconds(ResolveTimeout(
                settings.Outbound.HandshakeTimeoutSeconds,
                context.ConnectTimeoutSeconds)));

            if (IsHttp2Negotiated(connection))
            {
                var http2Stream = await OpenCachedOrFreshHttp2ConnectAsync(
                    http2CacheKey,
                    connection.ApplicationStream,
                    http2ConnectHeaders ?? BuildConnectHeaders(
                        settings.Outbound,
                        context,
                        resolvedDestination,
                        includeProxyConnection: false),
                    resolvedDestination,
                    context.InitialPayload,
                    handshakeCts.Token).ConfigureAwait(false);

                return http2Stream;
            }

            var request = BuildConnectRequest(
                BuildConnectHeaders(
                    settings.Outbound,
                    context,
                    resolvedDestination,
                    includeProxyConnection: true),
                resolvedDestination);
            await connection.ApplicationStream.WriteAsync(request, handshakeCts.Token).ConfigureAwait(false);
            await connection.ApplicationStream.FlushAsync(handshakeCts.Token).ConfigureAwait(false);
            await ReadConnectResponseAsync(connection.ApplicationStream, handshakeCts.Token).ConfigureAwait(false);
            return await ApplyInitialPayloadAsync(
                    connection.ApplicationStream,
                    context.InitialPayload,
                    handshakeCts.Token)
                .ConfigureAwait(false);
        }
        catch
        {
            await connection.ApplicationStream.DisposeAsync().ConfigureAwait(false);
            throw;
        }
    }

    private static bool ShouldRetryTunnelOpen(Exception exception)
        => exception is not ArgumentException &&
           exception is not InvalidOperationException &&
           exception is not NotSupportedException;

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

    private static int ResolveTimeout(int value, int fallback)
    {
        if (value > 0)
        {
            return value;
        }

        return fallback > 0 ? fallback : 10;
    }

    private static RuntimeInternetStack ResolveInternetStack(string transport)
        => HttpOutboundTransports.Normalize(transport) switch
        {
            HttpOutboundTransports.Tcp => RuntimeInternetStack.Create(
                RuntimeInternetTransportProtocols.Tcp,
                RuntimeInternetSecurityTypes.None),
            HttpOutboundTransports.Tls => RuntimeInternetStack.Create(
                RuntimeInternetTransportProtocols.Tcp,
                RuntimeInternetSecurityTypes.Tls),
            _ => throw new NotSupportedException($"Unsupported HTTP outbound transport: {transport}.")
        };

    private static bool ShouldUseHttp2SessionCache(string cacheKey, RuntimeHttpOutboundOptions settings)
        => !string.IsNullOrWhiteSpace(cacheKey) &&
           string.Equals(
               HttpOutboundTransports.Normalize(settings.Transport),
               HttpOutboundTransports.Tls,
               StringComparison.Ordinal);

    private static string BuildHttp2SessionCacheKey(HttpResolvedSettings settings)
    {
        var builder = new StringBuilder(256);
        builder.Append(settings.Common.ProxyOutboundTag.Trim());
        builder.Append('|');
        builder.Append(settings.Common.Via.Trim());
        builder.Append('|');
        builder.Append(settings.Common.ViaCidr.Trim());
        builder.Append('|');
        builder.Append(settings.Outbound.ServerHost.Trim());
        builder.Append(':');
        builder.Append(settings.Outbound.ServerPort.ToString(CultureInfo.InvariantCulture));
        builder.Append('|');
        builder.Append(settings.Outbound.ServerName.Trim());
        builder.Append('|');
        builder.Append(settings.Outbound.Fingerprint.Trim());
        builder.Append('|');
        builder.Append(HttpOutboundTransports.Normalize(settings.Outbound.Transport));
        builder.Append('|');
        builder.Append(settings.Outbound.SkipCertificateValidation ? '1' : '0');
        builder.Append('|');
        foreach (var protocol in settings.Outbound.ApplicationProtocols)
        {
            if (string.IsNullOrWhiteSpace(protocol))
            {
                continue;
            }

            builder.Append(protocol.Trim());
            builder.Append(',');
        }

        return builder.ToString();
    }

    private static bool IsHttp2Negotiated(RuntimeInternetConnectionContext connection)
        => string.Equals(
            ResolveNegotiatedApplicationProtocol(connection),
            "h2",
            StringComparison.Ordinal);

    private static string ResolveNegotiatedApplicationProtocol(RuntimeInternetConnectionContext connection)
        => string.IsNullOrWhiteSpace(connection.NegotiatedApplicationProtocol)
            ? string.Empty
            : connection.NegotiatedApplicationProtocol.Trim();

    private static void EnsureSupportedNegotiatedProtocol(RuntimeInternetConnectionContext connection)
    {
        var protocol = ResolveNegotiatedApplicationProtocol(connection);
        if (string.IsNullOrWhiteSpace(protocol) ||
            string.Equals(protocol, "http/1.1", StringComparison.Ordinal) ||
            string.Equals(protocol, "h2", StringComparison.Ordinal))
        {
            return;
        }

        throw new NotSupportedException($"HTTP outbound negotiated an unsupported application layer protocol: {protocol}.");
    }

    private static DispatchContext CreateProxyContext(
        DispatchContext context,
        string host,
        int port,
        string outboundTag)
        => context with
        {
            OutboundTag = outboundTag,
            InitialPayload = Array.Empty<byte>(),
            OriginalDestinationHost = host,
            OriginalDestinationPort = port
        };

    private static async ValueTask<Stream> ApplyInitialPayloadAsync(
        Stream stream,
        byte[] initialPayload,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(stream);
        ArgumentNullException.ThrowIfNull(initialPayload);

        if (initialPayload.Length == 0)
        {
            return stream;
        }

        await stream.WriteAsync(initialPayload, cancellationToken).ConfigureAwait(false);
        await stream.FlushAsync(cancellationToken).ConfigureAwait(false);
        return new InitialPayloadSentStream(stream, initialPayload.Length);
    }

    internal static string FormatAuthority(string host, int port)
    {
        if (host.Contains(':', StringComparison.Ordinal) &&
            !host.StartsWith("[", StringComparison.Ordinal) &&
            !host.EndsWith("]", StringComparison.Ordinal))
        {
            return $"[{host}]:{port}";
        }

        return $"{host}:{port}";
    }
}

internal sealed record HttpResolvedSettings
{
    public required OutboundCommonSettings Common { get; init; }

    public required RuntimeHttpOutboundOptions Outbound { get; init; }
}

internal sealed record HttpInternetOptions(RuntimeHttpOutboundOptions Settings) : IRuntimeInternetOptions, IRuntimeTlsSessionResumptionOptions
{
    public string ServerHost => Settings.ServerHost;

    public string ServerName => Settings.ServerName;

    public string Fingerprint => Settings.Fingerprint;

    public string TransportProtocol => RuntimeInternetTransportProtocols.Tcp;

    public string SecurityType => HttpOutboundTransports.Normalize(Settings.Transport) == HttpOutboundTransports.Tls
        ? RuntimeInternetSecurityTypes.Tls
        : RuntimeInternetSecurityTypes.None;

    public RuntimeRealityOptions RealityOptions => RuntimeRealityOptions.Empty;

    public string WebSocketPath => "/";

    public IReadOnlyDictionary<string, string> WebSocketHeaders { get; }
        = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);

    public int WebSocketHeartbeatPeriodSeconds => 0;

    public string SplitHttpHost => string.Empty;

    public string SplitHttpPath => "/";

    public IReadOnlyDictionary<string, string> SplitHttpHeaders { get; }
        = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);

    public string SplitHttpMode => string.Empty;

    public bool SplitHttpNoGrpcHeader => false;

    public RuntimeInt32Range SplitHttpXPaddingBytes => RuntimeInt32Range.Empty;

    public bool SplitHttpXPaddingObfsMode => false;

    public string SplitHttpXPaddingKey => string.Empty;

    public string SplitHttpXPaddingHeader => string.Empty;

    public string SplitHttpXPaddingPlacement => string.Empty;

    public string SplitHttpXPaddingMethod => string.Empty;

    public string SplitHttpUplinkHttpMethod => string.Empty;

    public string SplitHttpSessionPlacement => string.Empty;

    public string SplitHttpSessionKey => string.Empty;

    public string SplitHttpSeqPlacement => string.Empty;

    public string SplitHttpSeqKey => string.Empty;

    public string SplitHttpUplinkDataPlacement => string.Empty;

    public string SplitHttpUplinkDataKey => string.Empty;

    public RuntimeInt32Range SplitHttpUplinkChunkSize => RuntimeInt32Range.Empty;

    public RuntimeInt32Range SplitHttpScMaxEachPostBytes => RuntimeInt32Range.Empty;

    public RuntimeInt32Range SplitHttpScMinPostsIntervalMs => RuntimeInt32Range.Empty;

    public int SplitHttpScMaxBufferedPosts => 0;

    public RuntimeSplitHttpXmuxOptions SplitHttpXmux => RuntimeSplitHttpXmuxOptions.Empty;

    public RuntimeSplitHttpDownloadOptions? SplitHttpDownloadSettings => null;

    public IReadOnlyList<string> ApplicationProtocols => Settings.ApplicationProtocols;

    public RuntimeQuicOptions QuicOptions => RuntimeQuicOptions.Empty;

    public string GrpcServiceName => string.Empty;

    public string GrpcAuthority => string.Empty;

    public bool GrpcMultiMode => false;

    public string GrpcUserAgent => string.Empty;

    public int GrpcIdleTimeoutSeconds => 0;

    public int GrpcHealthCheckTimeoutSeconds => 0;

    public bool GrpcPermitWithoutStream => false;

    public int GrpcInitialWindowSize => 0;

    public bool EnableTlsSessionResumption => Settings.EnableTlsSessionResumption;

    public bool SkipCertificateValidation => Settings.SkipCertificateValidation;

    public RemoteCertificateValidationCallback? CertificateValidationCallback => null;

    public SslProtocols EnabledSslProtocols => SslProtocols.Tls12 | SslProtocols.Tls13;
}

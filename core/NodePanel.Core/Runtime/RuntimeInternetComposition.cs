using System.Net.Security;
using System.Net.WebSockets;
using System.Runtime.ExceptionServices;
using System.Security.Authentication;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using NodePanel.Core.Transport;

namespace NodePanel.Core.Runtime;

public static class RuntimeInternetTransportProtocols
{
    public const string Tcp = "tcp";
    public const string Ws = "ws";
    public const string HttpUpgrade = "httpupgrade";
    public const string Grpc = "grpc";
    public const string SplitHttp = "splithttp";
    public const string Mkcp = "mkcp";
    public const string Hysteria = "hysteria";

    public static string Normalize(string? value)
        => string.IsNullOrWhiteSpace(value)
            ? Tcp
            : value.Trim().ToLowerInvariant() switch
            {
                "raw" => Tcp,
                "websocket" => Ws,
                "http-upgrade" => HttpUpgrade,
                "xhttp" or "split-http" => SplitHttp,
                "kcp" => Mkcp,
                _ => value.Trim().ToLowerInvariant()
            };

    public static bool TryGetKnownAvailabilityError(string? value, out string? error)
    {
        error = Normalize(value) switch
        {
            "http" or "h2" or "h3"
                => "HTTP transport has been removed in xray-core. Use SplitHTTP with HTTP/2 or HTTP/3 instead.",
            "quic"
                => "QUIC transport has been removed in xray-core. Use SplitHTTP with HTTP/3 instead.",
            Mkcp
                => "mKCP transport is only partially implemented in NodePanel.Core right now. Outbound client and plain inbound server modes are supported, but TLS and REALITY inbound server support are not implemented yet.",
            Hysteria
                => "Hysteria transport is supported by xray-core but is not implemented in NodePanel.Core yet.",
            _ => null
        };

        return !string.IsNullOrEmpty(error);
    }

    public static bool UsesHttp11OnlyApplicationProtocols(string? value)
        => Normalize(value) is Ws or HttpUpgrade;
}

public static class RuntimeInternetSecurityTypes
{
    public const string None = "none";
    public const string Tls = "tls";
    public const string Reality = "reality";

    public static string Normalize(string? value)
        => string.IsNullOrWhiteSpace(value)
            ? None
            : value.Trim().ToLowerInvariant();

    public static bool UsesTlsLikeSemantics(string? value)
        => Normalize(value) is Tls or Reality;

    public static bool IsSecure(string? value)
        => !string.Equals(Normalize(value), None, StringComparison.Ordinal);
}

internal interface IRuntimeInternetOptions
{
    string ServerHost { get; }

    string ServerName { get; }

    string Fingerprint { get; }

    string TransportProtocol { get; }

    string SecurityType { get; }

    RuntimeRealityOptions RealityOptions { get; }

    string WebSocketPath { get; }

    IReadOnlyDictionary<string, string> WebSocketHeaders { get; }

    int WebSocketHeartbeatPeriodSeconds { get; }

    string SplitHttpHost { get; }

    string SplitHttpPath { get; }

    IReadOnlyDictionary<string, string> SplitHttpHeaders { get; }

    string SplitHttpMode { get; }

    bool SplitHttpNoGrpcHeader { get; }

    RuntimeInt32Range SplitHttpXPaddingBytes { get; }

    bool SplitHttpXPaddingObfsMode { get; }

    string SplitHttpXPaddingKey { get; }

    string SplitHttpXPaddingHeader { get; }

    string SplitHttpXPaddingPlacement { get; }

    string SplitHttpXPaddingMethod { get; }

    string SplitHttpUplinkHttpMethod { get; }

    string SplitHttpSessionPlacement { get; }

    string SplitHttpSessionKey { get; }

    string SplitHttpSeqPlacement { get; }

    string SplitHttpSeqKey { get; }

    string SplitHttpUplinkDataPlacement { get; }

    string SplitHttpUplinkDataKey { get; }

    RuntimeInt32Range SplitHttpUplinkChunkSize { get; }

    RuntimeInt32Range SplitHttpScMaxEachPostBytes { get; }

    RuntimeInt32Range SplitHttpScMinPostsIntervalMs { get; }

    int SplitHttpScMaxBufferedPosts { get; }

    RuntimeSplitHttpXmuxOptions SplitHttpXmux { get; }

    RuntimeSplitHttpDownloadOptions? SplitHttpDownloadSettings { get; }

    IReadOnlyList<string> ApplicationProtocols { get; }

    RuntimeQuicOptions QuicOptions { get; }

    string GrpcServiceName { get; }

    string GrpcAuthority { get; }

    bool GrpcMultiMode { get; }

    string GrpcUserAgent { get; }

    int GrpcIdleTimeoutSeconds { get; }

    int GrpcHealthCheckTimeoutSeconds { get; }

    bool GrpcPermitWithoutStream { get; }

    int GrpcInitialWindowSize { get; }

    bool SkipCertificateValidation { get; }

    RemoteCertificateValidationCallback? CertificateValidationCallback { get; }

    SslProtocols EnabledSslProtocols { get; }
}

internal readonly record struct RuntimeInternetStack(
    string TransportProtocol,
    string SecurityType)
{
    public static RuntimeInternetStack Create(string transportProtocol, string securityType)
        => new(
            RuntimeInternetTransportProtocols.Normalize(transportProtocol),
            RuntimeInternetSecurityTypes.Normalize(securityType));
}

internal sealed class RuntimeInternetConnectionContext
{
    public RuntimeInternetConnectionContext(Stream baseStream)
    {
        ArgumentNullException.ThrowIfNull(baseStream);

        BaseStream = baseStream;
        TransportStream = baseStream;
        ApplicationStream = baseStream;
    }

    public Stream BaseStream { get; }

    public Stream TransportStream { get; private set; }

    public Stream ApplicationStream { get; private set; }

    public SslStream? SslStream { get; private set; }

    public WebSocket? WebSocket { get; private set; }

    public RuntimeInternetSecurityState SecurityState { get; private set; } = RuntimeInternetSecurityState.None;

    public string NegotiatedApplicationProtocol => SecurityState.NegotiatedApplicationProtocol;

    public SslProtocols NegotiatedSslProtocol => SecurityState.NegotiatedSslProtocol;

    public X509Certificate2? RemoteCertificate => SecurityState.RemoteCertificate;

    public void SetTransportStream(
        Stream stream,
        SslStream? sslStream = null,
        string? negotiatedApplicationProtocol = null,
        RuntimeInternetSecurityState? securityState = null,
        bool updateApplicationStream = true)
    {
        ArgumentNullException.ThrowIfNull(stream);

        TransportStream = stream;
        if (updateApplicationStream)
        {
            ApplicationStream = stream;
        }

        SslStream = sslStream;
        SecurityState = ResolveSecurityState(securityState, sslStream, negotiatedApplicationProtocol);
    }

    public void SetApplicationStream(Stream stream, WebSocket? webSocket = null)
    {
        ArgumentNullException.ThrowIfNull(stream);

        ApplicationStream = stream;
        WebSocket = webSocket;
    }

    public void ReplaceApplicationStream(Stream stream)
    {
        ArgumentNullException.ThrowIfNull(stream);

        ApplicationStream = stream;
    }

    private static RuntimeInternetSecurityState ResolveSecurityState(
        RuntimeInternetSecurityState? securityState,
        SslStream? sslStream,
        string? negotiatedApplicationProtocol)
    {
        if (securityState is not null)
        {
            if (string.IsNullOrWhiteSpace(negotiatedApplicationProtocol))
            {
                return securityState;
            }

            return securityState with
            {
                NegotiatedApplicationProtocol = negotiatedApplicationProtocol.Trim()
            };
        }

        if (sslStream is not null)
        {
            return RuntimeInternetSecurityState.Create(
                RuntimeInternetSecurityTypes.Tls,
                sslStream,
                negotiatedApplicationProtocol);
        }

        return string.IsNullOrWhiteSpace(negotiatedApplicationProtocol)
            ? RuntimeInternetSecurityState.None
            : RuntimeInternetSecurityState.None with
            {
                NegotiatedApplicationProtocol = negotiatedApplicationProtocol.Trim()
            };
    }
}

internal sealed class RuntimeDelayedOpenStream : Stream
{
    private readonly Func<byte[]?, CancellationToken, ValueTask<Stream>> _openAsync;
    private readonly SemaphoreSlim _openLock = new(1, 1);
    private readonly int _earlyDataBytes;

    private int _disposed;
    private Exception? _openException;
    private Stream? _innerStream;
    private TaskCompletionSource<Stream> _openedTcs = new(TaskCreationOptions.RunContinuationsAsynchronously);

    public RuntimeDelayedOpenStream(
        int earlyDataBytes,
        Func<byte[]?, CancellationToken, ValueTask<Stream>> openAsync)
    {
        _earlyDataBytes = Math.Max(0, earlyDataBytes);
        _openAsync = openAsync ?? throw new ArgumentNullException(nameof(openAsync));
    }

    public override bool CanRead => Volatile.Read(ref _disposed) == 0;

    public override bool CanSeek => false;

    public override bool CanWrite => Volatile.Read(ref _disposed) == 0;

    public override bool CanTimeout => _innerStream?.CanTimeout ?? false;

    public override long Length => throw new NotSupportedException();

    public override long Position
    {
        get => throw new NotSupportedException();
        set => throw new NotSupportedException();
    }

    public override int ReadTimeout
    {
        get => _innerStream?.ReadTimeout ?? throw new InvalidOperationException("The delayed stream has not been opened yet.");
        set
        {
            var innerStream = _innerStream ?? throw new InvalidOperationException("The delayed stream has not been opened yet.");
            innerStream.ReadTimeout = value;
        }
    }

    public override int WriteTimeout
    {
        get => _innerStream?.WriteTimeout ?? throw new InvalidOperationException("The delayed stream has not been opened yet.");
        set
        {
            var innerStream = _innerStream ?? throw new InvalidOperationException("The delayed stream has not been opened yet.");
            innerStream.WriteTimeout = value;
        }
    }

    public override void Flush()
        => FlushAsync(CancellationToken.None).GetAwaiter().GetResult();

    public override async Task FlushAsync(CancellationToken cancellationToken)
    {
        if (_innerStream is null)
        {
            return;
        }

        await _innerStream.FlushAsync(cancellationToken).ConfigureAwait(false);
    }

    public override int Read(byte[] buffer, int offset, int count)
        => ReadAsync(buffer.AsMemory(offset, count), CancellationToken.None).AsTask().GetAwaiter().GetResult();

    public override int Read(Span<byte> buffer)
    {
        var temp = new byte[buffer.Length];
        var read = ReadAsync(temp.AsMemory(0, temp.Length), CancellationToken.None).AsTask().GetAwaiter().GetResult();
        temp.AsSpan(0, read).CopyTo(buffer);
        return read;
    }

    public override async ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken cancellationToken = default)
    {
        var innerStream = await EnsureOpenedForReadAsync(cancellationToken).ConfigureAwait(false);
        return await innerStream.ReadAsync(buffer, cancellationToken).ConfigureAwait(false);
    }

    public override Task<int> ReadAsync(byte[] buffer, int offset, int count, CancellationToken cancellationToken)
        => ReadAsync(buffer.AsMemory(offset, count), cancellationToken).AsTask();

    public override void Write(byte[] buffer, int offset, int count)
        => WriteAsync(buffer.AsMemory(offset, count), CancellationToken.None).AsTask().GetAwaiter().GetResult();

    public override void Write(ReadOnlySpan<byte> buffer)
        => WriteAsync(buffer.ToArray().AsMemory(), CancellationToken.None).AsTask().GetAwaiter().GetResult();

    public override async ValueTask WriteAsync(ReadOnlyMemory<byte> buffer, CancellationToken cancellationToken = default)
    {
        var (innerStream, consumed) = await EnsureOpenedForWriteAsync(buffer, cancellationToken).ConfigureAwait(false);
        if (consumed)
        {
            return;
        }

        await innerStream.WriteAsync(buffer, cancellationToken).ConfigureAwait(false);
    }

    public override Task WriteAsync(byte[] buffer, int offset, int count, CancellationToken cancellationToken)
        => WriteAsync(buffer.AsMemory(offset, count), cancellationToken).AsTask();

    public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();

    public override void SetLength(long value) => throw new NotSupportedException();

    protected override void Dispose(bool disposing)
    {
        if (disposing &&
            Interlocked.Exchange(ref _disposed, 1) == 0)
        {
            _openedTcs.TrySetException(new EndOfStreamException("The delayed stream was disposed before it was opened."));
            _openLock.Dispose();
            _innerStream?.Dispose();
        }

        base.Dispose(disposing);
    }

    public override async ValueTask DisposeAsync()
    {
        if (Interlocked.Exchange(ref _disposed, 1) != 0)
        {
            return;
        }

        _openedTcs.TrySetException(new EndOfStreamException("The delayed stream was disposed before it was opened."));
        _openLock.Dispose();
        if (_innerStream is not null)
        {
            await _innerStream.DisposeAsync().ConfigureAwait(false);
        }
    }

    private async ValueTask<Stream> EnsureOpenedForReadAsync(CancellationToken cancellationToken)
    {
        ObjectDisposedException.ThrowIf(Volatile.Read(ref _disposed) != 0, this);

        if (_innerStream is not null)
        {
            return _innerStream;
        }

        if (_openException is not null)
        {
            ExceptionDispatchInfo.Capture(_openException).Throw();
        }

        return await _openedTcs.Task.WaitAsync(cancellationToken).ConfigureAwait(false);
    }

    private async ValueTask<(Stream Stream, bool Consumed)> EnsureOpenedForWriteAsync(
        ReadOnlyMemory<byte> buffer,
        CancellationToken cancellationToken)
    {
        ObjectDisposedException.ThrowIf(Volatile.Read(ref _disposed) != 0, this);

        if (_innerStream is not null)
        {
            return (_innerStream, false);
        }

        if (_openException is not null)
        {
            ExceptionDispatchInfo.Capture(_openException).Throw();
        }

        await _openLock.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            ObjectDisposedException.ThrowIf(Volatile.Read(ref _disposed) != 0, this);

            if (_innerStream is not null)
            {
                return (_innerStream, false);
            }

            if (_openException is not null)
            {
                ExceptionDispatchInfo.Capture(_openException).Throw();
            }

            var earlyData = buffer.Length > 0 && buffer.Length <= _earlyDataBytes
                ? buffer.ToArray()
                : null;
            try
            {
                _innerStream = await _openAsync(earlyData, cancellationToken).ConfigureAwait(false);
                _openedTcs.TrySetResult(_innerStream);
                return (_innerStream, earlyData is not null);
            }
            catch (Exception ex)
            {
                _openException = ex;
                _openedTcs.TrySetException(ex);
                throw;
            }
        }
        finally
        {
            _openLock.Release();
        }
    }
}

internal static class RuntimeInternetHttpUtilities
{
    public const string DefaultChromeUserAgent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/144.0.0.0 Safari/537.36";

    public static async Task<string> ReadHttpLineAsync(
        Stream stream,
        string eofMessage,
        CancellationToken cancellationToken)
    {
        using var buffer = new MemoryStream(128);
        var oneByte = new byte[1];

        while (buffer.Length < 8 * 1024)
        {
            var read = await stream.ReadAsync(oneByte.AsMemory(0, 1), cancellationToken).ConfigureAwait(false);
            if (read == 0)
            {
                throw new EndOfStreamException(eofMessage);
            }

            if (oneByte[0] == '\n')
            {
                var bytes = buffer.ToArray();
                if (bytes.Length > 0 && bytes[^1] == '\r')
                {
                    Array.Resize(ref bytes, bytes.Length - 1);
                }

                return Encoding.ASCII.GetString(bytes);
            }

            buffer.WriteByte(oneByte[0]);
        }

        throw new InvalidOperationException("HTTP handshake line exceeded the configured limit.");
    }

    public static string NormalizePath(string value)
    {
        if (string.IsNullOrWhiteSpace(value))
        {
            return "/";
        }

        var normalized = value.Trim();
        return normalized.StartsWith("/", StringComparison.Ordinal) ? normalized : "/" + normalized;
    }

    public static string BuildHostHeader(RuntimeInternetStack stack, IRuntimeInternetOptions options)
    {
        if (options.WebSocketHeaders.TryGetValue("Host", out var requestedHost) &&
            !string.IsNullOrWhiteSpace(requestedHost))
        {
            return requestedHost.Trim();
        }

        return RuntimeInternetSecurityTypes.UsesTlsLikeSemantics(stack.SecurityType)
            ? GetServerName(options)
            : options.ServerHost.Trim();
    }

    public static string BuildUserAgentHeader(IRuntimeInternetOptions options)
        => options.WebSocketHeaders.TryGetValue("User-Agent", out var requestedUserAgent) &&
           !string.IsNullOrWhiteSpace(requestedUserAgent)
            ? requestedUserAgent.Trim()
            : DefaultChromeUserAgent;

    public static string BuildGrpcUserAgentHeader(IRuntimeInternetOptions options)
        => !string.IsNullOrWhiteSpace(options.GrpcUserAgent)
            ? options.GrpcUserAgent.Trim()
            : DefaultChromeUserAgent;

    private static string GetServerName(IRuntimeInternetOptions options)
        => string.IsNullOrWhiteSpace(options.ServerName) ? options.ServerHost.Trim() : options.ServerName.Trim();
}

internal interface IRuntimeInternetTransportFactory
{
    string Name { get; }

    ValueTask ApplyAsync(
        RuntimeInternetConnectionContext context,
        RuntimeInternetStack stack,
        IRuntimeInternetOptions options,
        byte[]? transportInitializationData,
        CancellationToken cancellationToken);
}

internal interface IRuntimeInternetSecurityFactory
{
    string Name { get; }

    ValueTask ApplyAsync(
        RuntimeInternetConnectionContext context,
        RuntimeInternetStack stack,
        IRuntimeInternetOptions options,
        CancellationToken cancellationToken);
}

internal interface IRuntimeInternetBrowserDialer
{
    ValueTask<Stream> OpenStreamAsync(
        RuntimeInternetBrowserStreamRequest request,
        CancellationToken cancellationToken);

    ValueTask<Stream> OpenWebSocketStreamAsync(
        RuntimeInternetBrowserWebSocketRequest request,
        CancellationToken cancellationToken);

    ValueTask SendPacketAsync(
        RuntimeInternetBrowserPacketRequest request,
        ReadOnlyMemory<byte> payload,
        CancellationToken cancellationToken);
}

internal sealed record RuntimeInternetBrowserStreamRequest(
    string Url,
    IReadOnlyDictionary<string, string> Headers);

internal sealed record RuntimeInternetBrowserWebSocketRequest(
    string Url,
    string? SubProtocol);

internal sealed record RuntimeInternetBrowserPacketRequest(
    string Method,
    string Url,
    IReadOnlyDictionary<string, string> Headers);

internal sealed class RuntimeInternetProfile
{
    public static RuntimeInternetProfile Default { get; } = CreateDefault();

    private readonly IReadOnlyDictionary<string, IRuntimeInternetTransportFactory> _transportFactories;
    private readonly IReadOnlyDictionary<string, IRuntimeInternetSecurityFactory> _securityFactories;

    public RuntimeInternetProfile(
        IEnumerable<IRuntimeInternetTransportFactory> transportFactories,
        IEnumerable<IRuntimeInternetSecurityFactory> securityFactories,
        IRuntimeInternetBrowserDialer? browserDialer = null)
    {
        ArgumentNullException.ThrowIfNull(transportFactories);
        ArgumentNullException.ThrowIfNull(securityFactories);

        _transportFactories = BuildTransportFactories(transportFactories);
        _securityFactories = BuildSecurityFactories(securityFactories);
        BrowserDialer = browserDialer;
    }

    internal GrpcTunnelSessionPool GrpcTunnelSessionPool { get; } = new();

    internal IRuntimeInternetBrowserDialer? BrowserDialer { get; }

    internal static RuntimeInternetProfile FromDefault(
        IEnumerable<IRuntimeInternetTransportFactory>? transportFactories = null,
        IEnumerable<IRuntimeInternetSecurityFactory>? securityFactories = null,
        bool replaceExistingTransportFactories = false,
        bool replaceExistingSecurityFactories = false,
        IRuntimeInternetBrowserDialer? browserDialer = null)
        => new(
            MergeFactories(
                CreateDefaultTransportFactories(),
                transportFactories,
                static factory => RuntimeInternetTransportProtocols.Normalize(factory.Name),
                replaceExistingTransportFactories,
                static name => $"Runtime internet transport factory '{name}' is already registered."),
            MergeFactories(
                CreateDefaultSecurityFactories(),
                securityFactories,
                static factory => RuntimeInternetSecurityTypes.Normalize(factory.Name),
                replaceExistingSecurityFactories,
                static name => $"Runtime internet security factory '{name}' is already registered."),
            browserDialer);

    public RuntimeInternetStack Resolve(RuntimeInternetStack stack)
    {
        var normalized = RuntimeInternetStack.Create(stack.TransportProtocol, stack.SecurityType);
        ValidateSecurityTransportCompatibility(normalized);
        _ = GetSecurityFactory(normalized.SecurityType);
        _ = GetTransportFactory(normalized.TransportProtocol);
        return normalized;
    }

    public async ValueTask<RuntimeInternetConnectionContext> OpenAsync(
        Stream baseStream,
        RuntimeInternetStack stack,
        IRuntimeInternetOptions options,
        byte[]? transportInitializationData,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(baseStream);
        ArgumentNullException.ThrowIfNull(options);

        var normalizedStack = Resolve(stack);
        var context = await SecureCoreAsync(baseStream, normalizedStack, options, cancellationToken)
            .ConfigureAwait(false);
        await ApplyTransportCoreAsync(context, normalizedStack, options, transportInitializationData, cancellationToken)
            .ConfigureAwait(false);

        return context;
    }

    internal async ValueTask<RuntimeInternetConnectionContext> SecureAsync(
        Stream baseStream,
        RuntimeInternetStack stack,
        IRuntimeInternetOptions options,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(baseStream);
        ArgumentNullException.ThrowIfNull(options);

        var normalizedStack = Resolve(stack);
        return await SecureCoreAsync(baseStream, normalizedStack, options, cancellationToken)
            .ConfigureAwait(false);
    }

    internal async ValueTask ApplyTransportAsync(
        RuntimeInternetConnectionContext context,
        RuntimeInternetStack stack,
        IRuntimeInternetOptions options,
        byte[]? transportInitializationData,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(context);
        ArgumentNullException.ThrowIfNull(options);

        var normalizedStack = Resolve(stack);
        await ApplyTransportCoreAsync(context, normalizedStack, options, transportInitializationData, cancellationToken)
            .ConfigureAwait(false);
    }

    internal async ValueTask<RuntimeInternetConnectionContext?> TryOpenWithoutBaseTransportAsync(
        RuntimeInternetStack stack,
        IRuntimeInternetOptions options,
        byte[]? transportInitializationData,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(options);

        var normalizedStack = Resolve(stack);
        return await WebSocketTransportFactory
            .TryOpenWithBrowserDialerAsync(
                BrowserDialer,
                normalizedStack,
                options,
                transportInitializationData,
                cancellationToken)
            .ConfigureAwait(false);
    }

    private IRuntimeInternetTransportFactory GetTransportFactory(string name)
        => _transportFactories.TryGetValue(RuntimeInternetTransportProtocols.Normalize(name), out var factory)
            ? factory
            : throw new NotSupportedException(
                RuntimeInternetTransportProtocols.TryGetKnownAvailabilityError(name, out var error)
                    ? error
                    : $"Unsupported runtime internet transport protocol: {name}.");

    private IRuntimeInternetSecurityFactory GetSecurityFactory(string name)
        => _securityFactories.TryGetValue(RuntimeInternetSecurityTypes.Normalize(name), out var factory)
            ? factory
            : throw new NotSupportedException($"Unsupported runtime internet security type: {name}.");

    private async ValueTask<RuntimeInternetConnectionContext> SecureCoreAsync(
        Stream baseStream,
        RuntimeInternetStack normalizedStack,
        IRuntimeInternetOptions options,
        CancellationToken cancellationToken)
    {
        var context = new RuntimeInternetConnectionContext(baseStream);
        await GetSecurityFactory(normalizedStack.SecurityType)
            .ApplyAsync(context, normalizedStack, options, cancellationToken)
            .ConfigureAwait(false);
        return context;
    }

    private async ValueTask ApplyTransportCoreAsync(
        RuntimeInternetConnectionContext context,
        RuntimeInternetStack normalizedStack,
        IRuntimeInternetOptions options,
        byte[]? transportInitializationData,
        CancellationToken cancellationToken)
    {
        await GetTransportFactory(normalizedStack.TransportProtocol)
            .ApplyAsync(context, normalizedStack, options, transportInitializationData, cancellationToken)
            .ConfigureAwait(false);
    }

    private static void ValidateSecurityTransportCompatibility(RuntimeInternetStack stack)
    {
        if (string.Equals(stack.SecurityType, RuntimeInternetSecurityTypes.Reality, StringComparison.Ordinal) &&
            stack.TransportProtocol is not (
                RuntimeInternetTransportProtocols.Tcp or
                RuntimeInternetTransportProtocols.Grpc or
                RuntimeInternetTransportProtocols.SplitHttp))
        {
            throw new NotSupportedException("REALITY security currently only supports tcp, splithttp and grpc transports.");
        }
    }

    internal static SslClientAuthenticationOptions CreateClientAuthenticationOptions(
        RuntimeInternetStack stack,
        IRuntimeInternetOptions options)
    {
        var sslOptions = new SslClientAuthenticationOptions
        {
            TargetHost = string.IsNullOrWhiteSpace(options.ServerName) ? options.ServerHost.Trim() : options.ServerName.Trim(),
            EnabledSslProtocols = options.EnabledSslProtocols,
            AllowTlsResume = IsTlsSessionResumptionEnabled(options),
            CertificateRevocationCheckMode = X509RevocationMode.NoCheck,
            ClientCertificateContext = null,
            ClientCertificates = null,
            LocalCertificateSelectionCallback = null
        };

        var applicationProtocols = ResolveClientApplicationProtocols(stack, options);
        if (applicationProtocols.Count > 0)
        {
            sslOptions.ApplicationProtocols = applicationProtocols
                .Where(static value => !string.IsNullOrWhiteSpace(value))
                .Select(static value => new SslApplicationProtocol(value))
                .ToList();
        }

        return sslOptions;
    }

    private static bool IsTlsSessionResumptionEnabled(IRuntimeInternetOptions options)
        => options is IRuntimeTlsSessionResumptionOptions { EnableTlsSessionResumption: true };

    internal static IReadOnlyList<string> ResolveClientApplicationProtocols(
        RuntimeInternetStack stack,
        IRuntimeInternetOptions options)
        => stack.TransportProtocol switch
        {
            RuntimeInternetTransportProtocols.Tcp
                => options.ApplicationProtocols.Count > 0
                    ? options.ApplicationProtocols
                    : ["h2", "http/1.1"],
            RuntimeInternetTransportProtocols.Mkcp => options.ApplicationProtocols,
            RuntimeInternetTransportProtocols.Grpc
                => ["h2"],
            RuntimeInternetTransportProtocols.SplitHttp
                => options.ApplicationProtocols.Count > 0
                    ? options.ApplicationProtocols
                    : ["h2", "http/1.1"],
            RuntimeInternetTransportProtocols.Ws or RuntimeInternetTransportProtocols.HttpUpgrade
                => ["http/1.1"],
            _ => Array.Empty<string>()
        };

    private static IReadOnlyDictionary<string, IRuntimeInternetTransportFactory> BuildTransportFactories(
        IEnumerable<IRuntimeInternetTransportFactory> factories)
    {
        var dictionary = new Dictionary<string, IRuntimeInternetTransportFactory>(StringComparer.OrdinalIgnoreCase);
        foreach (var factory in factories)
        {
            var name = RuntimeInternetTransportProtocols.Normalize(factory.Name);
            if (!dictionary.TryAdd(name, factory))
            {
                throw new InvalidOperationException($"Runtime internet transport factory '{name}' is already registered.");
            }
        }

        return dictionary;
    }

    private static IReadOnlyDictionary<string, IRuntimeInternetSecurityFactory> BuildSecurityFactories(
        IEnumerable<IRuntimeInternetSecurityFactory> factories)
    {
        var dictionary = new Dictionary<string, IRuntimeInternetSecurityFactory>(StringComparer.OrdinalIgnoreCase);
        foreach (var factory in factories)
        {
            var name = RuntimeInternetSecurityTypes.Normalize(factory.Name);
            if (!dictionary.TryAdd(name, factory))
            {
                throw new InvalidOperationException($"Runtime internet security factory '{name}' is already registered.");
            }
        }

        return dictionary;
    }

    private static RuntimeInternetProfile CreateDefault()
        => new(CreateDefaultTransportFactories(), CreateDefaultSecurityFactories());

    private static IReadOnlyList<IRuntimeInternetTransportFactory> CreateDefaultTransportFactories()
        =>
        [
            new TcpTransportFactory(),
            new MkcpTransportFactory(),
            new GrpcTransportFactory(),
            new SplitHttpTransportFactory(),
            new HttpUpgradeTransportFactory(),
            new WebSocketTransportFactory()
        ];

    private static IReadOnlyList<IRuntimeInternetSecurityFactory> CreateDefaultSecurityFactories()
        =>
        [
            new NoSecurityFactory(),
            new TlsSecurityFactory(),
            new RealitySecurityFactory()
        ];

    private static IReadOnlyList<TFactory> MergeFactories<TFactory>(
        IReadOnlyList<TFactory> defaults,
        IEnumerable<TFactory>? overrides,
        Func<TFactory, string> keySelector,
        bool replaceExisting,
        Func<string, string> duplicateErrorFactory)
        where TFactory : class
    {
        ArgumentNullException.ThrowIfNull(defaults);
        ArgumentNullException.ThrowIfNull(keySelector);
        ArgumentNullException.ThrowIfNull(duplicateErrorFactory);

        var merged = defaults.ToDictionary(keySelector, StringComparer.OrdinalIgnoreCase);
        if (overrides is null)
        {
            return merged.Values.ToArray();
        }

        foreach (var factory in overrides)
        {
            ArgumentNullException.ThrowIfNull(factory);

            var key = keySelector(factory);
            if (replaceExisting || !merged.ContainsKey(key))
            {
                merged[key] = factory;
                continue;
            }

            throw new InvalidOperationException(duplicateErrorFactory(key));
        }

        return merged.Values.ToArray();
    }

    private sealed class TcpTransportFactory : IRuntimeInternetTransportFactory
    {
        public string Name => RuntimeInternetTransportProtocols.Tcp;

        public ValueTask ApplyAsync(
            RuntimeInternetConnectionContext context,
            RuntimeInternetStack stack,
            IRuntimeInternetOptions options,
            byte[]? transportInitializationData,
            CancellationToken cancellationToken)
            => ValueTask.CompletedTask;
    }

    private sealed class GrpcTransportFactory : IRuntimeInternetTransportFactory
    {
        public string Name => RuntimeInternetTransportProtocols.Grpc;

        public async ValueTask ApplyAsync(
            RuntimeInternetConnectionContext context,
            RuntimeInternetStack stack,
            IRuntimeInternetOptions options,
            byte[]? transportInitializationData,
            CancellationToken cancellationToken)
        {
            var applicationStream = await Http2GrpcTunnel
                .OpenAsync(context.TransportStream, stack, options, cancellationToken)
                .ConfigureAwait(false);
            context.SetApplicationStream(applicationStream);
        }
    }

    private sealed class SplitHttpTransportFactory : IRuntimeInternetTransportFactory
    {
        public string Name => RuntimeInternetTransportProtocols.SplitHttp;

        public ValueTask ApplyAsync(
            RuntimeInternetConnectionContext context,
            RuntimeInternetStack stack,
            IRuntimeInternetOptions options,
            byte[]? transportInitializationData,
            CancellationToken cancellationToken)
            => ValueTask.FromException(
                new NotSupportedException("SplitHTTP transport must be opened through the runtime client connector."));
    }

    private sealed class WebSocketTransportFactory : IRuntimeInternetTransportFactory
    {
        public string Name => RuntimeInternetTransportProtocols.Ws;

        internal static async ValueTask<RuntimeInternetConnectionContext?> TryOpenWithBrowserDialerAsync(
            IRuntimeInternetBrowserDialer? browserDialer,
            RuntimeInternetStack stack,
            IRuntimeInternetOptions options,
            byte[]? transportInitializationData,
            CancellationToken cancellationToken)
        {
            if (browserDialer is null ||
                !string.Equals(stack.TransportProtocol, RuntimeInternetTransportProtocols.Ws, StringComparison.Ordinal) ||
                options is not IRuntimeGrpcClientDialOptions dialOptions ||
                string.Equals(stack.SecurityType, RuntimeInternetSecurityTypes.Reality, StringComparison.Ordinal))
            {
                return null;
            }

            var webSocketUrl = BuildBrowserWebSocketUrl(stack, options, dialOptions.ServerPort);
            var earlyDataBytes = ResolveWebSocketEarlyDataBytes(options);
            if (earlyDataBytes > 0 &&
                !HasTransportInitializationData(transportInitializationData))
            {
                var delayedStream = new RuntimeDelayedOpenStream(
                    earlyDataBytes,
                    async (candidateEarlyData, ct) => await browserDialer
                        .OpenWebSocketStreamAsync(
                            new RuntimeInternetBrowserWebSocketRequest(
                                webSocketUrl,
                                EncodeSubProtocol(candidateEarlyData)),
                            ct)
                        .ConfigureAwait(false));

                var delayedContext = new RuntimeInternetConnectionContext(delayedStream);
                delayedContext.SetTransportStream(
                    delayedStream,
                    securityState: CreateBrowserDialerSecurityState(stack));
                delayedContext.SetApplicationStream(delayedStream);
                return delayedContext;
            }

            var webSocketStream = await browserDialer
                .OpenWebSocketStreamAsync(
                    new RuntimeInternetBrowserWebSocketRequest(
                        webSocketUrl,
                        EncodeSubProtocol(transportInitializationData)),
                    cancellationToken)
                .ConfigureAwait(false);

            var context = new RuntimeInternetConnectionContext(webSocketStream);
            context.SetTransportStream(
                webSocketStream,
                securityState: CreateBrowserDialerSecurityState(stack));
            context.SetApplicationStream(webSocketStream);
            return context;
        }

        public async ValueTask ApplyAsync(
            RuntimeInternetConnectionContext context,
            RuntimeInternetStack stack,
            IRuntimeInternetOptions options,
            byte[]? transportInitializationData,
            CancellationToken cancellationToken)
        {
            var earlyDataBytes = ResolveWebSocketEarlyDataBytes(options);
            if (earlyDataBytes > 0 &&
                !HasTransportInitializationData(transportInitializationData))
            {
                context.SetApplicationStream(
                    new RuntimeDelayedOpenStream(
                        earlyDataBytes,
                        async (candidateEarlyData, ct) =>
                        {
                            var delayedWebSocket = await OpenWebSocketAsync(
                                    context.TransportStream,
                                    stack,
                                    options,
                                    candidateEarlyData,
                                    ct)
                                .ConfigureAwait(false);
                            return new WebSocketDuplexStream(delayedWebSocket);
                        }));
                return;
            }

            var webSocket = await OpenWebSocketAsync(
                    context.TransportStream,
                    stack,
                    options,
                    transportInitializationData,
                    cancellationToken)
                .ConfigureAwait(false);
            context.SetApplicationStream(new WebSocketDuplexStream(webSocket), webSocket);
        }

        private static async Task<WebSocket> OpenWebSocketAsync(
            Stream transportStream,
            RuntimeInternetStack stack,
            IRuntimeInternetOptions options,
            byte[]? transportInitializationData,
            CancellationToken cancellationToken)
        {
            var webSocketKey = Convert.ToBase64String(RandomNumberGenerator.GetBytes(16));
            var request = BuildWebSocketRequest(stack, options, webSocketKey, transportInitializationData);

            await transportStream.WriteAsync(Encoding.ASCII.GetBytes(request), cancellationToken).ConfigureAwait(false);
            await transportStream.FlushAsync(cancellationToken).ConfigureAwait(false);

            var statusLine = await RuntimeInternetHttpUtilities
                .ReadHttpLineAsync(
                    transportStream,
                    "Unexpected EOF during WebSocket handshake.",
                    cancellationToken)
                .ConfigureAwait(false);
            if (!statusLine.StartsWith("HTTP/1.1 101", StringComparison.Ordinal))
            {
                throw new InvalidOperationException($"Unexpected WebSocket response status: {statusLine}");
            }

            var headers = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
            while (true)
            {
                var line = await RuntimeInternetHttpUtilities
                    .ReadHttpLineAsync(
                        transportStream,
                        "Unexpected EOF during WebSocket handshake.",
                        cancellationToken)
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

            if (!headers.TryGetValue("Sec-WebSocket-Accept", out var acceptValue))
            {
                throw new InvalidOperationException("WebSocket response is missing Sec-WebSocket-Accept.");
            }

            var expectedAccept = ComputeWebSocketAccept(webSocketKey);
            if (!string.Equals(acceptValue, expectedAccept, StringComparison.Ordinal))
            {
                throw new InvalidOperationException("WebSocket Sec-WebSocket-Accept validation failed.");
            }

            return WebSocket.CreateFromStream(
                transportStream,
                isServer: false,
                subProtocol: null,
                keepAliveInterval: options.WebSocketHeartbeatPeriodSeconds > 0
                    ? TimeSpan.FromSeconds(options.WebSocketHeartbeatPeriodSeconds)
                    : Timeout.InfiniteTimeSpan);
        }

        private static string BuildWebSocketRequest(
            RuntimeInternetStack stack,
            IRuntimeInternetOptions options,
            string webSocketKey,
            byte[]? transportInitializationData)
        {
            var reservedHeaders = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
            {
                "Upgrade",
                "Connection",
                "Sec-WebSocket-Key",
                "Sec-WebSocket-Version",
                "Sec-WebSocket-Protocol",
                "User-Agent"
            };

            var builder = new StringBuilder(512);
            builder.Append("GET ");
            builder.Append(RuntimeInternetHttpUtilities.NormalizePath(options.WebSocketPath));
            builder.Append(" HTTP/1.1\r\n");
            builder.Append("Host: ");
            builder.Append(RuntimeInternetHttpUtilities.BuildHostHeader(stack, options));
            builder.Append("\r\n");
            builder.Append("Upgrade: websocket\r\n");
            builder.Append("Connection: Upgrade\r\n");
            builder.Append("Sec-WebSocket-Key: ");
            builder.Append(webSocketKey);
            builder.Append("\r\n");
            builder.Append("Sec-WebSocket-Version: 13\r\n");
            builder.Append("User-Agent: ");
            builder.Append(RuntimeInternetHttpUtilities.BuildUserAgentHeader(options));
            builder.Append("\r\n");
            var subProtocol = EncodeSubProtocol(transportInitializationData);
            if (!string.IsNullOrWhiteSpace(subProtocol))
            {
                builder.Append("Sec-WebSocket-Protocol: ");
                builder.Append(subProtocol);
                builder.Append("\r\n");
            }

            foreach (var (name, value) in options.WebSocketHeaders)
            {
                if (string.IsNullOrWhiteSpace(name) ||
                    string.IsNullOrWhiteSpace(value) ||
                    reservedHeaders.Contains(name) ||
                    string.Equals(name, "Host", StringComparison.OrdinalIgnoreCase))
                {
                    continue;
                }

                builder.Append(name.Trim());
                builder.Append(": ");
                builder.Append(value.Trim());
                builder.Append("\r\n");
            }

            builder.Append("\r\n");
            return builder.ToString();
        }

        private static string ComputeWebSocketAccept(string key)
        {
            const string webSocketGuid = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";
            var input = Encoding.ASCII.GetBytes(key + webSocketGuid);
            return Convert.ToBase64String(SHA1.HashData(input));
        }

        private static string BuildBrowserWebSocketUrl(
            RuntimeInternetStack stack,
            IRuntimeInternetOptions options,
            int serverPort)
        {
            var scheme = RuntimeInternetSecurityTypes.UsesTlsLikeSemantics(stack.SecurityType)
                ? "wss"
                : "ws";
            var host = NormalizeHostForUri(options.ServerHost);
            var authority = serverPort == (string.Equals(scheme, "wss", StringComparison.Ordinal) ? 443 : 80)
                ? host
                : host + ":" + serverPort;
            return scheme + "://" + authority + RuntimeInternetHttpUtilities.NormalizePath(options.WebSocketPath);
        }

        private static string NormalizeHostForUri(string host)
        {
            var normalized = host.Trim();
            if (normalized.StartsWith("[", StringComparison.Ordinal) ||
                normalized.IndexOf(':') < 0)
            {
                return normalized;
            }

            return "[" + normalized + "]";
        }

        private static string? EncodeSubProtocol(byte[]? transportInitializationData)
            => transportInitializationData is { Length: > 0 }
                ? Convert.ToBase64String(transportInitializationData)
                    .TrimEnd('=')
                    .Replace('+', '-')
                    .Replace('/', '_')
                : null;

        private static int ResolveWebSocketEarlyDataBytes(IRuntimeInternetOptions options)
            => options is IRuntimeGrpcClientDialOptions dialOptions
                ? Math.Max(0, dialOptions.WebSocketEarlyDataBytes)
                : 0;

        private static bool HasTransportInitializationData(byte[]? transportInitializationData)
            => transportInitializationData is not null;

        private static RuntimeInternetSecurityState CreateBrowserDialerSecurityState(RuntimeInternetStack stack)
            => RuntimeInternetSecurityTypes.IsSecure(stack.SecurityType)
                ? RuntimeInternetSecurityState.Create(stack.SecurityType, SslProtocols.None)
                : RuntimeInternetSecurityState.None;

    }

    private sealed class HttpUpgradeTransportFactory : IRuntimeInternetTransportFactory
    {
        public string Name => RuntimeInternetTransportProtocols.HttpUpgrade;

        public async ValueTask ApplyAsync(
            RuntimeInternetConnectionContext context,
            RuntimeInternetStack stack,
            IRuntimeInternetOptions options,
            byte[]? transportInitializationData,
            CancellationToken cancellationToken)
        {
            var applicationStream = await OpenHttpUpgradeAsync(
                    context.TransportStream,
                    stack,
                    options,
                    transportInitializationData,
                    cancellationToken)
                .ConfigureAwait(false);
            context.SetApplicationStream(applicationStream);
        }

        private static async Task<Stream> OpenHttpUpgradeAsync(
            Stream transportStream,
            RuntimeInternetStack stack,
            IRuntimeInternetOptions options,
            byte[]? transportInitializationData,
            CancellationToken cancellationToken)
        {
            var request = BuildHttpUpgradeRequest(stack, options);

            await transportStream.WriteAsync(Encoding.ASCII.GetBytes(request), cancellationToken).ConfigureAwait(false);
            if (transportInitializationData is { Length: > 0 })
            {
                await transportStream
                    .WriteAsync(transportInitializationData.AsMemory(0, transportInitializationData.Length), cancellationToken)
                    .ConfigureAwait(false);
            }

            await transportStream.FlushAsync(cancellationToken).ConfigureAwait(false);

            var upgradeStream = new HttpUpgradeStream(transportStream);
            if (transportInitializationData is null || transportInitializationData.Length == 0)
            {
                await upgradeStream.EnsureUpgradeAsync(cancellationToken).ConfigureAwait(false);
            }

            return upgradeStream;
        }

        private static string BuildHttpUpgradeRequest(
            RuntimeInternetStack stack,
            IRuntimeInternetOptions options)
        {
            var headers = ResolveHttpUpgradeHeaders(options);
            var reservedHeaders = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
            {
                "Connection",
                "Upgrade",
                "User-Agent"
            };

            var builder = new StringBuilder(512);
            builder.Append("GET ");
            builder.Append(ResolveHttpUpgradePath(options));
            builder.Append(" HTTP/1.1\r\n");
            builder.Append("Host: ");
            builder.Append(BuildHttpUpgradeHostHeader(stack, options, headers));
            builder.Append("\r\n");
            builder.Append("Connection: Upgrade\r\n");
            builder.Append("Upgrade: websocket\r\n");
            builder.Append("User-Agent: ");
            builder.Append(BuildHttpUpgradeUserAgentHeader(options, headers));
            builder.Append("\r\n");

            foreach (var (name, value) in headers)
            {
                if (string.IsNullOrWhiteSpace(name) ||
                    string.IsNullOrWhiteSpace(value) ||
                    reservedHeaders.Contains(name) ||
                    string.Equals(name, "Host", StringComparison.OrdinalIgnoreCase))
                {
                    continue;
                }

                builder.Append(name.Trim());
                builder.Append(": ");
                builder.Append(value.Trim());
                builder.Append("\r\n");
            }

            builder.Append("\r\n");
            return builder.ToString();
        }

        private static string ResolveHttpUpgradePath(IRuntimeInternetOptions options)
        {
            var splitHttpPath = RuntimeInternetHttpUtilities.NormalizePath(options.SplitHttpPath);
            if (!string.Equals(splitHttpPath, "/", StringComparison.Ordinal))
            {
                return splitHttpPath;
            }

            var webSocketPath = RuntimeInternetHttpUtilities.NormalizePath(options.WebSocketPath);
            return string.Equals(webSocketPath, "/ws", StringComparison.Ordinal)
                ? splitHttpPath
                : webSocketPath;
        }

        private static IReadOnlyDictionary<string, string> ResolveHttpUpgradeHeaders(IRuntimeInternetOptions options)
            => options.SplitHttpHeaders.Count > 0
                ? options.SplitHttpHeaders
                : options.WebSocketHeaders;

        private static string BuildHttpUpgradeHostHeader(
            RuntimeInternetStack stack,
            IRuntimeInternetOptions options,
            IReadOnlyDictionary<string, string> headers)
        {
            if (!string.IsNullOrWhiteSpace(options.SplitHttpHost))
            {
                return options.SplitHttpHost.Trim();
            }

            if (headers.TryGetValue("Host", out var requestedHost) &&
                !string.IsNullOrWhiteSpace(requestedHost))
            {
                return requestedHost.Trim();
            }

            return RuntimeInternetHttpUtilities.BuildHostHeader(stack, options);
        }

        private static string BuildHttpUpgradeUserAgentHeader(
            IRuntimeInternetOptions options,
            IReadOnlyDictionary<string, string> headers)
            => headers.TryGetValue("User-Agent", out var requestedUserAgent) &&
               !string.IsNullOrWhiteSpace(requestedUserAgent)
                ? requestedUserAgent.Trim()
                : RuntimeInternetHttpUtilities.BuildUserAgentHeader(options);
    }

    private sealed class NoSecurityFactory : IRuntimeInternetSecurityFactory
    {
        public string Name => RuntimeInternetSecurityTypes.None;

        public ValueTask ApplyAsync(
            RuntimeInternetConnectionContext context,
            RuntimeInternetStack stack,
            IRuntimeInternetOptions options,
            CancellationToken cancellationToken)
            => ValueTask.CompletedTask;
    }

    private sealed class TlsSecurityFactory : IRuntimeInternetSecurityFactory
    {
        public string Name => RuntimeInternetSecurityTypes.Tls;

        public async ValueTask ApplyAsync(
            RuntimeInternetConnectionContext context,
            RuntimeInternetStack stack,
            IRuntimeInternetOptions options,
            CancellationToken cancellationToken)
        {
            var normalizedFingerprint = RuntimeTlsFingerprintCatalog.Normalize(options.Fingerprint);
            if (!RuntimeTlsFingerprintCatalog.IsKnown(normalizedFingerprint))
            {
                throw new ArgumentException(
                    $"TLS fingerprint '{normalizedFingerprint}' is unknown.",
                    nameof(options));
            }

            if (RuntimeTlsFingerprintCatalog.ShouldUseCustomClient(
                    normalizedFingerprint,
                    options.EnabledSslProtocols))
            {
                var result = await new RuntimeTlsFingerprintClient(
                        new RuntimeTlsFingerprintHandshakeRequest
                        {
                            TransportStream = context.TransportStream,
                            ServerHost = options.ServerHost.Trim(),
                            ServerName = GetServerName(options),
                            TransportProtocol = stack.TransportProtocol,
                            ApplicationProtocols = ResolveClientApplicationProtocols(stack, options),
                            Fingerprint = normalizedFingerprint,
                            SkipCertificateValidation = options.SkipCertificateValidation,
                            CertificateValidationCallback = options.CertificateValidationCallback,
                            EnabledSslProtocols = options.EnabledSslProtocols
                        })
                    .ConnectAsync(cancellationToken)
                    .ConfigureAwait(false);

                context.SetTransportStream(
                    result.TransportStream,
                    result.SslStream,
                    securityState: result.SecurityState);
                return;
            }

            var sslStream = new SslStream(
                context.TransportStream,
                leaveInnerStreamOpen: false,
                (_, certificate, chain, errors) => RuntimeServerCertificateValidation.Validate(
                    options.SkipCertificateValidation,
                    options.CertificateValidationCallback,
                    options,
                    certificate,
                    chain,
                    errors));

            try
            {
                await sslStream
                    .AuthenticateAsClientAsync(BuildSslClientAuthenticationOptions(stack, options), cancellationToken)
                    .ConfigureAwait(false);
                context.SetTransportStream(
                    sslStream,
                    sslStream,
                    securityState: RuntimeInternetSecurityState.Create(
                        RuntimeInternetSecurityTypes.Tls,
                        sslStream));
            }
            catch
            {
                await sslStream.DisposeAsync().ConfigureAwait(false);
                throw;
            }
        }

        private static SslClientAuthenticationOptions BuildSslClientAuthenticationOptions(
            RuntimeInternetStack stack,
            IRuntimeInternetOptions options)
            => CreateClientAuthenticationOptions(stack, options);
    }

    private sealed class RealitySecurityFactory : IRuntimeInternetSecurityFactory
    {
        public string Name => RuntimeInternetSecurityTypes.Reality;

        public ValueTask ApplyAsync(
            RuntimeInternetConnectionContext context,
            RuntimeInternetStack stack,
            IRuntimeInternetOptions options,
            CancellationToken cancellationToken)
        {
            if (!options.RealityOptions.TryValidateForReality(out var normalizedOptions, out var error))
            {
                return ValueTask.FromException(new ArgumentException(error, nameof(options)));
            }

            if (context.TransportStream is SslStream tlsLikeStream &&
                tlsLikeStream.SslProtocol != SslProtocols.None)
            {
                context.SetTransportStream(
                    tlsLikeStream,
                    tlsLikeStream,
                    securityState: RuntimeInternetSecurityState.Create(
                        RuntimeInternetSecurityTypes.Reality,
                        tlsLikeStream));
                return ValueTask.CompletedTask;
            }

            var handshakeProvider = options is IRuntimeRealityHandshakeProviderAccessor
                {
                    RealityHandshakeProvider: { } explicitProvider
                }
                ? explicitProvider
                : RuntimeRealityHandshakeProviders.Default;
            return ApplyWithProviderAsync(
                context,
                stack,
                options,
                normalizedOptions,
                handshakeProvider,
                cancellationToken);
        }

        private static async ValueTask ApplyWithProviderAsync(
            RuntimeInternetConnectionContext context,
            RuntimeInternetStack stack,
            IRuntimeInternetOptions options,
            RuntimeRealityOptions normalizedOptions,
            IRuntimeRealityHandshakeProvider handshakeProvider,
            CancellationToken cancellationToken)
        {
            var result = await handshakeProvider
                .SecureAsync(
                    new RuntimeRealityHandshakeRequest
                    {
                        TransportStream = context.TransportStream,
                        ServerHost = options.ServerHost.Trim(),
                        ServerName = GetServerName(options),
                        TransportProtocol = stack.TransportProtocol,
                        ApplicationProtocols = ResolveClientApplicationProtocols(stack, options),
                        RealityOptions = normalizedOptions,
                        SkipCertificateValidation = options.SkipCertificateValidation,
                        CertificateValidationCallback = options.CertificateValidationCallback,
                        EnabledSslProtocols = options.EnabledSslProtocols
                    },
                    cancellationToken)
                .ConfigureAwait(false);

            ArgumentNullException.ThrowIfNull(result);
            ArgumentNullException.ThrowIfNull(result.TransportStream);

            var securityState = NormalizeRealitySecurityState(result);
            context.SetTransportStream(
                result.TransportStream,
                result.SslStream,
                securityState: securityState);
        }

        private static RuntimeInternetSecurityState NormalizeRealitySecurityState(RuntimeRealityHandshakeResult result)
        {
            ArgumentNullException.ThrowIfNull(result);

            var normalized = RuntimeInternetSecurityTypes.Normalize(result.SecurityState.SecurityType);
            if (!RuntimeInternetSecurityTypes.UsesTlsLikeSemantics(normalized))
            {
                throw new InvalidOperationException("REALITY handshake provider must return a TLS-like security state.");
            }

            if (result.SecurityState.NegotiatedSslProtocol == SslProtocols.None)
            {
                throw new InvalidOperationException("REALITY handshake provider must report a negotiated TLS protocol.");
            }

            return result.SecurityState with
            {
                SecurityType = RuntimeInternetSecurityTypes.Reality
            };
        }
    }

    private static string GetServerName(IRuntimeInternetOptions options)
        => string.IsNullOrWhiteSpace(options.ServerName) ? options.ServerHost.Trim() : options.ServerName.Trim();

    private sealed class HttpUpgradeStream : Stream
    {
        private readonly Stream _innerStream;
        private readonly SemaphoreSlim _upgradeLock = new(1, 1);

        private int _disposed;
        private Exception? _upgradeException;
        private int _upgradeState;

        public HttpUpgradeStream(Stream innerStream)
        {
            ArgumentNullException.ThrowIfNull(innerStream);
            _innerStream = innerStream;
        }

        public override bool CanRead => _innerStream.CanRead;

        public override bool CanSeek => _innerStream.CanSeek;

        public override bool CanWrite => _innerStream.CanWrite;

        public override bool CanTimeout => _innerStream.CanTimeout;

        public override long Length => _innerStream.Length;

        public override long Position
        {
            get => _innerStream.Position;
            set => _innerStream.Position = value;
        }

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

        public async ValueTask EnsureUpgradeAsync(CancellationToken cancellationToken)
        {
            var state = Volatile.Read(ref _upgradeState);
            if (state == 1)
            {
                return;
            }

            if (state == 2)
            {
                ThrowUpgradeException();
            }

            await _upgradeLock.WaitAsync(cancellationToken).ConfigureAwait(false);
            try
            {
                state = Volatile.Read(ref _upgradeState);
                if (state == 1)
                {
                    return;
                }

                if (state == 2)
                {
                    ThrowUpgradeException();
                }

                try
                {
                    await ReadAndValidateResponseAsync(_innerStream, cancellationToken).ConfigureAwait(false);
                    Volatile.Write(ref _upgradeState, 1);
                }
                catch (Exception ex)
                {
                    _upgradeException = ex;
                    Volatile.Write(ref _upgradeState, 2);
                    throw;
                }
            }
            finally
            {
                _upgradeLock.Release();
            }
        }

        public override void Flush() => _innerStream.Flush();

        public override Task FlushAsync(CancellationToken cancellationToken) => _innerStream.FlushAsync(cancellationToken);

        public override int Read(byte[] buffer, int offset, int count)
            => ReadAsync(buffer.AsMemory(offset, count), CancellationToken.None).AsTask().GetAwaiter().GetResult();

        public override int Read(Span<byte> buffer)
        {
            EnsureUpgradeAsync(CancellationToken.None).AsTask().GetAwaiter().GetResult();
            return _innerStream.Read(buffer);
        }

        public override async ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken cancellationToken = default)
        {
            await EnsureUpgradeAsync(cancellationToken).ConfigureAwait(false);
            return await _innerStream.ReadAsync(buffer, cancellationToken).ConfigureAwait(false);
        }

        public override Task<int> ReadAsync(byte[] buffer, int offset, int count, CancellationToken cancellationToken)
            => ReadAsync(buffer.AsMemory(offset, count), cancellationToken).AsTask();

        public override long Seek(long offset, SeekOrigin origin) => _innerStream.Seek(offset, origin);

        public override void SetLength(long value) => _innerStream.SetLength(value);

        public override void Write(byte[] buffer, int offset, int count) => _innerStream.Write(buffer, offset, count);

        public override void Write(ReadOnlySpan<byte> buffer) => _innerStream.Write(buffer);

        public override ValueTask WriteAsync(ReadOnlyMemory<byte> buffer, CancellationToken cancellationToken = default)
            => _innerStream.WriteAsync(buffer, cancellationToken);

        public override Task WriteAsync(byte[] buffer, int offset, int count, CancellationToken cancellationToken)
            => _innerStream.WriteAsync(buffer, offset, count, cancellationToken);

        protected override void Dispose(bool disposing)
        {
            if (disposing &&
                Interlocked.Exchange(ref _disposed, 1) == 0)
            {
                _upgradeLock.Dispose();
                _innerStream.Dispose();
            }

            base.Dispose(disposing);
        }

        public override async ValueTask DisposeAsync()
        {
            if (Interlocked.Exchange(ref _disposed, 1) != 0)
            {
                return;
            }

            _upgradeLock.Dispose();
            await _innerStream.DisposeAsync().ConfigureAwait(false);
        }

        private static async Task ReadAndValidateResponseAsync(
            Stream stream,
            CancellationToken cancellationToken)
        {
            var statusLine = await RuntimeInternetHttpUtilities
                .ReadHttpLineAsync(
                    stream,
                    "Unexpected EOF during HTTP Upgrade handshake.",
                    cancellationToken)
                .ConfigureAwait(false);
            if (!statusLine.StartsWith("HTTP/1.1 101", StringComparison.Ordinal))
            {
                throw new InvalidOperationException($"Unexpected HTTP Upgrade response status: {statusLine}");
            }

            var headers = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
            while (true)
            {
                var line = await RuntimeInternetHttpUtilities
                    .ReadHttpLineAsync(
                        stream,
                        "Unexpected EOF during HTTP Upgrade handshake.",
                        cancellationToken)
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

            if (!headers.TryGetValue("Upgrade", out var upgradeValue) ||
                !string.Equals(upgradeValue, "websocket", StringComparison.OrdinalIgnoreCase))
            {
                throw new InvalidOperationException("HTTP Upgrade response is missing Upgrade: websocket.");
            }

            if (!headers.TryGetValue("Connection", out var connectionValue) ||
                !string.Equals(connectionValue, "upgrade", StringComparison.OrdinalIgnoreCase))
            {
                throw new InvalidOperationException("HTTP Upgrade response is missing Connection: Upgrade.");
            }
        }

        private void ThrowUpgradeException()
        {
            if (_upgradeException is null)
            {
                throw new InvalidOperationException("HTTP Upgrade handshake failed.");
            }

            ExceptionDispatchInfo.Capture(_upgradeException).Throw();
        }
    }
}

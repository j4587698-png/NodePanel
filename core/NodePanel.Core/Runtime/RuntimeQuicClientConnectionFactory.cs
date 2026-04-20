using System.Net;
using System.Net.Quic;
using System.Net.Security;
using System.Net.Sockets;
using System.Runtime.Versioning;
using System.Security.Authentication;
using System.Security.Cryptography.X509Certificates;

namespace NodePanel.Core.Runtime;

[SupportedOSPlatform("windows")]
[SupportedOSPlatform("linux")]
[SupportedOSPlatform("macos")]
internal static class RuntimeQuicClientConnectionFactory
{
    private const long DefaultCloseErrorCode = 0;
    private const long DefaultStreamErrorCode = 0;
    private const int DefaultHttp3MaxInboundUnidirectionalStreams = 10;
    private const long MinReceiveWindowSize = 16_384;
    private const long MinBrutalBandwidthBytesPerSecond = 65_536;
    private const long MinUdpHopIntervalSeconds = 5;
    private const long MinMaxIdleTimeoutSeconds = 4;
    private const long MaxMaxIdleTimeoutSeconds = 120;
    private const long MinKeepAlivePeriodSeconds = 2;
    private const long MaxKeepAlivePeriodSeconds = 60;
    private const long MinMaxIncomingStreams = 8;
    private static readonly TimeSpan DefaultHttp3IdleTimeout = TimeSpan.FromSeconds(300);
    private static readonly TimeSpan DefaultHttp3KeepAliveInterval = TimeSpan.FromSeconds(10);

    public static async ValueTask<RuntimeQuicClientConnection> OpenAsync<TOptions>(
        TOptions options,
        RuntimeInternetStack internetStack,
        IDnsResolver dnsResolver,
        CancellationToken cancellationToken)
        where TOptions : class, IRuntimeGrpcClientDialOptions
    {
        ArgumentNullException.ThrowIfNull(options);
        ArgumentNullException.ThrowIfNull(dnsResolver);

        if (!QuicConnection.IsSupported)
        {
            throw new PlatformNotSupportedException("The current platform does not support QUIC client connections.");
        }

        var remoteEndPoints = await ResolveRemoteEndPointsAsync(
                options,
                internetStack,
                dnsResolver,
                cancellationToken)
            .ConfigureAwait(false);

        Exception? lastError = null;
        foreach (var remoteEndPoint in remoteEndPoints)
        {
            var connectionOptions = CreateConnectionOptions(options, internetStack, remoteEndPoint);
            try
            {
                var connection = await QuicConnection
                    .ConnectAsync(connectionOptions, cancellationToken)
                    .ConfigureAwait(false);
                return new RuntimeQuicClientConnection(connection);
            }
            catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
            {
                throw;
            }
            catch (Exception ex)
            {
                lastError = ex;
            }
        }

        if (lastError is not null && IsKnownCredentialLoadFailure(lastError))
        {
            throw new IOException(
                "QUIC outbound could not initialize the local .NET/MsQuic client TLS credential configuration (QUIC_STATUS_CERT_NO_CERT). HTTP/3 is unavailable in the current environment.",
                lastError);
        }

        throw new IOException("QUIC outbound failed to establish the underlying connection.", lastError);
    }

    internal static async ValueTask<IReadOnlyList<IPEndPoint>> ResolveRemoteEndPointsAsync<TOptions>(
        TOptions options,
        RuntimeInternetStack internetStack,
        IDnsResolver dnsResolver,
        CancellationToken cancellationToken)
        where TOptions : class, IRuntimeGrpcClientDialOptions
    {
        ArgumentNullException.ThrowIfNull(options);
        ArgumentNullException.ThrowIfNull(dnsResolver);

        ValidateConfiguration(options, internetStack);

        var dialContext = OutboundClientDialContext.Resolve(
            options.DialContext,
            options.SourceEndPoint,
            options.LocalEndPoint);

        using var connectCts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        connectCts.CancelAfter(GetConnectTimeout(options));
        return await OutboundSocketDialer
            .ResolveTcpEndPointsAsync(
                dialContext,
                options.ServerHost,
                options.ServerPort,
                AddressFamily.Unspecified,
                dnsResolver,
                connectCts.Token)
            .ConfigureAwait(false);
    }

    internal static QuicClientConnectionOptions CreateConnectionOptions<TOptions>(
        TOptions options,
        RuntimeInternetStack internetStack,
        IPEndPoint remoteEndPoint)
        where TOptions : class, IRuntimeGrpcClientDialOptions
    {
        ArgumentNullException.ThrowIfNull(options);
        ArgumentNullException.ThrowIfNull(remoteEndPoint);

        ValidateConfiguration(options, internetStack);
        ValidateQuicOptions(options.QuicOptions);

        var authenticationOptions = BuildClientAuthenticationOptions(internetStack, options);
        var connectionOptions = new QuicClientConnectionOptions
        {
            RemoteEndPoint = remoteEndPoint,
            LocalEndPoint = ResolveLocalEndPoint(options, remoteEndPoint.AddressFamily),
            ClientAuthenticationOptions = authenticationOptions,
            DefaultCloseErrorCode = DefaultCloseErrorCode,
            DefaultStreamErrorCode = DefaultStreamErrorCode,
            HandshakeTimeout = GetHandshakeTimeout(options)
        };

        ApplyQuicOptions(connectionOptions, options.QuicOptions);
        ApplyHttp3Defaults(connectionOptions, authenticationOptions, options.QuicOptions);
        return connectionOptions;
    }

    private static void ValidateConfiguration(
        IRuntimeGrpcClientDialOptions options,
        RuntimeInternetStack internetStack)
    {
        if (options.TransportStreamFactory is not null)
        {
            throw new NotSupportedException(
                "Runtime QUIC outbound does not support TransportStreamFactory. QUIC needs a native UDP transport path.");
        }

        if (!string.Equals(internetStack.SecurityType, RuntimeInternetSecurityTypes.Tls, StringComparison.Ordinal))
        {
            throw new NotSupportedException(
                $"Runtime QUIC outbound currently only supports TLS security, but '{internetStack.SecurityType}' was configured.");
        }

        if ((options.EnabledSslProtocols & SslProtocols.Tls13) == 0)
        {
            throw new NotSupportedException("Runtime QUIC outbound requires TLS 1.3 support.");
        }
    }

    private static void ValidateQuicOptions(RuntimeQuicOptions options)
    {
        ArgumentNullException.ThrowIfNull(options);

        ValidateBrutalBandwidthValue(options.BrutalUp, nameof(RuntimeQuicOptions.BrutalUp));
        ValidateBrutalBandwidthValue(options.BrutalDown, nameof(RuntimeQuicOptions.BrutalDown));

        var normalizedCongestion = NormalizeCongestion(options.Congestion);
        ValidateCongestionValue(normalizedCongestion, options.BrutalUp);

        ValidateUdpHopIntervalValue(
            options.UdpHop.IntervalMinSeconds,
            nameof(RuntimeUdpHopOptions.IntervalMinSeconds));
        ValidateUdpHopIntervalValue(
            options.UdpHop.IntervalMaxSeconds,
            nameof(RuntimeUdpHopOptions.IntervalMaxSeconds));

        if (normalizedCongestion.Length > 0)
        {
            throw new NotSupportedException(
                "Runtime QUIC outbound does not support custom congestion algorithms yet.");
        }

        if (options.BrutalUp > 0 || options.BrutalDown > 0)
        {
            throw new NotSupportedException(
                "Runtime QUIC outbound does not support brutal bandwidth shaping yet.");
        }

        if (options.DisablePathMtuDiscovery)
        {
            throw new NotSupportedException(
                "Runtime QUIC outbound does not support disabling path MTU discovery yet.");
        }

        if (HasUdpHopConfiguration(options.UdpHop))
        {
            throw new NotSupportedException(
                "Runtime QUIC outbound does not support UDP hop endpoints yet.");
        }

        ValidateReceiveWindowPair(
            options.InitStreamReceiveWindow,
            options.MaxStreamReceiveWindow,
            "stream");
        ValidateReceiveWindowPair(
            options.InitConnReceiveWindow,
            options.MaxConnReceiveWindow,
            "connection");
        ValidateReceiveWindowValue(options.InitStreamReceiveWindow, nameof(options.InitStreamReceiveWindow));
        ValidateReceiveWindowValue(options.MaxStreamReceiveWindow, nameof(options.MaxStreamReceiveWindow));
        ValidateReceiveWindowValue(options.InitConnReceiveWindow, nameof(options.InitConnReceiveWindow));
        ValidateReceiveWindowValue(options.MaxConnReceiveWindow, nameof(options.MaxConnReceiveWindow));
        ValidateInclusiveSecondsRange(
            options.MaxIdleTimeoutSeconds,
            MinMaxIdleTimeoutSeconds,
            MaxMaxIdleTimeoutSeconds,
            nameof(options.MaxIdleTimeoutSeconds));
        ValidateInclusiveSecondsRange(
            options.KeepAlivePeriodSeconds,
            MinKeepAlivePeriodSeconds,
            MaxKeepAlivePeriodSeconds,
            nameof(options.KeepAlivePeriodSeconds));

        if (options.MaxIncomingStreams < 0)
        {
            throw new ArgumentOutOfRangeException(
                nameof(options.MaxIncomingStreams),
                options.MaxIncomingStreams,
                "Runtime QUIC outbound only accepts MaxIncomingStreams values greater than or equal to zero.");
        }

        if (options.MaxIncomingStreams is > 0 and < MinMaxIncomingStreams)
        {
            throw new ArgumentOutOfRangeException(
                nameof(options.MaxIncomingStreams),
                options.MaxIncomingStreams,
                $"Runtime QUIC outbound requires MaxIncomingStreams to be at least {MinMaxIncomingStreams.ToString(System.Globalization.CultureInfo.InvariantCulture)} when explicitly configured.");
        }
    }

    private static string NormalizeCongestion(string value)
        => string.IsNullOrWhiteSpace(value) ? string.Empty : value.Trim().ToLowerInvariant();

    private static void ValidateCongestionValue(string value, long brutalUp)
    {
        switch (value)
        {
            case "":
            case "reno":
            case "bbr":
            case "brutal":
                return;
            case "force-brutal":
                if (brutalUp <= 0)
                {
                    throw new ArgumentException(
                        "Runtime QUIC outbound requires BrutalUp to be configured when congestion is 'force-brutal'.",
                        nameof(RuntimeQuicOptions.Congestion));
                }

                return;
            default:
                throw new ArgumentException(
                    "Runtime QUIC outbound only accepts congestion values '', 'reno', 'bbr', 'brutal', or 'force-brutal'.",
                    nameof(RuntimeQuicOptions.Congestion));
        }
    }

    private static void ValidateBrutalBandwidthValue(long value, string paramName)
    {
        if (value is > 0 and < MinBrutalBandwidthBytesPerSecond)
        {
            throw new ArgumentOutOfRangeException(
                paramName,
                value,
                $"Runtime QUIC outbound requires {paramName} to be at least {MinBrutalBandwidthBytesPerSecond.ToString(System.Globalization.CultureInfo.InvariantCulture)} bytes per second when explicitly configured.");
        }
    }

    private static void ValidateUdpHopIntervalValue(long value, string paramName)
    {
        if (value is > 0 and < MinUdpHopIntervalSeconds)
        {
            throw new ArgumentOutOfRangeException(
                paramName,
                value,
                $"Runtime QUIC outbound requires {paramName} to be at least {MinUdpHopIntervalSeconds.ToString(System.Globalization.CultureInfo.InvariantCulture)} seconds when explicitly configured.");
        }
    }

    private static bool HasUdpHopConfiguration(RuntimeUdpHopOptions options)
        => options.Ports.Count > 0 ||
           options.IntervalMinSeconds > 0 ||
           options.IntervalMaxSeconds > 0;

    private static void ValidateReceiveWindowPair(
        long initialValue,
        long maxValue,
        string scope)
    {
        if (initialValue < 0)
        {
            throw new ArgumentOutOfRangeException(
                nameof(initialValue),
                initialValue,
                $"Runtime QUIC outbound {scope} receive window values must be greater than or equal to zero.");
        }

        if (maxValue < 0)
        {
            throw new ArgumentOutOfRangeException(
                nameof(maxValue),
                maxValue,
                $"Runtime QUIC outbound {scope} receive window values must be greater than or equal to zero.");
        }
    }

    private static void ValidateReceiveWindowValue(long value, string paramName)
    {
        if (value is > 0 and < MinReceiveWindowSize)
        {
            throw new ArgumentOutOfRangeException(
                paramName,
                value,
                $"Runtime QUIC outbound requires receive window values to be at least {MinReceiveWindowSize.ToString(System.Globalization.CultureInfo.InvariantCulture)} bytes when explicitly configured.");
        }
    }

    private static void ValidateInclusiveSecondsRange(
        long value,
        long minInclusive,
        long maxInclusive,
        string paramName)
    {
        if (value != 0 && (value < minInclusive || value > maxInclusive))
        {
            throw new ArgumentOutOfRangeException(
                paramName,
                value,
                $"Runtime QUIC outbound requires {paramName} to be between {minInclusive.ToString(System.Globalization.CultureInfo.InvariantCulture)} and {maxInclusive.ToString(System.Globalization.CultureInfo.InvariantCulture)} seconds when explicitly configured.");
        }
    }

    private static void ApplyQuicOptions(
        QuicClientConnectionOptions connectionOptions,
        RuntimeQuicOptions options)
    {
        if (options.MaxIdleTimeoutSeconds > 0)
        {
            connectionOptions.IdleTimeout = TimeSpan.FromSeconds(options.MaxIdleTimeoutSeconds);
        }

        if (options.KeepAlivePeriodSeconds > 0)
        {
            connectionOptions.KeepAliveInterval = TimeSpan.FromSeconds(options.KeepAlivePeriodSeconds);
        }

        if (TryCreateReceiveWindowSizes(options, out var receiveWindowSizes))
        {
            connectionOptions.InitialReceiveWindowSizes = receiveWindowSizes;
        }

        if (TryGetMaxInboundStreams(options.MaxIncomingStreams, out var maxInboundStreams))
        {
            connectionOptions.MaxInboundBidirectionalStreams = maxInboundStreams;
            connectionOptions.MaxInboundUnidirectionalStreams = maxInboundStreams;
        }
    }

    private static void ApplyHttp3Defaults(
        QuicClientConnectionOptions connectionOptions,
        SslClientAuthenticationOptions authenticationOptions,
        RuntimeQuicOptions quicOptions)
    {
        if (authenticationOptions.ApplicationProtocols is not { Count: > 0 } protocols ||
            !protocols.Any(static protocol =>
                string.Equals(protocol.ToString(), "h3", StringComparison.OrdinalIgnoreCase)))
        {
            return;
        }

        if (connectionOptions.IdleTimeout <= TimeSpan.Zero &&
            quicOptions.MaxIdleTimeoutSeconds <= 0)
        {
            connectionOptions.IdleTimeout = DefaultHttp3IdleTimeout;
        }

        if (connectionOptions.KeepAliveInterval <= TimeSpan.Zero &&
            quicOptions.KeepAlivePeriodSeconds <= 0)
        {
            connectionOptions.KeepAliveInterval = DefaultHttp3KeepAliveInterval;
        }

        if (quicOptions.MaxIncomingStreams <= 0 &&
            connectionOptions.MaxInboundUnidirectionalStreams <= 0)
        {
            // HTTP/3 peers need room for their control and QPACK streams even when
            // the higher-level config did not explicitly request inbound streams.
            connectionOptions.MaxInboundUnidirectionalStreams = DefaultHttp3MaxInboundUnidirectionalStreams;
        }
    }

    private static bool TryCreateReceiveWindowSizes(
        RuntimeQuicOptions options,
        out QuicReceiveWindowSizes receiveWindowSizes)
    {
        receiveWindowSizes = default!;

        var streamWindow = GetMappedReceiveWindowValue(
            options.InitStreamReceiveWindow,
            options.MaxStreamReceiveWindow);
        var connectionWindow = GetMappedReceiveWindowValue(
            options.InitConnReceiveWindow,
            options.MaxConnReceiveWindow);

        if (streamWindow is null && connectionWindow is null)
        {
            return false;
        }

        receiveWindowSizes = new QuicReceiveWindowSizes();
        if (connectionWindow is int mappedConnectionWindow)
        {
            receiveWindowSizes.Connection = mappedConnectionWindow;
        }

        if (streamWindow is int mappedStreamWindow)
        {
            receiveWindowSizes.LocallyInitiatedBidirectionalStream = mappedStreamWindow;
            receiveWindowSizes.RemotelyInitiatedBidirectionalStream = mappedStreamWindow;
            receiveWindowSizes.UnidirectionalStream = mappedStreamWindow;
        }

        return true;
    }

    private static int? GetMappedReceiveWindowValue(long initialValue, long maxValue)
    {
        var effectiveValue = initialValue > 0 && maxValue > 0
            ? Math.Min(initialValue, maxValue)
            : initialValue > 0 ? initialValue : maxValue > 0 ? maxValue : 0;
        if (effectiveValue <= 0)
        {
            return null;
        }

        if (effectiveValue > int.MaxValue)
        {
            throw new ArgumentOutOfRangeException(
                nameof(effectiveValue),
                effectiveValue,
                "Runtime QUIC outbound receive window values must fit within Int32.");
        }

        return checked((int)effectiveValue);
    }

    private static bool TryGetMaxInboundStreams(long configuredValue, out int maxInboundStreams)
    {
        maxInboundStreams = 0;
        if (configuredValue <= 0)
        {
            return false;
        }

        if (configuredValue > int.MaxValue)
        {
            throw new ArgumentOutOfRangeException(
                nameof(configuredValue),
                configuredValue,
                "Runtime QUIC outbound MaxIncomingStreams must fit within Int32.");
        }

        maxInboundStreams = checked((int)configuredValue);
        return true;
    }

    private static SslClientAuthenticationOptions BuildClientAuthenticationOptions(
        RuntimeInternetStack internetStack,
        IRuntimeInternetOptions options)
    {
        var clientAuthenticationOptions = RuntimeInternetProfile.CreateClientAuthenticationOptions(internetStack, options);
        var applicationProtocols = clientAuthenticationOptions.ApplicationProtocols;
        if (applicationProtocols is null || applicationProtocols.Count == 0)
        {
            throw new NotSupportedException("Runtime QUIC outbound requires at least one ALPN protocol.");
        }

        if (applicationProtocols.Any(static protocol =>
                string.Equals(protocol.ToString(), "http/1.1", StringComparison.OrdinalIgnoreCase)))
        {
            throw new NotSupportedException("Runtime QUIC outbound cannot negotiate the 'http/1.1' ALPN.");
        }

        clientAuthenticationOptions.EnabledSslProtocols = SslProtocols.Tls13;
        // MsQuic treats an empty collection differently from null here and may try to
        // load a client certificate credential even when no client cert is configured.
        clientAuthenticationOptions.ClientCertificateContext = null;
        clientAuthenticationOptions.ClientCertificates = null;
        clientAuthenticationOptions.LocalCertificateSelectionCallback = null;
        clientAuthenticationOptions.RemoteCertificateValidationCallback =
            (_, certificate, chain, errors) => RuntimeServerCertificateValidation.Validate(
                options.SkipCertificateValidation,
                options.CertificateValidationCallback,
                options,
                certificate,
                chain,
                errors);
        return clientAuthenticationOptions;
    }

    private static IPEndPoint? ResolveLocalEndPoint(
        IRuntimeGrpcClientDialOptions options,
        AddressFamily addressFamily)
    {
        var dialContext = OutboundClientDialContext.Resolve(
            options.DialContext,
            options.SourceEndPoint,
            options.LocalEndPoint);
        return OutboundSocketDialer.ResolveBindEndPoint(
            dialContext,
            options.Via,
            options.ViaCidr,
            addressFamily);
    }

    private static TimeSpan GetConnectTimeout(IRuntimeGrpcClientDialOptions options)
        => TimeSpan.FromSeconds(Math.Max(1, options.ConnectTimeoutSeconds));

    private static TimeSpan GetHandshakeTimeout(IRuntimeGrpcClientDialOptions options)
        => TimeSpan.FromSeconds(Math.Max(1, options.HandshakeTimeoutSeconds));

    private static bool IsKnownCredentialLoadFailure(Exception exception)
    {
        for (var current = exception; current is not null; current = current.InnerException)
        {
            if (current.Message.Contains("QUIC_STATUS_CERT_NO_CERT", StringComparison.OrdinalIgnoreCase))
            {
                return true;
            }
        }

        return false;
    }
}

[SupportedOSPlatform("windows")]
[SupportedOSPlatform("linux")]
[SupportedOSPlatform("macos")]
internal sealed class RuntimeQuicClientConnection : IAsyncDisposable
{
    public RuntimeQuicClientConnection(QuicConnection connection)
    {
        Connection = connection ?? throw new ArgumentNullException(nameof(connection));
        SecurityState = CreateSecurityState(connection);
    }

    public QuicConnection Connection { get; }

    public RuntimeInternetSecurityState SecurityState { get; }

    public string NegotiatedApplicationProtocol => SecurityState.NegotiatedApplicationProtocol;

    public SslProtocols NegotiatedSslProtocol => SecurityState.NegotiatedSslProtocol;

    public X509Certificate2? RemoteCertificate
        => SecurityState.RemoteCertificate is null
            ? null
            : new X509Certificate2(SecurityState.RemoteCertificate);

    public ValueTask<QuicStream> OpenOutboundBidirectionalStreamAsync(CancellationToken cancellationToken)
        => Connection.OpenOutboundStreamAsync(QuicStreamType.Bidirectional, cancellationToken);

    public ValueTask<QuicStream> OpenOutboundUnidirectionalStreamAsync(CancellationToken cancellationToken)
        => Connection.OpenOutboundStreamAsync(QuicStreamType.Unidirectional, cancellationToken);

    public ValueTask<QuicStream> AcceptInboundStreamAsync(CancellationToken cancellationToken)
        => Connection.AcceptInboundStreamAsync(cancellationToken);

    public async ValueTask DisposeAsync()
    {
        await Connection.DisposeAsync().ConfigureAwait(false);
        SecurityState.RemoteCertificate?.Dispose();
    }

    private static RuntimeInternetSecurityState CreateSecurityState(QuicConnection connection)
    {
        X509Certificate2? remoteCertificate = null;
        if (connection.RemoteCertificate is not null)
        {
            remoteCertificate = connection.RemoteCertificate as X509Certificate2
                ?? new X509Certificate2(connection.RemoteCertificate);
        }

        return RuntimeInternetSecurityState.Create(
            RuntimeInternetSecurityTypes.Tls,
            connection.SslProtocol,
            connection.NegotiatedApplicationProtocol.ToString(),
            remoteCertificate);
    }
}

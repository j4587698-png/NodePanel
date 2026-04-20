using System.Globalization;
using System.Linq;
using System.Net.Quic;
using System.Net.Security;
using System.Runtime.Versioning;
using System.Security.Authentication;

namespace NodePanel.Core.Runtime;

[SupportedOSPlatform("windows")]
[SupportedOSPlatform("linux")]
[SupportedOSPlatform("macos")]
internal static class RuntimeQuicServerConnectionOptionsFactory
{
    private const long DefaultCloseErrorCode = 0;
    private const long DefaultStreamErrorCode = 0;
    private const int DefaultMaxInboundBidirectionalStreams = 128;
    private const int DefaultHttp3MaxInboundUnidirectionalStreams = 16;
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

    public static QuicServerConnectionOptions Create(
        IReadOnlyList<string> applicationProtocols,
        RuntimeTlsOptions tlsOptions,
        RuntimeQuicOptions? quicOptions)
    {
        ArgumentNullException.ThrowIfNull(applicationProtocols);
        ArgumentNullException.ThrowIfNull(tlsOptions);

        var normalizedQuicOptions = RuntimeQuicOptionsNormalizer.Normalize(quicOptions);
        ValidateQuicOptions(normalizedQuicOptions);

        var authenticationOptions = TlsInboundConnectionAcceptor.BuildAuthenticationOptions(applicationProtocols, tlsOptions);
        authenticationOptions.EnabledSslProtocols = SslProtocols.Tls13;

        var serverOptions = new QuicServerConnectionOptions
        {
            DefaultCloseErrorCode = DefaultCloseErrorCode,
            DefaultStreamErrorCode = DefaultStreamErrorCode,
            HandshakeTimeout = TimeSpan.FromSeconds(10),
            MaxInboundBidirectionalStreams = DefaultMaxInboundBidirectionalStreams,
            MaxInboundUnidirectionalStreams = DefaultHttp3MaxInboundUnidirectionalStreams,
            ServerAuthenticationOptions = authenticationOptions
        };

        ApplyQuicOptions(serverOptions, normalizedQuicOptions);
        ApplyHttp3Defaults(serverOptions, authenticationOptions.ApplicationProtocols, normalizedQuicOptions);
        return serverOptions;
    }

    internal static void ValidateQuicOptions(RuntimeQuicOptions options)
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
                "Runtime QUIC inbound server does not support custom congestion algorithms yet.");
        }

        if (options.BrutalUp > 0 || options.BrutalDown > 0)
        {
            throw new NotSupportedException(
                "Runtime QUIC inbound server does not support brutal bandwidth shaping yet.");
        }

        if (options.DisablePathMtuDiscovery)
        {
            throw new NotSupportedException(
                "Runtime QUIC inbound server does not support disabling path MTU discovery yet.");
        }

        if (HasUdpHopConfiguration(options.UdpHop))
        {
            throw new NotSupportedException(
                "Runtime QUIC inbound server does not support UDP hop endpoints yet.");
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
                "Runtime QUIC inbound server only accepts MaxIncomingStreams values greater than or equal to zero.");
        }

        if (options.MaxIncomingStreams is > 0 and < MinMaxIncomingStreams)
        {
            throw new ArgumentOutOfRangeException(
                nameof(options.MaxIncomingStreams),
                options.MaxIncomingStreams,
                $"Runtime QUIC inbound server requires MaxIncomingStreams to be at least {MinMaxIncomingStreams.ToString(CultureInfo.InvariantCulture)} when explicitly configured.");
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
                        "Runtime QUIC inbound server requires BrutalUp to be configured when congestion is 'force-brutal'.",
                        nameof(RuntimeQuicOptions.Congestion));
                }

                return;
            default:
                throw new ArgumentException(
                    "Runtime QUIC inbound server only accepts congestion values '', 'reno', 'bbr', 'brutal', or 'force-brutal'.",
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
                $"Runtime QUIC inbound server requires {paramName} to be at least {MinBrutalBandwidthBytesPerSecond.ToString(CultureInfo.InvariantCulture)} bytes per second when explicitly configured.");
        }
    }

    private static void ValidateUdpHopIntervalValue(long value, string paramName)
    {
        if (value is > 0 and < MinUdpHopIntervalSeconds)
        {
            throw new ArgumentOutOfRangeException(
                paramName,
                value,
                $"Runtime QUIC inbound server requires {paramName} to be at least {MinUdpHopIntervalSeconds.ToString(CultureInfo.InvariantCulture)} seconds when explicitly configured.");
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
                $"Runtime QUIC inbound server {scope} receive window values must be greater than or equal to zero.");
        }

        if (maxValue < 0)
        {
            throw new ArgumentOutOfRangeException(
                nameof(maxValue),
                maxValue,
                $"Runtime QUIC inbound server {scope} receive window values must be greater than or equal to zero.");
        }
    }

    private static void ValidateReceiveWindowValue(long value, string paramName)
    {
        if (value is > 0 and < MinReceiveWindowSize)
        {
            throw new ArgumentOutOfRangeException(
                paramName,
                value,
                $"Runtime QUIC inbound server requires receive window values to be at least {MinReceiveWindowSize.ToString(CultureInfo.InvariantCulture)} bytes when explicitly configured.");
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
                $"Runtime QUIC inbound server requires {paramName} to be between {minInclusive.ToString(CultureInfo.InvariantCulture)} and {maxInclusive.ToString(CultureInfo.InvariantCulture)} seconds when explicitly configured.");
        }
    }

    private static void ApplyQuicOptions(
        QuicServerConnectionOptions connectionOptions,
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

        if (TryGetMaxInboundBidirectionalStreams(options.MaxIncomingStreams, out var maxInboundStreams))
        {
            connectionOptions.MaxInboundBidirectionalStreams = maxInboundStreams;
        }
    }

    private static void ApplyHttp3Defaults(
        QuicServerConnectionOptions connectionOptions,
        IList<SslApplicationProtocol>? applicationProtocols,
        RuntimeQuicOptions quicOptions)
    {
        if (applicationProtocols is not { Count: > 0 } protocols ||
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
                "Runtime QUIC inbound server receive window values must fit within Int32.");
        }

        return checked((int)effectiveValue);
    }

    private static bool TryGetMaxInboundBidirectionalStreams(long configuredValue, out int maxInboundStreams)
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
                "Runtime QUIC inbound server MaxIncomingStreams must fit within Int32.");
        }

        maxInboundStreams = checked((int)configuredValue);
        return true;
    }
}

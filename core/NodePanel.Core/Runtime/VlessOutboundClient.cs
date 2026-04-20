using System.Security.Authentication;
using NodePanel.Core.Protocol;

namespace NodePanel.Core.Runtime;

public sealed class VlessOutboundClient
{
    private readonly IDnsResolver _dnsResolver;
    private readonly RuntimeInternetProfile _internetProfile;
    private readonly VlessTransportEncryption _transportEncryption = new();
    private readonly VlessHandshakeWriter _vlessHandshakeWriter;

    public VlessOutboundClient()
        : this(new VlessHandshakeWriter(), dnsResolver: null)
    {
    }

    public VlessOutboundClient(
        VlessHandshakeWriter vlessHandshakeWriter,
        IDnsResolver? dnsResolver = null)
        : this(vlessHandshakeWriter, dnsResolver, internetProfile: null)
    {
    }

    internal VlessOutboundClient(
        VlessHandshakeWriter vlessHandshakeWriter,
        IDnsResolver? dnsResolver,
        RuntimeInternetProfile? internetProfile)
    {
        _vlessHandshakeWriter = vlessHandshakeWriter;
        _dnsResolver = dnsResolver ?? SystemDnsResolver.Instance;
        _internetProfile = internetProfile ?? RuntimeInternetProfile.Default;
    }

    public async Task<VlessClientConnection> ConnectAsync(
        VlessClientOptions options,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(options);
        ValidateOptions(options);
        options = NormalizeRealityOptions(options);

        var normalizedFlow = VlessFlowTypes.Normalize(options.Flow);
        var handshakePayload = _vlessHandshakeWriter.Build(
            options.UserUuid,
            options.Command,
            options.TargetHost,
            options.TargetPort,
            options.Version,
            CreateRequestAddons(normalizedFlow));
        var internetStack = _internetProfile.Resolve(ResolveInternetStack(options));
        var transportInitializationData = ResolveTransportInitializationData(internetStack, options, handshakePayload);

        var transportConnection = await OpenTransportAsync(
                options,
                internetStack,
                transportInitializationData,
                cancellationToken)
            .ConfigureAwait(false);
        try
        {
            return await CompleteConnectCoreAsync(
                    transportConnection,
                    options,
                    internetStack,
                    normalizedFlow,
                    handshakePayload,
                    transportInitializationData,
                    cancellationToken)
                .ConfigureAwait(false);
        }
        catch
        {
            await transportConnection.DisposeAsync().ConfigureAwait(false);
            throw;
        }
    }

    internal async Task<VlessClientConnection> OpenTransportConnectionAsync(
        VlessClientOptions options,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(options);
        ValidateTransportOptions(options);
        options = NormalizeRealityOptions(options);

        var internetStack = _internetProfile.Resolve(ResolveInternetStack(options));
        return await OpenTransportAsync(
                options,
                internetStack,
                transportInitializationData: null,
                cancellationToken)
            .ConfigureAwait(false);
    }

    internal async Task<VlessClientConnection> CompleteConnectAsync(
        VlessClientConnection transportConnection,
        VlessClientOptions options,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(transportConnection);
        ArgumentNullException.ThrowIfNull(options);
        ValidateOptions(options);
        options = NormalizeRealityOptions(options);

        var normalizedFlow = VlessFlowTypes.Normalize(options.Flow);
        var handshakePayload = _vlessHandshakeWriter.Build(
            options.UserUuid,
            options.Command,
            options.TargetHost,
            options.TargetPort,
            options.Version,
            CreateRequestAddons(normalizedFlow));
        var internetStack = _internetProfile.Resolve(ResolveInternetStack(options));
        var transportInitializationData = ResolveTransportInitializationData(internetStack, options, handshakePayload);
        if (transportInitializationData is not null)
        {
            throw new InvalidOperationException("VLESS preconnected transport does not support transport-level early-data handshakes.");
        }

        return await CompleteConnectCoreAsync(
                transportConnection,
                options,
                internetStack,
                normalizedFlow,
                handshakePayload,
                transportInitializationData,
                cancellationToken)
            .ConfigureAwait(false);
    }

    private async Task<VlessClientConnection> OpenTransportAsync(
        VlessClientOptions options,
        RuntimeInternetStack internetStack,
        byte[]? transportInitializationData,
        CancellationToken cancellationToken)
    {
        var connectionContext = await RuntimeGrpcClientConnector
            .OpenAsync(
                options,
                internetStack,
                _internetProfile,
                _dnsResolver,
                transportInitializationData,
                cancellationToken)
            .ConfigureAwait(false);

        return new VlessClientConnection(connectionContext);
    }

    private static byte[]? ResolveTransportInitializationData(
        RuntimeInternetStack internetStack,
        VlessClientOptions options,
        byte[] handshakePayload)
    {
        if (!string.Equals(internetStack.TransportProtocol, RuntimeInternetTransportProtocols.HttpUpgrade, StringComparison.Ordinal) ||
            options.WebSocketEarlyDataBytes <= 0)
        {
            return null;
        }

        return handshakePayload.Length <= options.WebSocketEarlyDataBytes ? handshakePayload : null;
    }

    private async Task<VlessClientConnection> CompleteConnectCoreAsync(
        VlessClientConnection transportConnection,
        VlessClientOptions options,
        RuntimeInternetStack internetStack,
        string normalizedFlow,
        byte[] handshakePayload,
        byte[]? transportInitializationData,
        CancellationToken cancellationToken)
    {
        using var handshakeCts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        handshakeCts.CancelAfter(TimeSpan.FromSeconds(options.HandshakeTimeoutSeconds));

        if (VlessTransportEncryption.IsEnabled(options.Encryption))
        {
            await _transportEncryption.ApplyAsync(transportConnection, options, handshakeCts.Token).ConfigureAwait(false);
        }

        if (transportInitializationData is null)
        {
            await transportConnection.Stream.WriteAsync(handshakePayload.AsMemory(0, handshakePayload.Length), handshakeCts.Token).ConfigureAwait(false);
            await transportConnection.Stream.FlushAsync(handshakeCts.Token).ConfigureAwait(false);
        }

        transportConnection.UseApplicationStream(
            new VlessLazyResponseHeaderStream(
                transportConnection.Stream,
                options.Version,
                TimeSpan.FromSeconds(options.HandshakeTimeoutSeconds)));
        ApplyVisionFlow(transportConnection, options, internetStack, normalizedFlow);

        return transportConnection;
    }

    private static RuntimeInternetStack ResolveInternetStack(VlessClientOptions options)
    {
        var hasExplicitTransport = !string.IsNullOrWhiteSpace(options.TransportProtocol);
        var hasExplicitSecurity = !string.IsNullOrWhiteSpace(options.SecurityType);
        if (hasExplicitTransport || hasExplicitSecurity)
        {
            var fallback = ResolveLegacyInternetStack(options.Transport);
            return RuntimeInternetStack.Create(
                hasExplicitTransport ? options.TransportProtocol : fallback.TransportProtocol,
                hasExplicitSecurity ? options.SecurityType : RuntimeInternetSecurityTypes.None);
        }

        return ResolveLegacyInternetStack(options.Transport);
    }

    private static void ValidateOptions(VlessClientOptions options)
    {
        ValidateTransportOptions(options);

        if (options.Command is not (VlessCommand.Mux or VlessCommand.Rvs))
        {
            ArgumentException.ThrowIfNullOrWhiteSpace(options.TargetHost);
            if (options.TargetPort is <= 0 or > 65535)
            {
                throw new ArgumentOutOfRangeException(nameof(options), options.TargetPort, "Target port must be between 1 and 65535.");
            }
        }

        if (options.ConnectTimeoutSeconds <= 0)
        {
            throw new ArgumentOutOfRangeException(nameof(options), options.ConnectTimeoutSeconds, "Connect timeout must be greater than zero.");
        }

        if (options.HandshakeTimeoutSeconds <= 0)
        {
            throw new ArgumentOutOfRangeException(nameof(options), options.HandshakeTimeoutSeconds, "Handshake timeout must be greater than zero.");
        }

        if (options.WebSocketEarlyDataBytes < 0)
        {
            throw new ArgumentOutOfRangeException(nameof(options), options.WebSocketEarlyDataBytes, "WebSocket early data bytes must be zero or greater.");
        }

        if (options.WebSocketHeartbeatPeriodSeconds < 0)
        {
            throw new ArgumentOutOfRangeException(nameof(options), options.WebSocketHeartbeatPeriodSeconds, "WebSocket heartbeat period must be zero or greater.");
        }

        if (!VlessTransportEncryption.TryValidateConfiguration(options.Encryption, options.Padding, out var encryptionError))
        {
            throw new ArgumentException(encryptionError, nameof(options));
        }

        if (VlessTransportEncryption.IsEnabled(options.Encryption) &&
            options.WebSocketEarlyDataBytes > 0)
        {
            throw new ArgumentException("VLESS transport encryption does not support websocket early-data.", nameof(options));
        }
    }

    private static void ValidateTransportOptions(VlessClientOptions options)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(options.ServerHost);

        if (!ProtocolUuid.TryNormalize(options.UserUuid, out _))
        {
            throw new ArgumentException("VLESS user UUID is invalid.", nameof(options));
        }

        if (!VlessFlowTypes.IsSupported(options.Flow))
        {
            throw new ArgumentException($"Unsupported VLESS flow: {options.Flow?.Trim() ?? string.Empty}.", nameof(options));
        }

        if (options.ServerPort is <= 0 or > 65535)
        {
            throw new ArgumentOutOfRangeException(nameof(options), options.ServerPort, "Server port must be between 1 and 65535.");
        }

        if (options.ConnectTimeoutSeconds <= 0)
        {
            throw new ArgumentOutOfRangeException(nameof(options), options.ConnectTimeoutSeconds, "Connect timeout must be greater than zero.");
        }

        if (options.HandshakeTimeoutSeconds <= 0)
        {
            throw new ArgumentOutOfRangeException(nameof(options), options.HandshakeTimeoutSeconds, "Handshake timeout must be greater than zero.");
        }

        if (options.WebSocketEarlyDataBytes < 0)
        {
            throw new ArgumentOutOfRangeException(nameof(options), options.WebSocketEarlyDataBytes, "WebSocket early data bytes must be zero or greater.");
        }

        if (options.WebSocketHeartbeatPeriodSeconds < 0)
        {
            throw new ArgumentOutOfRangeException(nameof(options), options.WebSocketHeartbeatPeriodSeconds, "WebSocket heartbeat period must be zero or greater.");
        }
    }

    private static VlessHeaderAddons? CreateRequestAddons(string normalizedFlow)
        => VlessFlowTypes.IsVision(normalizedFlow)
            ? new VlessHeaderAddons
            {
                Flow = VlessFlowTypes.ToHeaderFlow(normalizedFlow)
            }
            : null;

    private static void ApplyVisionFlow(
        VlessClientConnection connection,
        VlessClientOptions options,
        RuntimeInternetStack internetStack,
        string normalizedFlow)
    {
        if (!VlessFlowTypes.IsVision(normalizedFlow))
        {
            return;
        }

        if (!string.Equals(internetStack.TransportProtocol, RuntimeInternetTransportProtocols.Tcp, StringComparison.Ordinal) ||
            !RuntimeInternetSecurityTypes.UsesTlsLikeSemantics(internetStack.SecurityType))
        {
            throw new NotSupportedException($"VLESS flow '{normalizedFlow}' currently requires direct TLS-like transport.");
        }

        if (connection.NegotiatedSslProtocol != SslProtocols.Tls13)
        {
            throw new InvalidOperationException($"VLESS flow '{normalizedFlow}' requires an outer TLS 1.3 transport.");
        }

        Span<byte> userUuidBytes = stackalloc byte[VlessVisionPaddingCodec.UserUuidLength];
        if (!ProtocolUuid.TryWriteBytes(options.UserUuid, userUuidBytes))
        {
            throw new InvalidDataException("VLESS user UUID could not be converted into vision runtime state.");
        }

        connection.UseApplicationStream(
            new VlessVisionDuplexStream(
                connection.Stream,
                new VlessVisionTrafficState(userUuidBytes),
                readIsUplink: false,
                writeIsUplink: true,
                paddingSeed: VlessVisionPaddingSeed.FromTestSeed(options.TestSeed)));
    }

    private static VlessClientOptions NormalizeRealityOptions(VlessClientOptions options)
    {
        var internetStack = ResolveInternetStack(options);
        if (!string.Equals(internetStack.SecurityType, RuntimeInternetSecurityTypes.Reality, StringComparison.Ordinal))
        {
            return options with
            {
                RealityOptions = RuntimeRealityOptions.Normalize(options.RealityOptions)
            };
        }

        if (!options.RealityOptions.TryValidateForReality(out var normalizedRealityOptions, out var error))
        {
            throw new ArgumentException(error, nameof(options));
        }

        return options with
        {
            RealityOptions = normalizedRealityOptions
        };
    }

    private static RuntimeInternetStack ResolveLegacyInternetStack(VlessClientTransportType transport)
        => transport switch
        {
            VlessClientTransportType.Tcp => RuntimeInternetStack.Create(
                RuntimeInternetTransportProtocols.Tcp,
                RuntimeInternetSecurityTypes.None),
            VlessClientTransportType.Tls => RuntimeInternetStack.Create(
                RuntimeInternetTransportProtocols.Tcp,
                RuntimeInternetSecurityTypes.Tls),
            VlessClientTransportType.Ws => RuntimeInternetStack.Create(
                RuntimeInternetTransportProtocols.Ws,
                RuntimeInternetSecurityTypes.None),
            VlessClientTransportType.Wss => RuntimeInternetStack.Create(
                RuntimeInternetTransportProtocols.Ws,
                RuntimeInternetSecurityTypes.Tls),
            VlessClientTransportType.HttpUpgrade => RuntimeInternetStack.Create(
                RuntimeInternetTransportProtocols.HttpUpgrade,
                RuntimeInternetSecurityTypes.None),
            VlessClientTransportType.HttpUpgradeTls => RuntimeInternetStack.Create(
                RuntimeInternetTransportProtocols.HttpUpgrade,
                RuntimeInternetSecurityTypes.Tls),
            VlessClientTransportType.Grpc => RuntimeInternetStack.Create(
                RuntimeInternetTransportProtocols.Grpc,
                RuntimeInternetSecurityTypes.Tls),
            VlessClientTransportType.SplitHttp => RuntimeInternetStack.Create(
                RuntimeInternetTransportProtocols.SplitHttp,
                RuntimeInternetSecurityTypes.None),
            _ => throw new NotSupportedException($"Unsupported VLESS client transport: {transport}.")
        };
}

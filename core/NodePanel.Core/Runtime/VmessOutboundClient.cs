using System.Security.Cryptography;
using NodePanel.Core.Protocol;

namespace NodePanel.Core.Runtime;

public sealed class VmessOutboundClient
{
    private readonly IDnsResolver _dnsResolver;
    private readonly RuntimeInternetProfile _internetProfile;
    private readonly VmessHandshakeWriter _vmessHandshakeWriter;

    public VmessOutboundClient()
        : this(new VmessHandshakeWriter(), dnsResolver: null)
    {
    }

    public VmessOutboundClient(
        VmessHandshakeWriter vmessHandshakeWriter,
        IDnsResolver? dnsResolver = null)
        : this(vmessHandshakeWriter, dnsResolver, internetProfile: null)
    {
    }

    internal VmessOutboundClient(
        VmessHandshakeWriter vmessHandshakeWriter,
        IDnsResolver? dnsResolver,
        RuntimeInternetProfile? internetProfile)
    {
        _vmessHandshakeWriter = vmessHandshakeWriter;
        _dnsResolver = dnsResolver ?? SystemDnsResolver.Instance;
        _internetProfile = internetProfile ?? RuntimeInternetProfile.Default;
    }

    public async Task<VmessClientConnection> ConnectAsync(
        VmessClientOptions options,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(options);
        ValidateOptions(options);
        options = NormalizeRealityOptions(options);

        var request = CreateRequest(options);
        var handshakePayload = _vmessHandshakeWriter.BuildRequestHeader(request);
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
            using var handshakeCts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
            handshakeCts.CancelAfter(TimeSpan.FromSeconds(options.HandshakeTimeoutSeconds));

            if (transportInitializationData is null)
            {
                await transportConnection.ApplicationStream
                    .WriteAsync(handshakePayload.AsMemory(0, handshakePayload.Length), handshakeCts.Token)
                    .ConfigureAwait(false);
                await transportConnection.ApplicationStream.FlushAsync(handshakeCts.Token).ConfigureAwait(false);
            }

            var responseHeaderStream = new VmessLazyResponseHeaderStream(
                transportConnection.ApplicationStream,
                request,
                TimeSpan.FromSeconds(options.HandshakeTimeoutSeconds));

            return new VmessClientConnection(
                transportConnection,
                options.NoTerminationSignal,
                new VmessClientDataStream(responseHeaderStream, request));
        }
        catch
        {
            if (!ReferenceEquals(transportConnection.ApplicationStream, transportConnection.TransportStream))
            {
                await transportConnection.ApplicationStream.DisposeAsync().ConfigureAwait(false);
            }

            await transportConnection.TransportStream.DisposeAsync().ConfigureAwait(false);
            throw;
        }
    }

    private async Task<RuntimeInternetConnectionContext> OpenTransportAsync(
        VmessClientOptions options,
        RuntimeInternetStack internetStack,
        byte[]? transportInitializationData,
        CancellationToken cancellationToken)
    {
        return await RuntimeGrpcClientConnector
            .OpenAsync(
                options,
                internetStack,
                _internetProfile,
                _dnsResolver,
                transportInitializationData,
                cancellationToken)
            .ConfigureAwait(false);
    }

    private static byte[]? ResolveTransportInitializationData(
        RuntimeInternetStack internetStack,
        VmessClientOptions options,
        byte[] handshakePayload)
    {
        if (!string.Equals(internetStack.TransportProtocol, RuntimeInternetTransportProtocols.HttpUpgrade, StringComparison.Ordinal) ||
            options.WebSocketEarlyDataBytes <= 0)
        {
            return null;
        }

        return handshakePayload.Length <= options.WebSocketEarlyDataBytes ? handshakePayload : null;
    }

    private static RuntimeInternetStack ResolveInternetStack(VmessClientOptions options)
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

    private static VmessRequest CreateRequest(VmessClientOptions options)
    {
        if (!ProtocolUuid.TryNormalize(options.UserUuid, out var normalizedUuid) ||
            !VmessAccountCodec.TryCreateCommandKey(normalizedUuid, out var commandKey))
        {
            throw new ArgumentException("VMess user UUID is invalid.", nameof(options));
        }

        var (security, option) = ResolveRequestSecurityProfile(options.RequestSecurity, options.AuthenticatedLength);
        var sessionBytes = RandomNumberGenerator.GetBytes(33);

        return new VmessRequest
        {
            Version = 1,
            User = new VmessUser
            {
                UserId = normalizedUuid,
                Uuid = normalizedUuid,
                CmdKey = commandKey,
                BytesPerSecond = 0
            },
            RequestBodyKey = sessionBytes.AsSpan(0, 16).ToArray(),
            RequestBodyIv = sessionBytes.AsSpan(16, 16).ToArray(),
            ResponseHeader = sessionBytes[32],
            Option = option,
            Security = security,
            Command = options.Command,
            TargetHost = options.Command == VmessCommand.Mux && string.IsNullOrWhiteSpace(options.TargetHost)
                ? TrojanMuxProtocol.Host
                : options.TargetHost,
            TargetPort = options.Command == VmessCommand.Mux && options.TargetPort <= 0
                ? TrojanMuxProtocol.Port
                : options.TargetPort
        };
    }

    private static (VmessSecurityType Security, byte Option) ResolveRequestSecurityProfile(
        string security,
        bool authenticatedLength)
    {
        var normalized = VmessOutboundSecurityTypes.Normalize(security);
        return normalized switch
        {
            VmessOutboundSecurityTypes.Auto or VmessOutboundSecurityTypes.Aes128Gcm
                => (VmessSecurityType.Aes128Gcm, BuildDefaultOption(usePadding: true, authenticatedLength)),
            VmessOutboundSecurityTypes.ChaCha20Poly1305
                => (VmessSecurityType.ChaCha20Poly1305, BuildDefaultOption(usePadding: true, authenticatedLength)),
            VmessOutboundSecurityTypes.None
                => (VmessSecurityType.None, BuildDefaultOption(usePadding: false, authenticatedLength: false)),
            VmessOutboundSecurityTypes.Zero
                => (VmessSecurityType.None, 0),
            _ => throw new NotSupportedException($"Unsupported VMess outbound security: {security}.")
        };

        static byte BuildDefaultOption(bool usePadding, bool authenticatedLength)
        {
            var option = (byte)(VmessRequestOptions.ChunkStream | VmessRequestOptions.ChunkMasking);
            if (usePadding)
            {
                option |= VmessRequestOptions.GlobalPadding;
            }

            if (authenticatedLength)
            {
                option |= VmessRequestOptions.AuthenticatedLength;
            }

            return option;
        }
    }

    private static void ValidateOptions(VmessClientOptions options)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(options.ServerHost);

        if (options.ServerPort is <= 0 or > 65535)
        {
            throw new ArgumentOutOfRangeException(nameof(options), options.ServerPort, "Server port must be between 1 and 65535.");
        }

        if (options.Command is not VmessCommand.Mux)
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

        _ = ResolveRequestSecurityProfile(options.RequestSecurity, options.AuthenticatedLength);
    }

    private static VmessClientOptions NormalizeRealityOptions(VmessClientOptions options)
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

    private static RuntimeInternetStack ResolveLegacyInternetStack(VmessClientTransportType transport)
        => transport switch
        {
            VmessClientTransportType.Tcp => RuntimeInternetStack.Create(
                RuntimeInternetTransportProtocols.Tcp,
                RuntimeInternetSecurityTypes.None),
            VmessClientTransportType.Tls => RuntimeInternetStack.Create(
                RuntimeInternetTransportProtocols.Tcp,
                RuntimeInternetSecurityTypes.Tls),
            VmessClientTransportType.Ws => RuntimeInternetStack.Create(
                RuntimeInternetTransportProtocols.Ws,
                RuntimeInternetSecurityTypes.None),
            VmessClientTransportType.Wss => RuntimeInternetStack.Create(
                RuntimeInternetTransportProtocols.Ws,
                RuntimeInternetSecurityTypes.Tls),
            VmessClientTransportType.HttpUpgrade => RuntimeInternetStack.Create(
                RuntimeInternetTransportProtocols.HttpUpgrade,
                RuntimeInternetSecurityTypes.None),
            VmessClientTransportType.HttpUpgradeTls => RuntimeInternetStack.Create(
                RuntimeInternetTransportProtocols.HttpUpgrade,
                RuntimeInternetSecurityTypes.Tls),
            VmessClientTransportType.Grpc => RuntimeInternetStack.Create(
                RuntimeInternetTransportProtocols.Grpc,
                RuntimeInternetSecurityTypes.Tls),
            VmessClientTransportType.SplitHttp => RuntimeInternetStack.Create(
                RuntimeInternetTransportProtocols.SplitHttp,
                RuntimeInternetSecurityTypes.None),
            _ => throw new NotSupportedException($"Unsupported VMess client transport: {transport}.")
        };
}

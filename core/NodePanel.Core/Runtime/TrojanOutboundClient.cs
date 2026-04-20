using NodePanel.Core.Protocol;

namespace NodePanel.Core.Runtime;

public sealed class TrojanOutboundClient
{
    private readonly IDnsResolver _dnsResolver;
    private readonly RuntimeInternetProfile _internetProfile;
    private readonly TrojanHandshakeWriter _trojanHandshakeWriter;

    public TrojanOutboundClient()
        : this(new TrojanHandshakeWriter(), dnsResolver: null)
    {
    }

    public TrojanOutboundClient(
        TrojanHandshakeWriter trojanHandshakeWriter,
        IDnsResolver? dnsResolver = null)
        : this(trojanHandshakeWriter, dnsResolver, internetProfile: null)
    {
    }

    internal TrojanOutboundClient(
        TrojanHandshakeWriter trojanHandshakeWriter,
        IDnsResolver? dnsResolver,
        RuntimeInternetProfile? internetProfile)
    {
        _trojanHandshakeWriter = trojanHandshakeWriter;
        _dnsResolver = dnsResolver ?? SystemDnsResolver.Instance;
        _internetProfile = internetProfile ?? RuntimeInternetProfile.Default;
    }

    public async Task<TrojanClientConnection> ConnectAsync(
        TrojanClientOptions options,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(options);
        ValidateOptions(options);
        options = NormalizeRealityOptions(options);

        var handshakePayload = _trojanHandshakeWriter.Build(
            options.Password,
            options.Command,
            options.TargetHost,
            options.TargetPort);
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
            if (transportInitializationData is null)
            {
                using var handshakeCts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
                handshakeCts.CancelAfter(TimeSpan.FromSeconds(options.HandshakeTimeoutSeconds));
                await transportConnection.Stream.WriteAsync(handshakePayload.AsMemory(0, handshakePayload.Length), handshakeCts.Token).ConfigureAwait(false);
                await transportConnection.Stream.FlushAsync(handshakeCts.Token).ConfigureAwait(false);
            }

            return transportConnection;
        }
        catch
        {
            await transportConnection.DisposeAsync().ConfigureAwait(false);
            throw;
        }
    }

    private async Task<TrojanClientConnection> OpenTransportAsync(
        TrojanClientOptions options,
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

        return new TrojanClientConnection(connectionContext);
    }

    private static byte[]? ResolveTransportInitializationData(
        RuntimeInternetStack internetStack,
        TrojanClientOptions options,
        byte[] handshakePayload)
    {
        if (!string.Equals(internetStack.TransportProtocol, RuntimeInternetTransportProtocols.HttpUpgrade, StringComparison.Ordinal) ||
            options.WebSocketEarlyDataBytes <= 0)
        {
            return null;
        }

        return handshakePayload.Length <= options.WebSocketEarlyDataBytes ? handshakePayload : null;
    }

    private static RuntimeInternetStack ResolveInternetStack(TrojanClientOptions options)
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

    private static void ValidateOptions(TrojanClientOptions options)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(options.ServerHost);
        ArgumentException.ThrowIfNullOrWhiteSpace(options.Password);
        ArgumentException.ThrowIfNullOrWhiteSpace(options.TargetHost);

        if (options.ServerPort is <= 0 or > 65535)
        {
            throw new ArgumentOutOfRangeException(nameof(options), options.ServerPort, "Server port must be between 1 and 65535.");
        }

        if (options.TargetPort is <= 0 or > 65535)
        {
            throw new ArgumentOutOfRangeException(nameof(options), options.TargetPort, "Target port must be between 1 and 65535.");
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

    private static TrojanClientOptions NormalizeRealityOptions(TrojanClientOptions options)
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

    private static RuntimeInternetStack ResolveLegacyInternetStack(TrojanClientTransportType transport)
        => transport switch
        {
            TrojanClientTransportType.Tcp => RuntimeInternetStack.Create(
                RuntimeInternetTransportProtocols.Tcp,
                RuntimeInternetSecurityTypes.None),
            TrojanClientTransportType.Tls => RuntimeInternetStack.Create(
                RuntimeInternetTransportProtocols.Tcp,
                RuntimeInternetSecurityTypes.Tls),
            TrojanClientTransportType.Ws => RuntimeInternetStack.Create(
                RuntimeInternetTransportProtocols.Ws,
                RuntimeInternetSecurityTypes.None),
            TrojanClientTransportType.Wss => RuntimeInternetStack.Create(
                RuntimeInternetTransportProtocols.Ws,
                RuntimeInternetSecurityTypes.Tls),
            TrojanClientTransportType.HttpUpgrade => RuntimeInternetStack.Create(
                RuntimeInternetTransportProtocols.HttpUpgrade,
                RuntimeInternetSecurityTypes.None),
            TrojanClientTransportType.HttpUpgradeTls => RuntimeInternetStack.Create(
                RuntimeInternetTransportProtocols.HttpUpgrade,
                RuntimeInternetSecurityTypes.Tls),
            TrojanClientTransportType.Grpc => RuntimeInternetStack.Create(
                RuntimeInternetTransportProtocols.Grpc,
                RuntimeInternetSecurityTypes.Tls),
            TrojanClientTransportType.SplitHttp => RuntimeInternetStack.Create(
                RuntimeInternetTransportProtocols.SplitHttp,
                RuntimeInternetSecurityTypes.None),
            _ => throw new NotSupportedException($"Unsupported trojan client transport: {transport}.")
        };
}

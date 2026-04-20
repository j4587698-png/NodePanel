using System.Net;
using System.Net.Sockets;
using System.Text;

namespace NodePanel.Core.Runtime;

public sealed class SocksOutboundHandler : IOutboundHandler
{
    private readonly IOutboundCommonSettingsProvider _commonSettingsProvider;
    private readonly IDnsResolver _dnsResolver;
    private readonly IRuntimeOutboundSettingsProvider _runtimeSettingsProvider;
    private readonly IServiceProvider? _serviceProvider;

    public SocksOutboundHandler(
        IOutboundCommonSettingsProvider commonSettingsProvider,
        IRuntimeOutboundSettingsProvider runtimeSettingsProvider,
        IServiceProvider? serviceProvider = null,
        IDnsResolver? dnsResolver = null)
    {
        _commonSettingsProvider = commonSettingsProvider ?? throw new ArgumentNullException(nameof(commonSettingsProvider));
        _runtimeSettingsProvider = runtimeSettingsProvider ?? throw new ArgumentNullException(nameof(runtimeSettingsProvider));
        _serviceProvider = serviceProvider;
        _dnsResolver = dnsResolver ?? SystemDnsResolver.Instance;
    }

    public string Protocol => OutboundProtocols.Socks;

    internal IDnsResolver DnsResolver => _dnsResolver;

    public async ValueTask<Stream> OpenTcpAsync(
        DispatchContext context,
        DispatchDestination destination,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(destination);
        if (destination.Network != DispatchNetwork.Tcp)
        {
            throw new NotSupportedException($"SOCKS outbound does not support TCP open for network '{destination.Network}'.");
        }

        var settings = ResolveSettings(context);
        var resolvedDestination = await OutboundTargetStrategyResolver.ResolveAsync(
            context,
            destination,
            settings.Common.TargetStrategy,
            _dnsResolver,
            cancellationToken).ConfigureAwait(false);

        var stream = await OpenServerTcpStreamAsync(context, settings, cancellationToken).ConfigureAwait(false);
        try
        {
            await PerformGreetingAsync(stream, settings.Outbound, cancellationToken).ConfigureAwait(false);
            await WriteRequestAsync(
                stream,
                Socks5ProtocolConstants.CommandConnect,
                resolvedDestination,
                cancellationToken).ConfigureAwait(false);
            await ReadReplyAsync(stream, cancellationToken).ConfigureAwait(false);
            return stream;
        }
        catch
        {
            await stream.DisposeAsync().ConfigureAwait(false);
            throw;
        }
    }

    public ValueTask<IOutboundUdpTransport> OpenUdpAsync(
        DispatchContext context,
        CancellationToken cancellationToken)
        => ValueTask.FromResult<IOutboundUdpTransport>(new SocksOutboundUdpTransport(this, context, ResolveSettings(context)));

    internal SocksResolvedSettings ResolveSettings(DispatchContext context)
    {
        if (!_commonSettingsProvider.TryResolve(context, out var commonSettings) ||
            !string.Equals(commonSettings.Protocol, OutboundProtocols.Socks, StringComparison.Ordinal))
        {
            throw new InvalidOperationException("SOCKS outbound common settings could not be resolved for the current dispatch context.");
        }

        if (!_runtimeSettingsProvider.TryResolve(context, out RuntimeSocksOutboundOptions runtimeSettings) ||
            !string.Equals(runtimeSettings.Protocol, OutboundProtocols.Socks, StringComparison.Ordinal))
        {
            throw new InvalidOperationException("SOCKS outbound settings could not be resolved for the current dispatch context.");
        }

        return new SocksResolvedSettings
        {
            Common = commonSettings,
            Outbound = runtimeSettings
        };
    }

    internal async ValueTask<Stream> OpenServerTcpStreamAsync(
        DispatchContext context,
        SocksResolvedSettings settings,
        CancellationToken cancellationToken)
    {
        if (!string.IsNullOrWhiteSpace(settings.Common.ProxyOutboundTag))
        {
            return await ResolveDispatcher().DispatchTcpAsync(
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

        using var connectCts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        connectCts.CancelAfter(TimeSpan.FromSeconds(ResolveTimeout(settings.Outbound.ConnectTimeoutSeconds, context.ConnectTimeoutSeconds)));
        var endPoints = await OutboundSocketDialer.ResolveTcpEndPointsAsync(
            context,
            settings.Outbound.ServerHost,
            settings.Outbound.ServerPort,
            AddressFamily.Unspecified,
            _dnsResolver,
            connectCts.Token).ConfigureAwait(false);
        return await OutboundSocketDialer.OpenTcpStreamAsync(
            context,
            settings.Common.Via,
            settings.Common.ViaCidr,
            endPoints,
            connectCts.Token).ConfigureAwait(false);
    }

    internal IDispatcher ResolveDispatcher()
        => _serviceProvider?.GetService(typeof(IDispatcher)) as IDispatcher
           ?? throw new InvalidOperationException("SOCKS outbound proxy chaining requires an active dispatcher.");

    internal static async Task PerformGreetingAsync(
        Stream stream,
        RuntimeSocksOutboundOptions settings,
        CancellationToken cancellationToken)
    {
        var authenticationMethod = UsesAuthentication(settings)
            ? Socks5ProtocolConstants.AuthenticationMethodUsernamePassword
            : Socks5ProtocolConstants.AuthenticationMethodNone;

        await WriteBytesAsync(
            stream,
            new byte[]
            {
                Socks5ProtocolConstants.Version,
                0x01,
                authenticationMethod
            },
            cancellationToken).ConfigureAwait(false);

        var selection = new byte[2];
        await ReadExactOrThrowAsync(stream, selection, cancellationToken).ConfigureAwait(false);
        if (selection[0] != Socks5ProtocolConstants.Version)
        {
            throw new InvalidDataException($"SOCKS server returned an unexpected version: {selection[0]}.");
        }

        if (selection[1] == Socks5ProtocolConstants.AuthenticationMethodNoAcceptable)
        {
            throw new IOException("SOCKS server rejected all advertised authentication methods.");
        }

        if (selection[1] != authenticationMethod)
        {
            throw new IOException($"SOCKS server selected an unexpected authentication method: {selection[1]}.");
        }

        if (!UsesAuthentication(settings))
        {
            return;
        }

        var username = Encoding.UTF8.GetBytes(settings.Username);
        var password = Encoding.UTF8.GetBytes(settings.Password);
        if (username.Length is 0 or > byte.MaxValue || password.Length > byte.MaxValue)
        {
            throw new InvalidDataException("SOCKS username and password must each be between 1 and 255 UTF-8 bytes.");
        }

        var authenticationRequest = new byte[3 + username.Length + password.Length];
        authenticationRequest[0] = Socks5ProtocolConstants.AuthenticationVersionUsernamePassword;
        authenticationRequest[1] = (byte)username.Length;
        username.CopyTo(authenticationRequest.AsSpan(2));
        authenticationRequest[2 + username.Length] = (byte)password.Length;
        password.CopyTo(authenticationRequest.AsSpan(3 + username.Length));
        await WriteBytesAsync(stream, authenticationRequest, cancellationToken).ConfigureAwait(false);

        var authenticationResponse = new byte[2];
        await ReadExactOrThrowAsync(stream, authenticationResponse, cancellationToken).ConfigureAwait(false);
        if (authenticationResponse[0] != Socks5ProtocolConstants.AuthenticationVersionUsernamePassword ||
            authenticationResponse[1] != Socks5ProtocolConstants.AuthenticationStatusSucceeded)
        {
            throw new IOException("SOCKS username/password authentication failed.");
        }
    }

    internal static async Task WriteRequestAsync(
        Stream stream,
        byte command,
        DispatchDestination destination,
        CancellationToken cancellationToken)
    {
        var addressLength = Socks5AddressCodec.GetSerializedLength(destination.Host);
        var buffer = new byte[3 + addressLength];
        buffer[0] = Socks5ProtocolConstants.Version;
        buffer[1] = command;
        buffer[2] = 0x00;
        Socks5AddressCodec.WriteAddressPort(buffer.AsSpan(3), destination.Host, destination.Port);
        await WriteBytesAsync(stream, buffer, cancellationToken).ConfigureAwait(false);
    }

    internal static async Task<SocksReply> ReadReplyAsync(
        Stream stream,
        CancellationToken cancellationToken)
    {
        var header = new byte[4];
        await ReadExactOrThrowAsync(stream, header, cancellationToken).ConfigureAwait(false);
        if (header[0] != Socks5ProtocolConstants.Version)
        {
            throw new InvalidDataException($"SOCKS server returned an unexpected version: {header[0]}.");
        }

        if (header[1] != Socks5ProtocolConstants.ReplySucceeded)
        {
            throw new IOException($"SOCKS server rejected the request with reply code: {header[1]}.");
        }

        var address = await ReadAddressPortAsync(stream, header[3], cancellationToken).ConfigureAwait(false);
        return new SocksReply
        {
            Host = address.Host,
            Port = address.Port
        };
    }

    internal static async Task<SocksAddress> ReadAddressPortAsync(
        Stream stream,
        byte addressType,
        CancellationToken cancellationToken)
    {
        switch (addressType)
        {
            case 0x01:
                return await ReadSizedAddressPortAsync(stream, addressType, 6, cancellationToken).ConfigureAwait(false);
            case 0x04:
                return await ReadSizedAddressPortAsync(stream, addressType, 18, cancellationToken).ConfigureAwait(false);
            case 0x03:
            {
                var domainLength = new byte[1];
                await ReadExactOrThrowAsync(stream, domainLength, cancellationToken).ConfigureAwait(false);
                var payload = new byte[1 + domainLength[0] + 2];
                payload[0] = domainLength[0];
                await ReadExactOrThrowAsync(stream, payload.AsMemory(1, payload.Length - 1), cancellationToken).ConfigureAwait(false);
                return DecodeAddress(addressType, payload);
            }
            default:
                throw new InvalidDataException($"SOCKS server returned an unsupported address type: {addressType}.");
        }
    }

    internal static async Task ReadExactOrThrowAsync(
        Stream stream,
        Memory<byte> buffer,
        CancellationToken cancellationToken)
    {
        var offset = 0;
        while (offset < buffer.Length)
        {
            var read = await stream.ReadAsync(buffer[offset..], cancellationToken).ConfigureAwait(false);
            if (read == 0)
            {
                throw new IOException("SOCKS server closed the connection during handshake.");
            }

            offset += read;
        }
    }

    internal static bool TryGetRemoteEndPoint(Stream stream, out IPEndPoint remoteEndPoint)
    {
        if (stream is NetworkStream networkStream &&
            networkStream.Socket.RemoteEndPoint is IPEndPoint endPoint)
        {
            remoteEndPoint = endPoint;
            return true;
        }

        remoteEndPoint = default!;
        return false;
    }

    internal static bool IsAnyAddress(string host)
        => string.Equals(host, IPAddress.Any.ToString(), StringComparison.Ordinal) ||
           string.Equals(host, IPAddress.IPv6Any.ToString(), StringComparison.Ordinal);

    internal static int ResolveTimeout(int value, int fallback)
        => value > 0 ? value : fallback;

    internal static DispatchContext CreateProxyContext(
        DispatchContext context,
        string host,
        int port,
        string outboundTag)
        => context with
        {
            OutboundTag = outboundTag,
            OriginalDestinationHost = host,
            OriginalDestinationPort = port
        };

    private static bool UsesAuthentication(RuntimeSocksOutboundOptions settings)
        => !string.IsNullOrWhiteSpace(settings.Username) || !string.IsNullOrWhiteSpace(settings.Password);

    private static async Task<SocksAddress> ReadSizedAddressPortAsync(
        Stream stream,
        byte addressType,
        int payloadLength,
        CancellationToken cancellationToken)
    {
        var payload = new byte[payloadLength];
        await ReadExactOrThrowAsync(stream, payload, cancellationToken).ConfigureAwait(false);
        return DecodeAddress(addressType, payload);
    }

    private static SocksAddress DecodeAddress(byte addressType, byte[] payload)
    {
        var buffer = new byte[1 + payload.Length];
        buffer[0] = addressType;
        payload.CopyTo(buffer.AsSpan(1));
        var address = Socks5AddressCodec.ReadAddressPort(buffer);
        return new SocksAddress
        {
            Host = address.Host,
            Port = address.Port
        };
    }

    private static Task WriteBytesAsync(
        Stream stream,
        ReadOnlyMemory<byte> payload,
        CancellationToken cancellationToken)
        => stream.WriteAsync(payload, cancellationToken).AsTask();
}

internal sealed record SocksResolvedSettings
{
    public required OutboundCommonSettings Common { get; init; }

    public required RuntimeSocksOutboundOptions Outbound { get; init; }
}

internal sealed record SocksReply
{
    public required string Host { get; init; }

    public required int Port { get; init; }
}

internal sealed record SocksAddress
{
    public required string Host { get; init; }

    public required int Port { get; init; }
}

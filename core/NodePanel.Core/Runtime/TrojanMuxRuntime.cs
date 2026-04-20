using System.Buffers.Binary;
using System.Collections.Concurrent;
using System.Net;
using System.Threading.Channels;
using NodePanel.Core.Protocol;

namespace NodePanel.Core.Runtime;

internal static class TrojanMuxProtocol
{
    public const string Host = "v1.mux.cool";
    public const int Port = 9527;
    public const int XudpPort = 666;
    public const int DefaultConcurrency = 8;
    public const int MaxMetadataLength = 512;
    public const int MaxSessionCountPerConnection = 128;
    public const int MaxStreamChunkLength = 8 * 1024;

    public static bool IsMuxDestination(string host)
        => !string.IsNullOrWhiteSpace(host) &&
           string.Equals(host.Trim(), Host, StringComparison.OrdinalIgnoreCase);

    public static DispatchDestination CreateMuxDestination()
        => new()
        {
            Host = Host,
            Port = Port,
            Network = DispatchNetwork.Tcp
        };

    public static DispatchDestination CreateXudpDestination()
        => new()
        {
            Host = Host,
            Port = XudpPort,
            Network = DispatchNetwork.Tcp
        };

    public static byte[] CreateGlobalId(DispatchContext context)
    {
        ArgumentNullException.ThrowIfNull(context);
        return XudpGlobalId.Create(context);
    }

    public static TrojanMuxFrameTarget? CreateEndpointTarget(
        EndPoint? endPoint,
        DispatchNetwork network)
    {
        switch (endPoint)
        {
            case IPEndPoint ipEndPoint when ipEndPoint.Port > 0:
                return new TrojanMuxFrameTarget(
                    NormalizeIpAddress(ipEndPoint.Address).ToString(),
                    ipEndPoint.Port,
                    network);
            case DnsEndPoint dnsEndPoint when dnsEndPoint.Port > 0 &&
                                             !string.IsNullOrWhiteSpace(dnsEndPoint.Host):
                return new TrojanMuxFrameTarget(
                    dnsEndPoint.Host.Trim(),
                    dnsEndPoint.Port,
                    network);
            default:
                return null;
        }
    }

    public static EndPoint? CreateEndPoint(TrojanMuxFrameTarget? target)
    {
        if (target is null ||
            target.Port <= 0 ||
            string.IsNullOrWhiteSpace(target.Host))
        {
            return null;
        }

        if (IPAddress.TryParse(target.Host, out var address))
        {
            return new IPEndPoint(NormalizeIpAddress(address), target.Port);
        }

        return new DnsEndPoint(target.Host.Trim(), target.Port);
    }

    public static IReadOnlyList<IPAddress> CreateAddressList(EndPoint? endPoint)
        => endPoint is IPEndPoint ipEndPoint
            ? [NormalizeIpAddress(ipEndPoint.Address)]
            : Array.Empty<IPAddress>();

    private static IPAddress NormalizeIpAddress(IPAddress address)
        => address.IsIPv4MappedToIPv6 ? address.MapToIPv4() : address;
}

internal enum TrojanMuxSessionStatus : byte
{
    New = 0x01,
    Keep = 0x02,
    End = 0x03,
    KeepAlive = 0x04
}

[Flags]
internal enum TrojanMuxFrameOption : byte
{
    None = 0x00,
    Data = 0x01,
    Error = 0x02
}

internal enum TrojanMuxTargetNetwork : byte
{
    Tcp = 0x01,
    Udp = 0x02
}

internal sealed record TrojanMuxFrameTarget(string Host, int Port, DispatchNetwork Network)
{
    public DispatchDestination ToDispatchDestination()
        => new()
        {
            Host = Host,
            Port = Port,
            Network = Network
        };
}

internal sealed record TrojanMuxFrame
{
    public required ushort SessionId { get; init; }

    public required TrojanMuxSessionStatus Status { get; init; }

    public TrojanMuxFrameOption Option { get; init; } = TrojanMuxFrameOption.None;

    public TrojanMuxFrameTarget? Target { get; init; }

    public TrojanMuxFrameTarget? Source { get; init; }

    public TrojanMuxFrameTarget? Local { get; init; }

    public byte[] GlobalId { get; init; } = Array.Empty<byte>();

    public byte[] Payload { get; init; } = Array.Empty<byte>();

    public bool HasData => Option.HasFlag(TrojanMuxFrameOption.Data);

    public bool HasError => Option.HasFlag(TrojanMuxFrameOption.Error);
}

internal static class TrojanMuxAddressCodec
{
    public static int GetSerializedLength(string host)
    {
        if (IPAddress.TryParse(host, out var ipAddress))
        {
            return ipAddress.AddressFamily switch
            {
                System.Net.Sockets.AddressFamily.InterNetwork => 2 + 1 + 4,
                System.Net.Sockets.AddressFamily.InterNetworkV6 => 2 + 1 + 16,
                _ => throw new InvalidDataException($"Unsupported IP address family for mux target: {host}.")
            };
        }

        var domainBytes = System.Text.Encoding.ASCII.GetBytes(host);
        if (domainBytes.Length is 0 or > byte.MaxValue)
        {
            throw new InvalidDataException("Mux domain address must be between 1 and 255 ASCII bytes.");
        }

        return 2 + 1 + 1 + domainBytes.Length;
    }

    public static int WriteAddressPort(Span<byte> destination, string host, int port)
    {
        if (port is <= 0 or > 65535)
        {
            throw new ArgumentOutOfRangeException(nameof(port), port, "Port must be between 1 and 65535.");
        }

        BinaryPrimitives.WriteUInt16BigEndian(destination, (ushort)port);

        if (IPAddress.TryParse(host, out var ipAddress))
        {
            var addressBytes = ipAddress.GetAddressBytes();
            return ipAddress.AddressFamily switch
            {
                System.Net.Sockets.AddressFamily.InterNetwork => WriteIp(destination, 0x01, addressBytes),
                System.Net.Sockets.AddressFamily.InterNetworkV6 => WriteIp(destination, 0x03, addressBytes),
                _ => throw new InvalidDataException($"Unsupported IP address family for mux target: {host}.")
            };
        }

        var domainBytes = System.Text.Encoding.ASCII.GetBytes(host);
        if (domainBytes.Length is 0 or > byte.MaxValue)
        {
            throw new InvalidDataException("Mux domain address must be between 1 and 255 ASCII bytes.");
        }

        destination[2] = 0x02;
        destination[3] = (byte)domainBytes.Length;
        domainBytes.CopyTo(destination[4..]);
        return 4 + domainBytes.Length;
    }

    public static (string Host, int Port, int Consumed) ReadAddressPort(ReadOnlySpan<byte> source)
    {
        if (source.Length < 3)
        {
            throw new InvalidDataException("Mux target address is incomplete.");
        }

        var port = BinaryPrimitives.ReadUInt16BigEndian(source);
        var addressType = source[2];
        return addressType switch
        {
            0x01 => ReadIp(source, 4, port),
            0x03 => ReadIp(source, 16, port),
            0x02 => ReadDomain(source, port),
            _ => throw new InvalidDataException($"Unsupported mux address type: {addressType}.")
        };
    }

    private static int WriteIp(Span<byte> destination, byte addressType, byte[] addressBytes)
    {
        destination[2] = addressType;
        addressBytes.CopyTo(destination[3..]);
        return 3 + addressBytes.Length;
    }

    private static (string Host, int Port, int Consumed) ReadIp(ReadOnlySpan<byte> source, int byteCount, int port)
    {
        if (source.Length < 3 + byteCount)
        {
            throw new InvalidDataException("Mux IP target is incomplete.");
        }

        return (new IPAddress(source.Slice(3, byteCount)).ToString(), port, 3 + byteCount);
    }

    private static (string Host, int Port, int Consumed) ReadDomain(ReadOnlySpan<byte> source, int port)
    {
        if (source.Length < 4)
        {
            throw new InvalidDataException("Mux domain target is incomplete.");
        }

        var length = source[3];
        if (source.Length < 4 + length)
        {
            throw new InvalidDataException("Mux domain target is incomplete.");
        }

        return (System.Text.Encoding.ASCII.GetString(source.Slice(4, length)), port, 4 + length);
    }
}

internal static class TrojanMuxFrameCodec
{
    public static async ValueTask<TrojanMuxFrame?> ReadAsync(Stream stream, CancellationToken cancellationToken)
        => await ReadAsync(stream, readSourceAndLocal: false, cancellationToken).ConfigureAwait(false);

    public static async ValueTask<TrojanMuxFrame?> ReadAsync(
        Stream stream,
        bool readSourceAndLocal,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(stream);

        var metaLengthBuffer = new byte[2];
        var read = await stream.ReadAsync(metaLengthBuffer.AsMemory(0, 2), cancellationToken).ConfigureAwait(false);
        if (read == 0)
        {
            return null;
        }

        while (read < 2)
        {
            var current = await stream.ReadAsync(metaLengthBuffer.AsMemory(read, 2 - read), cancellationToken).ConfigureAwait(false);
            if (current == 0)
            {
                throw new EndOfStreamException("Unexpected end of stream while reading mux metadata length.");
            }

            read += current;
        }

        var metaLength = BinaryPrimitives.ReadUInt16BigEndian(metaLengthBuffer);
        if (metaLength is < 4 or > TrojanMuxProtocol.MaxMetadataLength)
        {
            throw new InvalidDataException($"Invalid mux metadata length: {metaLength}.");
        }

        var metadata = new byte[metaLength];
        await TrojanProtocolCodec.ReadExactAsync(stream, metadata, cancellationToken).ConfigureAwait(false);

        var offset = 0;
        var sessionId = BinaryPrimitives.ReadUInt16BigEndian(metadata.AsSpan(offset, 2));
        offset += 2;
        var status = (TrojanMuxSessionStatus)metadata[offset++];
        var option = (TrojanMuxFrameOption)metadata[offset++];

        TrojanMuxFrameTarget? target = null;
        TrojanMuxFrameTarget? source = null;
        TrojanMuxFrameTarget? local = null;
        var globalId = Array.Empty<byte>();

        if (status == TrojanMuxSessionStatus.New ||
            (status == TrojanMuxSessionStatus.Keep &&
             offset < metadata.Length &&
             metadata[offset] == (byte)TrojanMuxTargetNetwork.Udp))
        {
            var network = metadata[offset++] switch
            {
                (byte)TrojanMuxTargetNetwork.Tcp => DispatchNetwork.Tcp,
                (byte)TrojanMuxTargetNetwork.Udp => DispatchNetwork.Udp,
            var value => throw new InvalidDataException($"Unsupported mux target network: {value}.")
            };

            var parsed = TrojanMuxAddressCodec.ReadAddressPort(metadata.AsSpan(offset));
            offset += parsed.Consumed;
            target = new TrojanMuxFrameTarget(parsed.Host, parsed.Port, network);

            if (status == TrojanMuxSessionStatus.New)
            {
                var remaining = metadata.AsSpan(offset);
                if (readSourceAndLocal &&
                    TryReadOptionalEndpoint(remaining, out source, out var sourceConsumed))
                {
                    offset += sourceConsumed;
                    remaining = metadata.AsSpan(offset);
                    if (TryReadOptionalEndpoint(remaining, out local, out var localConsumed))
                    {
                        offset += localConsumed;
                    }
                }
                else if (!readSourceAndLocal &&
                         network == DispatchNetwork.Udp &&
                         option.HasFlag(TrojanMuxFrameOption.Data) &&
                         metadata.Length - offset >= 8)
                {
                    globalId = metadata.AsSpan(offset, 8).ToArray();
                }
            }
        }

        var payload = Array.Empty<byte>();
        if (option.HasFlag(TrojanMuxFrameOption.Data))
        {
            var payloadLength = await TrojanProtocolCodec.ReadUInt16Async(stream, cancellationToken).ConfigureAwait(false);
            payload = new byte[payloadLength];
            if (payload.Length > 0)
            {
                await TrojanProtocolCodec.ReadExactAsync(stream, payload, cancellationToken).ConfigureAwait(false);
            }
        }

        return new TrojanMuxFrame
        {
            SessionId = sessionId,
            Status = status,
            Option = option,
            Target = target,
            Source = source,
            Local = local,
            GlobalId = globalId,
            Payload = payload
        };
    }

    public static async ValueTask WriteAsync(
        Stream stream,
        TrojanMuxFrame frame,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(stream);
        ArgumentNullException.ThrowIfNull(frame);

        var metadata = BuildMetadata(frame);
        await stream.WriteAsync(metadata.AsMemory(0, metadata.Length), cancellationToken).ConfigureAwait(false);
        if (frame.HasData)
        {
            var payloadLength = new byte[2];
            BinaryPrimitives.WriteUInt16BigEndian(payloadLength, checked((ushort)frame.Payload.Length));
            await stream.WriteAsync(payloadLength.AsMemory(0, payloadLength.Length), cancellationToken).ConfigureAwait(false);
            if (frame.Payload.Length > 0)
            {
                await stream.WriteAsync(frame.Payload.AsMemory(0, frame.Payload.Length), cancellationToken).ConfigureAwait(false);
            }
        }
    }

    private static byte[] BuildMetadata(TrojanMuxFrame frame)
    {
        var metaLength = 4;
        var hasData = frame.HasData;

        if (frame.Status == TrojanMuxSessionStatus.New)
        {
            ArgumentNullException.ThrowIfNull(frame.Target);
            metaLength += 1 + TrojanMuxAddressCodec.GetSerializedLength(frame.Target.Host);
            if (frame.Source is not null)
            {
                metaLength += 1 + TrojanMuxAddressCodec.GetSerializedLength(frame.Source.Host);
                if (frame.Local is not null)
                {
                    metaLength += 1 + TrojanMuxAddressCodec.GetSerializedLength(frame.Local.Host);
                }
            }
            else if (frame.Target.Network == DispatchNetwork.Udp && hasData)
            {
                metaLength += 8;
            }
        }
        else if (frame.Status == TrojanMuxSessionStatus.Keep &&
                 frame.Target?.Network == DispatchNetwork.Udp &&
                 hasData)
        {
            metaLength += 1 + TrojanMuxAddressCodec.GetSerializedLength(frame.Target.Host);
        }

        var buffer = new byte[2 + metaLength];
        var offset = 0;
        BinaryPrimitives.WriteUInt16BigEndian(buffer.AsSpan(offset, 2), checked((ushort)metaLength));
        offset += 2;
        BinaryPrimitives.WriteUInt16BigEndian(buffer.AsSpan(offset, 2), frame.SessionId);
        offset += 2;
        buffer[offset++] = (byte)frame.Status;
        buffer[offset++] = (byte)frame.Option;

        if (frame.Status == TrojanMuxSessionStatus.New)
        {
            offset += WriteTarget(buffer.AsSpan(offset), frame.Target!);
            if (frame.Source is not null)
            {
                offset += WriteTarget(buffer.AsSpan(offset), frame.Source);
                if (frame.Local is not null)
                {
                    offset += WriteTarget(buffer.AsSpan(offset), frame.Local);
                }
            }
            else if (frame.Target!.Network == DispatchNetwork.Udp && hasData)
            {
                var globalId = frame.GlobalId.Length == 8 ? frame.GlobalId : new byte[8];
                globalId.CopyTo(buffer.AsSpan(offset, 8));
            }
        }
        else if (frame.Status == TrojanMuxSessionStatus.Keep &&
                 frame.Target?.Network == DispatchNetwork.Udp &&
                 hasData)
        {
            WriteTarget(buffer.AsSpan(offset), frame.Target);
        }

        return buffer;
    }

    private static int WriteTarget(Span<byte> destination, TrojanMuxFrameTarget target)
    {
        destination[0] = target.Network switch
        {
            DispatchNetwork.Tcp => (byte)TrojanMuxTargetNetwork.Tcp,
            DispatchNetwork.Udp => (byte)TrojanMuxTargetNetwork.Udp,
            _ => throw new InvalidDataException($"Unsupported mux target network: {target.Network}.")
        };

        return 1 + TrojanMuxAddressCodec.WriteAddressPort(destination[1..], target.Host, target.Port);
    }

    private static bool TryReadOptionalEndpoint(
        ReadOnlySpan<byte> source,
        out TrojanMuxFrameTarget? endpoint,
        out int consumed)
    {
        endpoint = null;
        consumed = 0;
        if (source.Length == 0)
        {
            return false;
        }

        var network = source[0] switch
        {
            (byte)TrojanMuxTargetNetwork.Tcp => DispatchNetwork.Tcp,
            (byte)TrojanMuxTargetNetwork.Udp => DispatchNetwork.Udp,
            _ => default
        };

        if (network == default)
        {
            return false;
        }

        var parsed = TrojanMuxAddressCodec.ReadAddressPort(source[1..]);
        endpoint = new TrojanMuxFrameTarget(parsed.Host, parsed.Port, network);
        consumed = 1 + parsed.Consumed;
        return true;
    }
}

internal sealed record TrojanMuxSignature(
    string Protocol,
    string Tag,
    string ServerHost,
    int ServerPort,
    string ServerName,
    string Fingerprint,
    string Transport,
    string TransportSecurity,
    string WebSocketPath,
    string WebSocketHeaders,
    int WebSocketEarlyDataBytes,
    int WebSocketHeartbeatPeriodSeconds,
    string SplitHttpHost,
    string SplitHttpPath,
    string SplitHttpHeaders,
    string SplitHttpMode,
    bool SplitHttpNoGrpcHeader,
    RuntimeInt32Range SplitHttpXPaddingBytes,
    bool SplitHttpXPaddingObfsMode,
    string SplitHttpXPaddingKey,
    string SplitHttpXPaddingHeader,
    string SplitHttpXPaddingPlacement,
    string SplitHttpXPaddingMethod,
    string SplitHttpUplinkHttpMethod,
    string SplitHttpSessionPlacement,
    string SplitHttpSessionKey,
    string SplitHttpSeqPlacement,
    string SplitHttpSeqKey,
    string SplitHttpUplinkDataPlacement,
    string SplitHttpUplinkDataKey,
    RuntimeInt32Range SplitHttpUplinkChunkSize,
    RuntimeInt32Range SplitHttpScMaxEachPostBytes,
    RuntimeInt32Range SplitHttpScMinPostsIntervalMs,
    int SplitHttpScMaxBufferedPosts,
    string SplitHttpXmux,
    string SplitHttpDownloadSettings,
    string ApplicationProtocols,
    string GrpcServiceName,
    string GrpcAuthority,
    bool GrpcMultiMode,
    string GrpcUserAgent,
    int GrpcIdleTimeoutSeconds,
    int GrpcHealthCheckTimeoutSeconds,
    bool GrpcPermitWithoutStream,
    int GrpcInitialWindowSize,
    string RealitySignature,
    string Credential,
    int ConnectTimeoutSeconds,
    int HandshakeTimeoutSeconds,
    bool SkipCertificateValidation,
    string Via,
    string ViaCidr,
    string ProxyOutboundTag,
    int TcpConcurrency,
    int UdpConcurrency,
    string Udp443Mode)
{
    public static TrojanMuxSignature FromSettings(TrojanOutboundSettings settings)
        => new(
            OutboundProtocols.Trojan,
            settings.Tag,
            settings.ServerHost,
            settings.ServerPort,
            settings.ServerName,
            settings.Fingerprint,
            settings.Transport,
            settings.TransportSecurity,
            settings.WebSocketPath,
            string.Join(
                "\n",
            settings.WebSocketHeaders
                .OrderBy(static pair => pair.Key, StringComparer.OrdinalIgnoreCase)
                .Select(static pair => pair.Key + "=" + pair.Value)),
            settings.WebSocketEarlyDataBytes,
            settings.WebSocketHeartbeatPeriodSeconds,
            settings.SplitHttpHost,
            settings.SplitHttpPath,
            string.Join(
                "\n",
            settings.SplitHttpHeaders
                .OrderBy(static pair => pair.Key, StringComparer.OrdinalIgnoreCase)
                .Select(static pair => pair.Key + "=" + pair.Value)),
            settings.SplitHttpMode,
            settings.SplitHttpNoGrpcHeader,
            settings.SplitHttpXPaddingBytes,
            settings.SplitHttpXPaddingObfsMode,
            settings.SplitHttpXPaddingKey,
            settings.SplitHttpXPaddingHeader,
            settings.SplitHttpXPaddingPlacement,
            settings.SplitHttpXPaddingMethod,
            settings.SplitHttpUplinkHttpMethod,
            settings.SplitHttpSessionPlacement,
            settings.SplitHttpSessionKey,
            settings.SplitHttpSeqPlacement,
            settings.SplitHttpSeqKey,
            settings.SplitHttpUplinkDataPlacement,
            settings.SplitHttpUplinkDataKey,
            settings.SplitHttpUplinkChunkSize,
            settings.SplitHttpScMaxEachPostBytes,
            settings.SplitHttpScMinPostsIntervalMs,
            settings.SplitHttpScMaxBufferedPosts,
            SerializeSplitHttpXmux(settings.SplitHttpXmux),
            SerializeSplitHttpDownloadSettings(settings.SplitHttpDownloadSettings),
            string.Join("\n", settings.ApplicationProtocols),
            settings.GrpcServiceName,
            settings.GrpcAuthority,
            settings.GrpcMultiMode,
            settings.GrpcUserAgent,
            settings.GrpcIdleTimeoutSeconds,
            settings.GrpcHealthCheckTimeoutSeconds,
            settings.GrpcPermitWithoutStream,
            settings.GrpcInitialWindowSize,
            CreateRealitySignature(settings.RealityOptions, settings.RealityHandshakeProvider),
            settings.Password,
            settings.ConnectTimeoutSeconds,
            settings.HandshakeTimeoutSeconds,
            settings.SkipCertificateValidation,
            settings.Via,
            settings.ViaCidr,
            settings.ProxyOutboundTag,
            settings.MultiplexSettings.Concurrency,
            settings.MultiplexSettings.XudpConcurrency,
            settings.MultiplexSettings.XudpProxyUdp443);

    public static TrojanMuxSignature FromSettings(VlessOutboundSettings settings)
        => new(
            OutboundProtocols.Vless,
            settings.Tag,
            settings.ServerHost,
            settings.ServerPort,
            settings.ServerName,
            settings.Fingerprint,
            settings.Transport,
            settings.TransportSecurity,
            settings.WebSocketPath,
            string.Join(
                "\n",
            settings.WebSocketHeaders
                .OrderBy(static pair => pair.Key, StringComparer.OrdinalIgnoreCase)
                .Select(static pair => pair.Key + "=" + pair.Value)),
            settings.WebSocketEarlyDataBytes,
            settings.WebSocketHeartbeatPeriodSeconds,
            settings.SplitHttpHost,
            settings.SplitHttpPath,
            string.Join(
                "\n",
            settings.SplitHttpHeaders
                .OrderBy(static pair => pair.Key, StringComparer.OrdinalIgnoreCase)
                .Select(static pair => pair.Key + "=" + pair.Value)),
            settings.SplitHttpMode,
            settings.SplitHttpNoGrpcHeader,
            settings.SplitHttpXPaddingBytes,
            settings.SplitHttpXPaddingObfsMode,
            settings.SplitHttpXPaddingKey,
            settings.SplitHttpXPaddingHeader,
            settings.SplitHttpXPaddingPlacement,
            settings.SplitHttpXPaddingMethod,
            settings.SplitHttpUplinkHttpMethod,
            settings.SplitHttpSessionPlacement,
            settings.SplitHttpSessionKey,
            settings.SplitHttpSeqPlacement,
            settings.SplitHttpSeqKey,
            settings.SplitHttpUplinkDataPlacement,
            settings.SplitHttpUplinkDataKey,
            settings.SplitHttpUplinkChunkSize,
            settings.SplitHttpScMaxEachPostBytes,
            settings.SplitHttpScMinPostsIntervalMs,
            settings.SplitHttpScMaxBufferedPosts,
            SerializeSplitHttpXmux(settings.SplitHttpXmux),
            SerializeSplitHttpDownloadSettings(settings.SplitHttpDownloadSettings),
            string.Join("\n", settings.ApplicationProtocols),
            settings.GrpcServiceName,
            settings.GrpcAuthority,
            settings.GrpcMultiMode,
            settings.GrpcUserAgent,
            settings.GrpcIdleTimeoutSeconds,
            settings.GrpcHealthCheckTimeoutSeconds,
            settings.GrpcPermitWithoutStream,
            settings.GrpcInitialWindowSize,
            CreateRealitySignature(settings.RealityOptions, settings.RealityHandshakeProvider),
            settings.UserUuid +
            "|" + VlessFlowTypes.Normalize(settings.Flow) +
            "|" + VlessTransportEncryption.NormalizeEncryption(settings.Encryption) +
            "|" + settings.XorMode.ToString(System.Globalization.CultureInfo.InvariantCulture) +
            "|" + settings.Seconds.ToString(System.Globalization.CultureInfo.InvariantCulture) +
            "|" + settings.Padding.Trim() +
            "|" + string.Join(",", settings.TestSeed),
            settings.ConnectTimeoutSeconds,
            settings.HandshakeTimeoutSeconds,
            settings.SkipCertificateValidation,
            settings.Via,
            settings.ViaCidr,
            settings.ProxyOutboundTag,
            settings.MultiplexSettings.Concurrency,
            settings.MultiplexSettings.XudpConcurrency,
            settings.MultiplexSettings.XudpProxyUdp443);

    public static TrojanMuxSignature FromSettings(VmessOutboundSettings settings)
        => new(
            OutboundProtocols.Vmess,
            settings.Tag,
            settings.ServerHost,
            settings.ServerPort,
            settings.ServerName,
            settings.Fingerprint,
            settings.Transport,
            settings.TransportSecurity,
            settings.WebSocketPath,
            string.Join(
                "\n",
            settings.WebSocketHeaders
                .OrderBy(static pair => pair.Key, StringComparer.OrdinalIgnoreCase)
                .Select(static pair => pair.Key + "=" + pair.Value)),
            settings.WebSocketEarlyDataBytes,
            settings.WebSocketHeartbeatPeriodSeconds,
            settings.SplitHttpHost,
            settings.SplitHttpPath,
            string.Join(
                "\n",
            settings.SplitHttpHeaders
                .OrderBy(static pair => pair.Key, StringComparer.OrdinalIgnoreCase)
                .Select(static pair => pair.Key + "=" + pair.Value)),
            settings.SplitHttpMode,
            settings.SplitHttpNoGrpcHeader,
            settings.SplitHttpXPaddingBytes,
            settings.SplitHttpXPaddingObfsMode,
            settings.SplitHttpXPaddingKey,
            settings.SplitHttpXPaddingHeader,
            settings.SplitHttpXPaddingPlacement,
            settings.SplitHttpXPaddingMethod,
            settings.SplitHttpUplinkHttpMethod,
            settings.SplitHttpSessionPlacement,
            settings.SplitHttpSessionKey,
            settings.SplitHttpSeqPlacement,
            settings.SplitHttpSeqKey,
            settings.SplitHttpUplinkDataPlacement,
            settings.SplitHttpUplinkDataKey,
            settings.SplitHttpUplinkChunkSize,
            settings.SplitHttpScMaxEachPostBytes,
            settings.SplitHttpScMinPostsIntervalMs,
            settings.SplitHttpScMaxBufferedPosts,
            SerializeSplitHttpXmux(settings.SplitHttpXmux),
            SerializeSplitHttpDownloadSettings(settings.SplitHttpDownloadSettings),
            string.Join("\n", settings.ApplicationProtocols),
            settings.GrpcServiceName,
            settings.GrpcAuthority,
            settings.GrpcMultiMode,
            settings.GrpcUserAgent,
            settings.GrpcIdleTimeoutSeconds,
            settings.GrpcHealthCheckTimeoutSeconds,
            settings.GrpcPermitWithoutStream,
            settings.GrpcInitialWindowSize,
            CreateRealitySignature(settings.RealityOptions, settings.RealityHandshakeProvider),
            settings.UserUuid + "|" + VmessOutboundSecurityTypes.Normalize(settings.Security) + "|" + settings.AuthenticatedLength + "|" + settings.NoTerminationSignal,
            settings.ConnectTimeoutSeconds,
            settings.HandshakeTimeoutSeconds,
            settings.SkipCertificateValidation,
            settings.Via,
            settings.ViaCidr,
            settings.ProxyOutboundTag,
            settings.MultiplexSettings.Concurrency,
            settings.MultiplexSettings.XudpConcurrency,
            settings.MultiplexSettings.XudpProxyUdp443);

    private static string CreateRealitySignature(
        RuntimeRealityOptions options,
        IRuntimeRealityHandshakeProvider? handshakeProvider)
        => string.Join(
            "|",
            options.Fingerprint,
            options.PublicKey,
            options.ShortId,
            options.Mldsa65Verify,
            options.SpiderX,
            ResolveRealityHandshakeProviderIdentity(handshakeProvider));

    private static string SerializeSplitHttpDownloadSettings(RuntimeSplitHttpDownloadOptions? settings)
    {
        if (settings is null)
        {
            return string.Empty;
        }

        var headers = settings.Headers is null
            ? string.Empty
            : string.Join(
                "\n",
                settings.Headers
                    .OrderBy(static pair => pair.Key, StringComparer.OrdinalIgnoreCase)
                    .Select(static pair => pair.Key + "=" + pair.Value));
        return string.Join(
            "|",
            settings.ServerHost ?? string.Empty,
            settings.ServerPort?.ToString(System.Globalization.CultureInfo.InvariantCulture) ?? string.Empty,
            settings.ServerName ?? string.Empty,
            settings.Fingerprint ?? string.Empty,
            settings.TransportSecurity ?? string.Empty,
            settings.RealityOptions?.Fingerprint ?? string.Empty,
            settings.RealityOptions?.PublicKey ?? string.Empty,
            settings.RealityOptions?.ShortId ?? string.Empty,
            settings.RealityOptions?.Mldsa65Verify ?? string.Empty,
            settings.RealityOptions?.SpiderX ?? string.Empty,
            settings.Host ?? string.Empty,
            settings.Path ?? string.Empty,
            headers,
            settings.ConnectTimeoutSeconds?.ToString(System.Globalization.CultureInfo.InvariantCulture) ?? string.Empty,
            settings.HandshakeTimeoutSeconds?.ToString(System.Globalization.CultureInfo.InvariantCulture) ?? string.Empty,
            settings.SkipCertificateValidation?.ToString() ?? string.Empty);
    }

    private static string SerializeSplitHttpXmux(RuntimeSplitHttpXmuxOptions? settings)
    {
        settings ??= RuntimeSplitHttpXmuxOptions.Empty;
        return string.Join(
            "|",
            SerializeRange(settings.MaxConcurrency),
            SerializeRange(settings.MaxConnections),
            SerializeRange(settings.CMaxReuseTimes),
            SerializeRange(settings.HMaxRequestTimes),
            SerializeRange(settings.HMaxReusableSecs),
            settings.HKeepAlivePeriodSeconds.ToString(System.Globalization.CultureInfo.InvariantCulture));
    }

    private static string SerializeRange(RuntimeInt32Range? value)
        => value is null
            ? string.Empty
            : string.Join(
                ",",
                value.From.ToString(System.Globalization.CultureInfo.InvariantCulture),
                value.To.ToString(System.Globalization.CultureInfo.InvariantCulture));

    private static string ResolveRealityHandshakeProviderIdentity(IRuntimeRealityHandshakeProvider? handshakeProvider)
        => handshakeProvider is null
            ? string.Empty
            : !string.IsNullOrWhiteSpace(handshakeProvider.Identity)
                ? handshakeProvider.Identity.Trim()
                : handshakeProvider.GetType().FullName ?? handshakeProvider.GetType().Name;
}

internal sealed class TrojanMuxOutboundMultiplexState : IAsyncDisposable
{
    private readonly TrojanMuxWorkerPool? _tcpPool;
    private readonly TrojanMuxWorkerPool? _udpPool;

    public TrojanMuxOutboundMultiplexState(TrojanMuxSignature signature)
    {
        Signature = signature;

        if (signature.TcpConcurrency >= 0)
        {
            var concurrency = signature.TcpConcurrency == 0
                ? TrojanMuxProtocol.DefaultConcurrency
                : signature.TcpConcurrency;
            _tcpPool = new TrojanMuxWorkerPool(concurrency);
        }

        if (signature.UdpConcurrency > 0)
        {
            _udpPool = new TrojanMuxWorkerPool(signature.UdpConcurrency);
        }

        Udp443Mode = OutboundXudpProxyModes.Normalize(signature.Udp443Mode);
    }

    public TrojanMuxSignature Signature { get; }

    public string Udp443Mode { get; }

    public bool CanUseTcp => _tcpPool is not null;

    public bool CanUseUdp => ResolveUdpPool() is not null;

    public bool HasDedicatedUdpPool => _udpPool is not null;

    public async ValueTask<Stream> OpenTcpAsync(
        DispatchContext context,
        DispatchDestination destination,
        Func<DispatchContext, CancellationToken, ValueTask<RuntimeClientConnection>> openConnectionAsync,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(openConnectionAsync);

        if (_tcpPool is null)
        {
            throw new InvalidOperationException("TCP multiplex is disabled for the current outbound.");
        }

        return await _tcpPool.OpenTcpAsync(context, destination, openConnectionAsync, cancellationToken).ConfigureAwait(false);
    }

    public IOutboundUdpTransport CreateUdpTransport(
        DispatchContext context,
        string targetStrategy,
        Func<DispatchContext, CancellationToken, ValueTask<RuntimeClientConnection>> openConnectionAsync,
        IDnsResolver dnsResolver)
    {
        ArgumentNullException.ThrowIfNull(openConnectionAsync);
        ArgumentNullException.ThrowIfNull(dnsResolver);

        var pool = ResolveUdpPool();
        if (pool is null)
        {
            throw new InvalidOperationException("UDP multiplex is disabled for the current outbound.");
        }

        return new TrojanMuxUdpTransport(
            pool,
            context,
            targetStrategy,
            openConnectionAsync,
            dnsResolver,
            TrojanMuxProtocol.CreateGlobalId(context));
    }

    public async ValueTask DisposeAsync()
    {
        if (_udpPool is not null)
        {
            await _udpPool.DisposeAsync().ConfigureAwait(false);
        }

        if (_tcpPool is not null &&
            !ReferenceEquals(_tcpPool, _udpPool))
        {
            await _tcpPool.DisposeAsync().ConfigureAwait(false);
        }
    }

    private TrojanMuxWorkerPool? ResolveUdpPool()
    {
        if (_udpPool is not null)
        {
            return _udpPool;
        }

        return Signature.UdpConcurrency < 0 ? null : _tcpPool;
    }
}

internal sealed class TrojanMuxWorkerPool : IAsyncDisposable
{
    private readonly int _maxConcurrency;
    private readonly object _sync = new();
    private readonly List<TrojanMuxWorker> _workers = [];

    public TrojanMuxWorkerPool(int maxConcurrency)
    {
        _maxConcurrency = maxConcurrency;
    }

    public async ValueTask<Stream> OpenTcpAsync(
        DispatchContext context,
        DispatchDestination destination,
        Func<DispatchContext, CancellationToken, ValueTask<RuntimeClientConnection>> openConnectionAsync,
        CancellationToken cancellationToken)
    {
        for (var attempt = 0; attempt < 4; attempt++)
        {
            var worker = await AcquireWorkerAsync(context, openConnectionAsync, cancellationToken).ConfigureAwait(false);
            try
            {
                return await worker.OpenTcpAsync(destination, cancellationToken).ConfigureAwait(false);
            }
            catch (InvalidOperationException) when (worker.IsClosed || !worker.CanAcceptMoreSessions())
            {
            }
        }

        throw new InvalidOperationException("Unable to allocate a mux TCP worker.");
    }

    public async ValueTask<TrojanMuxWorker> AcquireWorkerAsync(
        DispatchContext context,
        Func<DispatchContext, CancellationToken, ValueTask<RuntimeClientConnection>> openConnectionAsync,
        CancellationToken cancellationToken)
    {
        var existing = TryGetAvailableWorker();
        if (existing is not null)
        {
            return existing;
        }

        var connection = await openConnectionAsync(context, cancellationToken).ConfigureAwait(false);
        var created = new TrojanMuxWorker(connection, _maxConcurrency);

        lock (_sync)
        {
            CleanupClosedWorkers();
            existing = _workers.LastOrDefault(static worker => worker.CanAcceptMoreSessions());
            if (existing is null)
            {
                _workers.Add(created);
                return created;
            }
        }

        await created.DisposeAsync().ConfigureAwait(false);
        return existing;
    }

    public async ValueTask DisposeAsync()
    {
        TrojanMuxWorker[] workers;
        lock (_sync)
        {
            workers = _workers.ToArray();
            _workers.Clear();
        }

        foreach (var worker in workers)
        {
            await worker.DisposeAsync().ConfigureAwait(false);
        }
    }

    private TrojanMuxWorker? TryGetAvailableWorker()
    {
        lock (_sync)
        {
            CleanupClosedWorkers();
            return _workers.LastOrDefault(static worker => worker.CanAcceptMoreSessions());
        }
    }

    private void CleanupClosedWorkers()
        => _workers.RemoveAll(static worker => worker.IsClosed);
}

internal interface ITrojanMuxClientSession
{
    void OnFrame(TrojanMuxFrame frame);

    void Complete(Exception? exception);
}

internal sealed class TrojanMuxWorker : IAsyncDisposable
{
    private readonly RuntimeClientConnection _connection;
    private readonly bool _isReverseMux;
    private readonly int _maxConcurrency;
    private readonly CancellationTokenSource _disposeCts = new();
    private readonly ConcurrentDictionary<ushort, ITrojanMuxClientSession> _sessions = new();
    private readonly object _sessionSync = new();
    private readonly SemaphoreSlim _writeLock = new(1, 1);
    private readonly Task _receiveLoop;

    private int _activeSessions;
    private int _closed;
    private ushort _nextSessionId;
    private int _totalSessions;

    public TrojanMuxWorker(
        RuntimeClientConnection connection,
        int maxConcurrency,
        bool isReverseMux = false)
    {
        _connection = connection;
        _isReverseMux = isReverseMux;
        _maxConcurrency = maxConcurrency;
        _receiveLoop = RunReceiveLoopAsync();
    }

    public bool IsClosed => Volatile.Read(ref _closed) != 0 || _receiveLoop.IsCompleted;

    public bool CanAcceptMoreSessions()
        => !IsClosed &&
           (_maxConcurrency <= 0 || Volatile.Read(ref _activeSessions) < _maxConcurrency) &&
           Volatile.Read(ref _totalSessions) < TrojanMuxProtocol.MaxSessionCountPerConnection;

    public Task WaitClosedAsync(CancellationToken cancellationToken = default)
        => _receiveLoop.WaitAsync(cancellationToken);

    public async ValueTask<Stream> OpenTcpAsync(
        DispatchDestination destination,
        CancellationToken cancellationToken)
        => await OpenTcpAsync(destination, context: null, cancellationToken).ConfigureAwait(false);

    public async ValueTask<Stream> OpenTcpAsync(
        DispatchDestination destination,
        DispatchContext? context,
        CancellationToken cancellationToken)
    {
        var stream = new TrojanMuxTcpSessionStream(this);
        var sessionId = RegisterSession(stream);
        stream.Bind(sessionId);

        try
        {
            await WriteAsync(
                new TrojanMuxFrame
                {
                    SessionId = sessionId,
                    Status = TrojanMuxSessionStatus.New,
                    Target = new TrojanMuxFrameTarget(destination.Host, destination.Port, destination.Network),
                    Source = _isReverseMux
                        ? TrojanMuxProtocol.CreateEndpointTarget(context?.SourceEndPoint, DispatchNetwork.Tcp)
                        : null,
                    Local = _isReverseMux
                        ? TrojanMuxProtocol.CreateEndpointTarget(context?.LocalEndPoint, DispatchNetwork.Tcp)
                        : null
                },
                cancellationToken).ConfigureAwait(false);
            return stream;
        }
        catch
        {
            CompleteSession(sessionId, null);
            await stream.DisposeAsync().ConfigureAwait(false);
            throw;
        }
    }

    public ushort RegisterSession(ITrojanMuxClientSession session)
    {
        ArgumentNullException.ThrowIfNull(session);

        lock (_sessionSync)
        {
            if (!CanAcceptMoreSessions())
            {
                throw new InvalidOperationException("Mux worker is full or closed.");
            }

            for (var attempt = 0; attempt < ushort.MaxValue; attempt++)
            {
                _nextSessionId++;
                if (_nextSessionId == 0)
                {
                    _nextSessionId = 1;
                }

                if (_sessions.TryAdd(_nextSessionId, session))
                {
                    Interlocked.Increment(ref _activeSessions);
                    Interlocked.Increment(ref _totalSessions);
                    return _nextSessionId;
                }
            }
        }

        throw new InvalidOperationException("No mux session identifier is available.");
    }

    public async ValueTask WriteTcpPayloadAsync(
        ushort sessionId,
        ReadOnlyMemory<byte> payload,
        CancellationToken cancellationToken)
    {
        var remaining = payload;
        while (!remaining.IsEmpty)
        {
            var chunkLength = Math.Min(remaining.Length, TrojanMuxProtocol.MaxStreamChunkLength);
            var chunk = remaining[..chunkLength].ToArray();
            remaining = remaining[chunkLength..];

            await WriteAsync(
                new TrojanMuxFrame
                {
                    SessionId = sessionId,
                    Status = TrojanMuxSessionStatus.Keep,
                    Option = TrojanMuxFrameOption.Data,
                    Payload = chunk
                },
                cancellationToken).ConfigureAwait(false);
        }
    }

    public ValueTask WriteUdpPayloadAsync(
        ushort sessionId,
        DispatchDestination destination,
        ReadOnlyMemory<byte> payload,
        bool isNewSession,
        byte[] globalId,
        CancellationToken cancellationToken)
        => WriteUdpPayloadAsync(
            sessionId,
            destination,
            payload,
            isNewSession,
            globalId,
            context: null,
            cancellationToken);

    public ValueTask WriteUdpPayloadAsync(
        ushort sessionId,
        DispatchDestination destination,
        ReadOnlyMemory<byte> payload,
        bool isNewSession,
        byte[] globalId,
        DispatchContext? context,
        CancellationToken cancellationToken)
    {
        var includeReverseEndpoints = _isReverseMux && isNewSession;
        return WriteAsync(
            new TrojanMuxFrame
            {
                SessionId = sessionId,
                Status = isNewSession ? TrojanMuxSessionStatus.New : TrojanMuxSessionStatus.Keep,
                Option = TrojanMuxFrameOption.Data,
                Target = new TrojanMuxFrameTarget(destination.Host, destination.Port, destination.Network),
                Source = includeReverseEndpoints
                    ? TrojanMuxProtocol.CreateEndpointTarget(context?.SourceEndPoint, DispatchNetwork.Udp)
                    : null,
                Local = includeReverseEndpoints
                    ? TrojanMuxProtocol.CreateEndpointTarget(context?.LocalEndPoint, DispatchNetwork.Udp)
                    : null,
                GlobalId = includeReverseEndpoints ? Array.Empty<byte>() : globalId,
                Payload = payload.ToArray()
            },
            cancellationToken);
    }

    public async ValueTask CloseLocalSessionAsync(
        ushort sessionId,
        CancellationToken cancellationToken)
    {
        if (!_sessions.TryRemove(sessionId, out var session))
        {
            return;
        }

        Interlocked.Decrement(ref _activeSessions);
        session.Complete(null);

        try
        {
            await WriteAsync(
                new TrojanMuxFrame
                {
                    SessionId = sessionId,
                    Status = TrojanMuxSessionStatus.End
                },
                cancellationToken).ConfigureAwait(false);
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            throw;
        }
        catch
        {
        }
    }

    public async ValueTask DisposeAsync()
    {
        if (Interlocked.Exchange(ref _closed, 1) != 0)
        {
            return;
        }

        _disposeCts.Cancel();
        await _connection.DisposeAsync().ConfigureAwait(false);

        try
        {
            await _receiveLoop.ConfigureAwait(false);
        }
        catch (OperationCanceledException)
        {
        }

        _writeLock.Dispose();
        _disposeCts.Dispose();
    }

    private async ValueTask WriteAsync(
        TrojanMuxFrame frame,
        CancellationToken cancellationToken)
    {
        if (IsClosed)
        {
            throw new IOException("The mux worker is closed.");
        }

        await _writeLock.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            await TrojanMuxFrameCodec.WriteAsync(_connection.Stream, frame, cancellationToken).ConfigureAwait(false);
            await _connection.Stream.FlushAsync(cancellationToken).ConfigureAwait(false);
        }
        finally
        {
            _writeLock.Release();
        }
    }

    private async Task RunReceiveLoopAsync()
    {
        Exception? terminalError = null;

        try
        {
            while (!_disposeCts.IsCancellationRequested)
            {
                var frame = await TrojanMuxFrameCodec.ReadAsync(_connection.Stream, _disposeCts.Token).ConfigureAwait(false);
                if (frame is null)
                {
                    break;
                }

                if (frame.Status == TrojanMuxSessionStatus.KeepAlive)
                {
                    continue;
                }

                if (!_sessions.TryGetValue(frame.SessionId, out var session))
                {
                    if (frame.Status != TrojanMuxSessionStatus.End)
                    {
                        try
                        {
                            await WriteAsync(
                                new TrojanMuxFrame
                                {
                                    SessionId = frame.SessionId,
                                    Status = TrojanMuxSessionStatus.End
                                },
                                _disposeCts.Token).ConfigureAwait(false);
                        }
                        catch
                        {
                        }
                    }

                    continue;
                }

                if (frame.Status == TrojanMuxSessionStatus.End)
                {
                    CompleteSession(
                        frame.SessionId,
                        frame.HasError ? new IOException($"Mux session {frame.SessionId} terminated with a remote error.") : null);
                    continue;
                }

                session.OnFrame(frame);
            }
        }
        catch (OperationCanceledException) when (_disposeCts.IsCancellationRequested)
        {
        }
        catch (Exception ex)
        {
            terminalError = ex;
        }
        finally
        {
            Interlocked.Exchange(ref _closed, 1);
            foreach (var sessionId in _sessions.Keys.ToArray())
            {
                CompleteSession(sessionId, terminalError);
            }
        }
    }

    private void CompleteSession(ushort sessionId, Exception? exception)
    {
        if (_sessions.TryRemove(sessionId, out var session))
        {
            Interlocked.Decrement(ref _activeSessions);
            session.Complete(exception);
        }
    }
}

internal sealed class TrojanMuxTcpSessionStream : Stream, ITrojanMuxClientSession
{
    private readonly TrojanMuxWorker _worker;
    private readonly Channel<byte[]> _incoming = Channel.CreateUnbounded<byte[]>(
        new UnboundedChannelOptions
        {
            SingleReader = true,
            SingleWriter = false
        });

    private byte[]? _currentBuffer;
    private int _currentOffset;
    private int _disposed;
    private ushort _sessionId;

    public TrojanMuxTcpSessionStream(TrojanMuxWorker worker)
    {
        _worker = worker;
    }

    public override bool CanRead => Volatile.Read(ref _disposed) == 0;

    public override bool CanSeek => false;

    public override bool CanWrite => Volatile.Read(ref _disposed) == 0;

    public override long Length => throw new NotSupportedException();

    public override long Position
    {
        get => throw new NotSupportedException();
        set => throw new NotSupportedException();
    }

    public void Bind(ushort sessionId) => _sessionId = sessionId;

    public void OnFrame(TrojanMuxFrame frame)
    {
        if (frame.Payload.Length == 0)
        {
            return;
        }

        _incoming.Writer.TryWrite(frame.Payload);
    }

    public void Complete(Exception? exception)
        => _incoming.Writer.TryComplete(exception);

    public override void Flush()
    {
    }

    public override Task FlushAsync(CancellationToken cancellationToken) => Task.CompletedTask;

    public override int Read(byte[] buffer, int offset, int count)
        => ReadAsync(buffer.AsMemory(offset, count), CancellationToken.None).AsTask().GetAwaiter().GetResult();

    public override async ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken cancellationToken = default)
    {
        if (Volatile.Read(ref _disposed) != 0)
        {
            throw new ObjectDisposedException(nameof(TrojanMuxTcpSessionStream));
        }

        while (true)
        {
            if (_currentBuffer is not null && _currentOffset < _currentBuffer.Length)
            {
                var copied = Math.Min(buffer.Length, _currentBuffer.Length - _currentOffset);
                _currentBuffer.AsMemory(_currentOffset, copied).CopyTo(buffer);
                _currentOffset += copied;
                if (_currentOffset >= _currentBuffer.Length)
                {
                    _currentBuffer = null;
                    _currentOffset = 0;
                }

                return copied;
            }

            try
            {
                _currentBuffer = await _incoming.Reader.ReadAsync(cancellationToken).ConfigureAwait(false);
                _currentOffset = 0;
            }
            catch (ChannelClosedException ex) when (ex.InnerException is null)
            {
                return 0;
            }
            catch (ChannelClosedException ex)
            {
                throw new IOException("Mux TCP session closed unexpectedly.", ex.InnerException);
            }
        }
    }

    public override int Read(Span<byte> buffer)
    {
        var scratch = new byte[buffer.Length];
        var read = ReadAsync(scratch, CancellationToken.None).AsTask().GetAwaiter().GetResult();
        scratch.AsSpan(0, read).CopyTo(buffer);
        return read;
    }

    public override void Write(byte[] buffer, int offset, int count)
        => WriteAsync(buffer.AsMemory(offset, count), CancellationToken.None).AsTask().GetAwaiter().GetResult();

    public override void Write(ReadOnlySpan<byte> buffer)
        => WriteAsync(buffer.ToArray(), CancellationToken.None).AsTask().GetAwaiter().GetResult();

    public override async ValueTask WriteAsync(ReadOnlyMemory<byte> buffer, CancellationToken cancellationToken = default)
    {
        if (Volatile.Read(ref _disposed) != 0)
        {
            throw new ObjectDisposedException(nameof(TrojanMuxTcpSessionStream));
        }

        if (buffer.IsEmpty)
        {
            return;
        }

        await _worker.WriteTcpPayloadAsync(_sessionId, buffer, cancellationToken).ConfigureAwait(false);
    }

    public override Task WriteAsync(byte[] buffer, int offset, int count, CancellationToken cancellationToken)
        => WriteAsync(buffer.AsMemory(offset, count), cancellationToken).AsTask();

    public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();

    public override void SetLength(long value) => throw new NotSupportedException();

    protected override void Dispose(bool disposing)
    {
        if (disposing)
        {
            DisposeAsync().AsTask().GetAwaiter().GetResult();
        }
    }

    public override async ValueTask DisposeAsync()
    {
        if (Interlocked.Exchange(ref _disposed, 1) != 0)
        {
            return;
        }

        _incoming.Writer.TryComplete();
        try
        {
            await _worker.CloseLocalSessionAsync(_sessionId, CancellationToken.None).ConfigureAwait(false);
        }
        catch
        {
        }
    }
}

internal sealed class TrojanMuxUdpTransport : IOutboundUdpTransport, ITrojanMuxClientSession
{
    private readonly TrojanMuxWorkerPool _pool;
    private readonly DispatchContext _context;
    private readonly IDnsResolver _dnsResolver;
    private readonly Func<DispatchContext, CancellationToken, ValueTask<RuntimeClientConnection>> _openConnectionAsync;
    private readonly Channel<DispatchDatagram> _responses = Channel.CreateUnbounded<DispatchDatagram>(
        new UnboundedChannelOptions
        {
            SingleReader = true,
            SingleWriter = false
        });
    private readonly SemaphoreSlim _sendLock = new(1, 1);
    private readonly string _targetStrategy;
    private readonly byte[] _globalId;

    private int _disposed;
    private ushort _sessionId;
    private TrojanMuxWorker? _worker;

    public TrojanMuxUdpTransport(
        TrojanMuxWorkerPool pool,
        DispatchContext context,
        string targetStrategy,
        Func<DispatchContext, CancellationToken, ValueTask<RuntimeClientConnection>> openConnectionAsync,
        IDnsResolver dnsResolver,
        byte[] globalId)
    {
        _pool = pool;
        _context = context;
        _targetStrategy = targetStrategy;
        _openConnectionAsync = openConnectionAsync;
        _dnsResolver = dnsResolver;
        _globalId = globalId;
    }

    public async ValueTask SendAsync(
        DispatchDestination destination,
        ReadOnlyMemory<byte> payload,
        CancellationToken cancellationToken)
    {
        if (Volatile.Read(ref _disposed) != 0)
        {
            throw new ObjectDisposedException(nameof(TrojanMuxUdpTransport));
        }
        if (destination.Network != DispatchNetwork.Udp)
        {
            throw new NotSupportedException($"Mux UDP session does not support '{destination.Network}'.");
        }

        var resolvedDestination = await OutboundTargetStrategyResolver.ResolveAsync(
            _context,
            destination,
            _targetStrategy,
            _dnsResolver,
            cancellationToken).ConfigureAwait(false);

        await _sendLock.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            if (_sessionId == 0)
            {
                for (var attempt = 0; attempt < 4; attempt++)
                {
                    var worker = await EnsureWorkerAsync(cancellationToken).ConfigureAwait(false);
                    try
                    {
                        var sessionId = worker.RegisterSession(this);
                        await worker.WriteUdpPayloadAsync(
                            sessionId,
                            resolvedDestination,
                            payload,
                            isNewSession: true,
                            _globalId,
                            cancellationToken).ConfigureAwait(false);
                        _worker = worker;
                        _sessionId = sessionId;
                        return;
                    }
                    catch (InvalidOperationException) when (worker.IsClosed || !worker.CanAcceptMoreSessions())
                    {
                        if (ReferenceEquals(_worker, worker))
                        {
                            _worker = null;
                        }
                    }
                }

                    throw new InvalidOperationException("Unable to allocate a mux UDP session.");
            }

            await _worker!.WriteUdpPayloadAsync(
                _sessionId,
                resolvedDestination,
                payload,
                isNewSession: false,
                _globalId,
                cancellationToken).ConfigureAwait(false);
        }
        finally
        {
            _sendLock.Release();
        }
    }

    public async ValueTask<DispatchDatagram?> ReceiveAsync(CancellationToken cancellationToken)
    {
        if (Volatile.Read(ref _disposed) != 0)
        {
            throw new ObjectDisposedException(nameof(TrojanMuxUdpTransport));
        }

        try
        {
            return await _responses.Reader.ReadAsync(cancellationToken).ConfigureAwait(false);
        }
        catch (ChannelClosedException ex) when (ex.InnerException is null)
        {
            return null;
        }
        catch (ChannelClosedException ex)
        {
                throw new IOException("Mux UDP session closed unexpectedly.", ex.InnerException);
        }
    }

    public void OnFrame(TrojanMuxFrame frame)
    {
        if (frame.Payload.Length == 0 || frame.Target is null)
        {
            return;
        }

        _responses.Writer.TryWrite(
            new DispatchDatagram
            {
                SourceHost = frame.Target.Host,
                SourcePort = frame.Target.Port,
                Payload = frame.Payload
            });
    }

    public void Complete(Exception? exception)
        => _responses.Writer.TryComplete(exception);

    public async ValueTask DisposeAsync()
    {
        if (Interlocked.Exchange(ref _disposed, 1) != 0)
        {
            return;
        }

        _responses.Writer.TryComplete();
        if (_sessionId != 0 && _worker is not null)
        {
            try
            {
                await _worker.CloseLocalSessionAsync(_sessionId, CancellationToken.None).ConfigureAwait(false);
            }
            catch
            {
            }
        }

        _sendLock.Dispose();
    }

    private async ValueTask<TrojanMuxWorker> EnsureWorkerAsync(CancellationToken cancellationToken)
    {
        if (_worker is not null && !_worker.IsClosed)
        {
            return _worker;
        }

        _worker = await _pool.AcquireWorkerAsync(_context, _openConnectionAsync, cancellationToken).ConfigureAwait(false);
        return _worker;
    }
}

internal sealed class TrojanAdaptiveUdpTransport : IOutboundUdpTransport
{
    private readonly Func<IOutboundUdpTransport> _createDirectTransport;
    private readonly Func<IOutboundUdpTransport> _createMuxTransport;
    private readonly SemaphoreSlim _initializeLock = new(1, 1);
    private readonly TaskCompletionSource<IOutboundUdpTransport> _innerTransportTcs = new(TaskCreationOptions.RunContinuationsAsynchronously);
    private readonly string _udp443Mode;

    private int _disposed;

    public TrojanAdaptiveUdpTransport(
        Func<IOutboundUdpTransport> createDirectTransport,
        Func<IOutboundUdpTransport> createMuxTransport,
        string udp443Mode)
    {
        _createDirectTransport = createDirectTransport;
        _createMuxTransport = createMuxTransport;
        _udp443Mode = udp443Mode;
    }

    public async ValueTask SendAsync(
        DispatchDestination destination,
        ReadOnlyMemory<byte> payload,
        CancellationToken cancellationToken)
    {
        if (Volatile.Read(ref _disposed) != 0)
        {
            throw new ObjectDisposedException(nameof(TrojanAdaptiveUdpTransport));
        }

        var transport = await EnsureTransportAsync(destination, cancellationToken).ConfigureAwait(false);
        await transport.SendAsync(destination, payload, cancellationToken).ConfigureAwait(false);
    }

    public async ValueTask<DispatchDatagram?> ReceiveAsync(CancellationToken cancellationToken)
    {
        if (Volatile.Read(ref _disposed) != 0)
        {
            throw new ObjectDisposedException(nameof(TrojanAdaptiveUdpTransport));
        }

        var transport = await _innerTransportTcs.Task.WaitAsync(cancellationToken).ConfigureAwait(false);
        return await transport.ReceiveAsync(cancellationToken).ConfigureAwait(false);
    }

    public async ValueTask DisposeAsync()
    {
        if (Interlocked.Exchange(ref _disposed, 1) != 0)
        {
            return;
        }

        _innerTransportTcs.TrySetCanceled();
        if (_innerTransportTcs.Task.IsCompletedSuccessfully)
        {
            await _innerTransportTcs.Task.Result.DisposeAsync().ConfigureAwait(false);
        }

        _initializeLock.Dispose();
    }

    private async ValueTask<IOutboundUdpTransport> EnsureTransportAsync(
        DispatchDestination destination,
        CancellationToken cancellationToken)
    {
        if (_innerTransportTcs.Task.IsCompletedSuccessfully)
        {
            return await _innerTransportTcs.Task.WaitAsync(cancellationToken).ConfigureAwait(false);
        }

        await _initializeLock.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            if (_innerTransportTcs.Task.IsCompletedSuccessfully)
            {
                return await _innerTransportTcs.Task.WaitAsync(cancellationToken).ConfigureAwait(false);
            }

            if (destination.Port == 443 &&
                string.Equals(_udp443Mode, OutboundXudpProxyModes.Reject, StringComparison.Ordinal))
            {
                var exception = new InvalidOperationException("Multiplex rejected UDP/443 traffic.");
                _innerTransportTcs.TrySetException(exception);
                throw exception;
            }

            var transport = destination.Port == 443 &&
                            string.Equals(_udp443Mode, OutboundXudpProxyModes.Skip, StringComparison.Ordinal)
                ? _createDirectTransport()
                : _createMuxTransport();

            _innerTransportTcs.TrySetResult(transport);
            return transport;
        }
        finally
        {
            _initializeLock.Release();
        }
    }
}

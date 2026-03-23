using System.Net;
using System.Net.Sockets;
using System.Text;

namespace NodePanel.Core.Runtime;

public sealed class TrojanFallbackRelayService
{
    private const int FallbackDialAttempts = 5;
    private static readonly TimeSpan InitialFallbackRetryDelay = TimeSpan.FromMilliseconds(100);

    private readonly IDnsResolver _dnsResolver;
    private readonly RelayService _relayService;

    public TrojanFallbackRelayService(
        RelayService relayService,
        IDnsResolver? dnsResolver = null)
    {
        _relayService = relayService;
        _dnsResolver = dnsResolver ?? SystemDnsResolver.Instance;
    }

    public async Task<bool> TryHandleAsync(
        Stream clientStream,
        byte[] initialPayload,
        ITrojanInboundConnectionOptions options,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(clientStream);
        ArgumentNullException.ThrowIfNull(initialPayload);
        ArgumentNullException.ThrowIfNull(options);

        var fallback = TrojanFallbackSelector.Select(
            options.Fallbacks,
            options.ServerName,
            options.Alpn,
            initialPayload);
        if (fallback is null)
        {
            return false;
        }

        var networkType = NormalizeNetworkType(fallback.Type);
        using var connectCts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        connectCts.CancelAfter(TimeSpan.FromSeconds(options.ConnectTimeoutSeconds));
        await using var remoteStream = await OpenFallbackStreamAsync(networkType, fallback.Dest, connectCts.Token).ConfigureAwait(false);
        if (fallback.ProxyProtocolVersion is 1 or 2)
        {
            var proxyHeader = BuildProxyProtocolHeader(
                fallback.ProxyProtocolVersion,
                options.RemoteEndPoint,
                options.LocalEndPoint);
            await remoteStream.WriteAsync(proxyHeader.AsMemory(0, proxyHeader.Length), cancellationToken).ConfigureAwait(false);
        }

        await remoteStream.WriteAsync(initialPayload.AsMemory(0, initialPayload.Length), cancellationToken).ConfigureAwait(false);
        await remoteStream.FlushAsync(cancellationToken).ConfigureAwait(false);
        await _relayService.RelayAsync(clientStream, remoteStream, options, cancellationToken).ConfigureAwait(false);
        return true;
    }

    private async Task<Stream> OpenFallbackStreamAsync(string networkType, string destination, CancellationToken cancellationToken)
    {
        return networkType switch
        {
            "tcp" or "tcp4" or "tcp6" => await OpenTcpFallbackStreamWithRetryAsync(networkType, destination, cancellationToken).ConfigureAwait(false),
            "unix" => await OpenUnixFallbackStreamWithRetryAsync(destination, cancellationToken).ConfigureAwait(false),
            TrojanFallbackCompatibility.ServeNetworkType => throw new NotSupportedException("Trojan fallback transport type 'serve' is not supported by the current .NET runtime."),
            _ => throw new NotSupportedException($"Unsupported trojan fallback transport type: {networkType}.")
        };
    }

    private Task<Stream> OpenTcpFallbackStreamWithRetryAsync(
        string networkType,
        string destination,
        CancellationToken cancellationToken)
    {
        var parsedDestination = ParseTcpDestination(networkType, destination);
        return ConnectWithRetryAsync(
            token => OpenTcpFallbackStreamAsync(parsedDestination, token),
            cancellationToken);
    }

    private static Task<Stream> OpenUnixFallbackStreamWithRetryAsync(string destination, CancellationToken cancellationToken)
        => ConnectWithRetryAsync(
            token => OpenUnixFallbackStreamAsync(destination, token),
            cancellationToken);

    private static async Task<Stream> ConnectWithRetryAsync(
        Func<CancellationToken, Task<Stream>> connectAsync,
        CancellationToken cancellationToken)
    {
        Exception? lastError = null;
        var delay = InitialFallbackRetryDelay;

        for (var attempt = 0; attempt < FallbackDialAttempts; attempt++)
        {
            cancellationToken.ThrowIfCancellationRequested();

            try
            {
                return await connectAsync(cancellationToken).ConfigureAwait(false);
            }
            catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
            {
                throw;
            }
            catch (Exception ex) when (attempt < FallbackDialAttempts - 1)
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

        throw lastError ?? new IOException("Trojan fallback connection failed.");
    }

    private async Task<Stream> OpenTcpFallbackStreamAsync(
        FallbackTcpDestination destination,
        CancellationToken cancellationToken)
    {
        var endPoints = await OutboundSocketDialer.ResolveTcpEndPointsAsync(
            destination.Host,
            destination.Port,
            destination.AddressFamily,
            _dnsResolver,
            cancellationToken).ConfigureAwait(false);
        return await OutboundSocketDialer.OpenTcpStreamAsync(
            new DispatchContext(),
            via: null,
            viaCidr: null,
            endPoints,
            cancellationToken).ConfigureAwait(false);
    }

    private static async Task<Stream> OpenUnixFallbackStreamAsync(string destination, CancellationToken cancellationToken)
    {
        if (string.IsNullOrWhiteSpace(destination))
        {
            throw new InvalidDataException("Trojan fallback destination is empty.");
        }

        var socket = new Socket(AddressFamily.Unix, SocketType.Stream, ProtocolType.Unspecified);
        try
        {
            await socket.ConnectAsync(TrojanFallbackCompatibility.CreateUnixEndPoint(destination), cancellationToken).ConfigureAwait(false);
            return new NetworkStream(socket, ownsSocket: true);
        }
        catch
        {
            socket.Dispose();
            throw;
        }
    }

    private static FallbackTcpDestination ParseTcpDestination(string networkType, string value)
    {
        if (string.IsNullOrWhiteSpace(value))
        {
            throw new InvalidDataException("Trojan fallback destination is empty.");
        }

        var normalizedDestination = TrojanFallbackCompatibility.NormalizeDestination(networkType, value);
        if (!Uri.TryCreate($"{networkType}://{normalizedDestination}", UriKind.Absolute, out var uri) || uri.Port <= 0)
        {
            throw new InvalidDataException($"Trojan fallback destination is invalid: {value}.");
        }

        var family = networkType switch
        {
            "tcp4" => AddressFamily.InterNetwork,
            "tcp6" => AddressFamily.InterNetworkV6,
            _ => AddressFamily.Unspecified
        };

        return new FallbackTcpDestination(uri.Host, uri.Port, family);
    }

    private static byte[] BuildProxyProtocolHeader(int version, EndPoint? remoteEndPoint, EndPoint? localEndPoint)
    {
        var remote = remoteEndPoint as IPEndPoint;
        var local = localEndPoint as IPEndPoint;

        return version switch
        {
            1 => BuildProxyProtocolV1Header(remote, local),
            2 => BuildProxyProtocolV2Header(remote, local),
            _ => Array.Empty<byte>()
        };
    }

    private static byte[] BuildProxyProtocolV1Header(IPEndPoint? remote, IPEndPoint? local)
    {
        if (remote is null || local is null)
        {
            return Encoding.ASCII.GetBytes("PROXY UNKNOWN\r\n");
        }

        var protocol = remote.AddressFamily == AddressFamily.InterNetworkV6 || local.AddressFamily == AddressFamily.InterNetworkV6
            ? "TCP6"
            : "TCP4";

        return Encoding.ASCII.GetBytes($"PROXY {protocol} {remote.Address} {local.Address} {remote.Port} {local.Port}\r\n");
    }

    private static byte[] BuildProxyProtocolV2Header(IPEndPoint? remote, IPEndPoint? local)
    {
        using var stream = new MemoryStream(64);
        stream.Write(new byte[] { 0x0D, 0x0A, 0x0D, 0x0A, 0x00, 0x0D, 0x0A, 0x51, 0x55, 0x49, 0x54, 0x0A });

        if (remote is null || local is null)
        {
            stream.Write(new byte[] { 0x20, 0x00, 0x00, 0x00 });
            return stream.ToArray();
        }

        if (remote.AddressFamily == AddressFamily.InterNetwork && local.AddressFamily == AddressFamily.InterNetwork)
        {
            stream.Write(new byte[] { 0x21, 0x11, 0x00, 0x0C });
            stream.Write(remote.Address.GetAddressBytes());
            stream.Write(local.Address.GetAddressBytes());
        }
        else
        {
            stream.Write(new byte[] { 0x21, 0x21, 0x00, 0x24 });
            stream.Write(remote.Address.MapToIPv6().GetAddressBytes());
            stream.Write(local.Address.MapToIPv6().GetAddressBytes());
        }

        stream.WriteByte((byte)(remote.Port >> 8));
        stream.WriteByte((byte)(remote.Port & 0xff));
        stream.WriteByte((byte)(local.Port >> 8));
        stream.WriteByte((byte)(local.Port & 0xff));
        return stream.ToArray();
    }

    private static string NormalizeNetworkType(string value)
        => string.IsNullOrWhiteSpace(value) ? TrojanFallbackCompatibility.DefaultNetworkType : value.Trim().ToLowerInvariant();

    private sealed record FallbackTcpDestination(string Host, int Port, AddressFamily AddressFamily);
}

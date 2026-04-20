using System.Net;
using System.Net.Sockets;
using System.Runtime.InteropServices;

namespace NodePanel.Core.Runtime;

public interface IDokodemoUdpRedirectSupport
{
    void ConfigureListener(Socket socket);

    ValueTask<DokodemoUdpReceiveResult> ReceiveAsync(
        Socket socket,
        Memory<byte> buffer,
        CancellationToken cancellationToken);

    IDokodemoUdpResponseWriter CreateResponseWriter(
        Socket listenerSocket,
        IPEndPoint listenerLocalEndPoint,
        IPEndPoint remoteEndPoint,
        IPEndPoint originalDestinationEndPoint,
        int mark);
}

public interface IDokodemoUdpResponseWriter : IAsyncDisposable
{
    ValueTask SendAsync(DispatchDatagram datagram, CancellationToken cancellationToken);
}

public readonly record struct DokodemoUdpReceiveResult(
    int ReceivedBytes,
    IPEndPoint RemoteEndPoint,
    IPEndPoint LocalEndPoint,
    IPEndPoint? OriginalDestinationEndPoint);

internal sealed class DefaultDokodemoUdpRedirectSupport : IDokodemoUdpRedirectSupport
{
    public void ConfigureListener(Socket socket)
    {
        ArgumentNullException.ThrowIfNull(socket);

        try
        {
            socket.SetSocketOption(
                socket.AddressFamily == AddressFamily.InterNetworkV6
                    ? SocketOptionLevel.IPv6
                    : SocketOptionLevel.IP,
                SocketOptionName.PacketInformation,
                true);
        }
        catch (PlatformNotSupportedException)
        {
        }
        catch (NotSupportedException)
        {
        }
        catch (SocketException)
        {
        }
    }

    public async ValueTask<DokodemoUdpReceiveResult> ReceiveAsync(
        Socket socket,
        Memory<byte> buffer,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(socket);

        var listenerLocalEndPoint = socket.LocalEndPoint as IPEndPoint
            ?? throw new InvalidOperationException("Dokodemo-door UDP socket is not using an IP endpoint.");
        var placeholder = CreateReceivePlaceholder(socket.AddressFamily);

        try
        {
            var received = await socket.ReceiveMessageFromAsync(
                buffer,
                SocketFlags.None,
                placeholder,
                cancellationToken).ConfigureAwait(false);
            if (received.RemoteEndPoint is not IPEndPoint remoteEndPoint)
            {
                throw new InvalidOperationException("Dokodemo-door UDP inbound requires an IP remote endpoint.");
            }

            var originalDestinationEndPoint = ResolveOriginalDestination(
                listenerLocalEndPoint,
                received.PacketInformation);
            return new DokodemoUdpReceiveResult(
                received.ReceivedBytes,
                Normalize(remoteEndPoint),
                originalDestinationEndPoint ?? Normalize(listenerLocalEndPoint),
                originalDestinationEndPoint);
        }
        catch (NotSupportedException)
        {
            return await ReceiveFallbackAsync(socket, buffer, listenerLocalEndPoint, placeholder, cancellationToken)
                .ConfigureAwait(false);
        }
        catch (SocketException ex) when (ex.SocketErrorCode == SocketError.OperationNotSupported)
        {
            return await ReceiveFallbackAsync(socket, buffer, listenerLocalEndPoint, placeholder, cancellationToken)
                .ConfigureAwait(false);
        }
    }

    public IDokodemoUdpResponseWriter CreateResponseWriter(
        Socket listenerSocket,
        IPEndPoint listenerLocalEndPoint,
        IPEndPoint remoteEndPoint,
        IPEndPoint originalDestinationEndPoint,
        int mark)
        => new DefaultDokodemoUdpResponseWriter(
            listenerSocket,
            listenerLocalEndPoint,
            remoteEndPoint,
            originalDestinationEndPoint,
            mark);

    private static async ValueTask<DokodemoUdpReceiveResult> ReceiveFallbackAsync(
        Socket socket,
        Memory<byte> buffer,
        IPEndPoint listenerLocalEndPoint,
        EndPoint placeholder,
        CancellationToken cancellationToken)
    {
        var received = await socket.ReceiveFromAsync(
            buffer,
            SocketFlags.None,
            placeholder,
            cancellationToken).ConfigureAwait(false);
        if (received.RemoteEndPoint is not IPEndPoint remoteEndPoint)
        {
            throw new InvalidOperationException("Dokodemo-door UDP inbound requires an IP remote endpoint.");
        }

        var normalizedLocal = Normalize(listenerLocalEndPoint);
        var originalDestinationEndPoint = IsUnspecified(normalizedLocal.Address)
            ? null
            : normalizedLocal;
        return new DokodemoUdpReceiveResult(
            received.ReceivedBytes,
            Normalize(remoteEndPoint),
            normalizedLocal,
            originalDestinationEndPoint);
    }

    private static IPEndPoint? ResolveOriginalDestination(
        IPEndPoint listenerLocalEndPoint,
        IPPacketInformation packetInformation)
    {
        var destinationAddress = packetInformation.Address;
        if (destinationAddress is not null &&
            !IsUnspecified(destinationAddress))
        {
            return new IPEndPoint(Normalize(destinationAddress), listenerLocalEndPoint.Port);
        }

        var normalizedListener = Normalize(listenerLocalEndPoint);
        return IsUnspecified(normalizedListener.Address)
            ? null
            : normalizedListener;
    }

    private static EndPoint CreateReceivePlaceholder(AddressFamily addressFamily)
        => addressFamily == AddressFamily.InterNetworkV6
            ? new IPEndPoint(IPAddress.IPv6Any, 0)
            : new IPEndPoint(IPAddress.Any, 0);

    private static IPEndPoint Normalize(IPEndPoint endPoint)
        => new(Normalize(endPoint.Address), endPoint.Port);

    private static IPAddress Normalize(IPAddress address)
        => address.IsIPv4MappedToIPv6 ? address.MapToIPv4() : address;

    private static bool IsUnspecified(IPAddress address)
        => Normalize(address) switch
        {
            var value when value.Equals(IPAddress.Any) => true,
            var value when value.Equals(IPAddress.IPv6Any) => true,
            _ => false
        };
}

internal sealed class DefaultDokodemoUdpResponseWriter : IDokodemoUdpResponseWriter
{
    private const int SolIp = 0;
    private const int SolSocket = 1;
    private const int IpTransparent = 19;
    private const int SoReusePort = 15;
    private const int SoMark = 36;

    private readonly IPEndPoint _defaultSourceEndPoint;
    private readonly Socket _listenerSocket;
    private readonly IPEndPoint _listenerLocalEndPoint;
    private readonly IPEndPoint _remoteEndPoint;
    private readonly int _mark;
    private readonly SemaphoreSlim _sendLock = new(1, 1);
    private readonly Lock _sync = new();
    private readonly Dictionary<string, Socket> _sockets = new(StringComparer.Ordinal);

    private int _disposed;

    public DefaultDokodemoUdpResponseWriter(
        Socket listenerSocket,
        IPEndPoint listenerLocalEndPoint,
        IPEndPoint remoteEndPoint,
        IPEndPoint originalDestinationEndPoint,
        int mark)
    {
        _listenerSocket = listenerSocket ?? throw new ArgumentNullException(nameof(listenerSocket));
        _listenerLocalEndPoint = Normalize(listenerLocalEndPoint ?? throw new ArgumentNullException(nameof(listenerLocalEndPoint)));
        _remoteEndPoint = Normalize(remoteEndPoint ?? throw new ArgumentNullException(nameof(remoteEndPoint)));
        _defaultSourceEndPoint = Normalize(originalDestinationEndPoint ?? throw new ArgumentNullException(nameof(originalDestinationEndPoint)));
        _mark = Math.Max(0, mark);
    }

    public async ValueTask SendAsync(DispatchDatagram datagram, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(datagram);
        ThrowIfDisposed();

        var sourceEndPoint = ResolveSourceEndPoint(datagram) ?? _defaultSourceEndPoint;
        var socket = GetOrCreateSocket(sourceEndPoint);
        await _sendLock.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            ThrowIfDisposed();
            try
            {
                await socket.SendToAsync(
                    datagram.Payload,
                    SocketFlags.None,
                    _remoteEndPoint,
                    cancellationToken).ConfigureAwait(false);
            }
            catch (ObjectDisposedException) when (!ReferenceEquals(socket, _listenerSocket))
            {
                InvalidateSocket(sourceEndPoint, socket);
            }
            catch (SocketException) when (!ReferenceEquals(socket, _listenerSocket))
            {
                InvalidateSocket(sourceEndPoint, socket);
            }
        }
        finally
        {
            _sendLock.Release();
        }
    }

    public async ValueTask DisposeAsync()
    {
        if (Interlocked.Exchange(ref _disposed, 1) != 0)
        {
            return;
        }

        Socket[] sockets;
        await _sendLock.WaitAsync(CancellationToken.None).ConfigureAwait(false);
        try
        {
            lock (_sync)
            {
                sockets = _sockets.Values.ToArray();
                _sockets.Clear();
            }
        }
        finally
        {
            _sendLock.Release();
        }

        foreach (var socket in sockets)
        {
            socket.Dispose();
        }

        _sendLock.Dispose();
    }

    private Socket GetOrCreateSocket(IPEndPoint localEndPoint)
    {
        var normalized = Normalize(localEndPoint);
        if (ShouldUseListenerSocket(normalized))
        {
            return _listenerSocket;
        }

        var key = normalized.Address + ":" + normalized.Port.ToString();
        lock (_sync)
        {
            if (_sockets.TryGetValue(key, out var existing))
            {
                return existing;
            }
        }

        try
        {
            var created = CreateSocket(normalized, _mark);

            lock (_sync)
            {
                if (_sockets.TryGetValue(key, out var existing))
                {
                    created.Dispose();
                    return existing;
                }

                _sockets[key] = created;
                return created;
            }
        }
        catch
        {
            return _listenerSocket;
        }
    }

    private bool ShouldUseListenerSocket(IPEndPoint localEndPoint)
        => localEndPoint.Port == _listenerLocalEndPoint.Port &&
           (EndpointsEqual(localEndPoint, _listenerLocalEndPoint) ||
            IsUnspecified(_listenerLocalEndPoint.Address));

    private void InvalidateSocket(IPEndPoint localEndPoint, Socket socket)
    {
        var key = GetSocketKey(Normalize(localEndPoint));
        lock (_sync)
        {
            if (_sockets.TryGetValue(key, out var current) &&
                ReferenceEquals(current, socket))
            {
                _sockets.Remove(key);
            }
        }

        try
        {
            socket.Dispose();
        }
        catch
        {
        }
    }

    private static IPEndPoint? ResolveSourceEndPoint(DispatchDatagram datagram)
    {
        if (datagram.SourcePort is <= 0 or > 65535 ||
            !IPAddress.TryParse(datagram.SourceHost, out var address))
        {
            return null;
        }

        return new IPEndPoint(Normalize(address), datagram.SourcePort);
    }

    private static bool EndpointsEqual(IPEndPoint left, IPEndPoint right)
        => left.Port == right.Port &&
           Normalize(left.Address).Equals(Normalize(right.Address));

    private static string GetSocketKey(IPEndPoint endPoint)
        => endPoint.Address + ":" + endPoint.Port.ToString();

    private static Socket CreateSocket(IPEndPoint localEndPoint, int mark)
    {
        var socket = new Socket(localEndPoint.AddressFamily, SocketType.Dgram, ProtocolType.Udp);
        try
        {
            ConfigureSocket(socket, mark);
            socket.Bind(localEndPoint);
            return socket;
        }
        catch
        {
            socket.Dispose();
            throw;
        }
    }

    private static void ConfigureSocket(Socket socket, int mark)
    {
        if (!OperatingSystem.IsLinux())
        {
            return;
        }

        try
        {
            socket.SetSocketOption(SocketOptionLevel.Socket, SocketOptionName.ReuseAddress, true);
        }
        catch
        {
        }

        TrySetSocketOption(socket.Handle, SolSocket, SoReusePort, optionValue: 1);
        TrySetSocketOption(socket.Handle, SolIp, IpTransparent, optionValue: 1);
        if (mark > 0)
        {
            TrySetSocketOption(socket.Handle, SolSocket, SoMark, optionValue: mark);
        }
    }

    private static void TrySetSocketOption(IntPtr handle, int level, int optionName, int optionValue)
    {
        if (handle == IntPtr.Zero)
        {
            return;
        }

        try
        {
            _ = SetSockOpt(checked((int)handle), level, optionName, ref optionValue, sizeof(int));
        }
        catch
        {
        }
    }

    private static IPEndPoint Normalize(IPEndPoint endPoint)
        => new(Normalize(endPoint.Address), endPoint.Port);

    private static IPAddress Normalize(IPAddress address)
        => address.IsIPv4MappedToIPv6 ? address.MapToIPv4() : address;

    private static bool IsUnspecified(IPAddress address)
        => Normalize(address) switch
        {
            var value when value.Equals(IPAddress.Any) => true,
            var value when value.Equals(IPAddress.IPv6Any) => true,
            _ => false
        };

    private void ThrowIfDisposed()
    {
        if (Volatile.Read(ref _disposed) != 0)
        {
            throw new ObjectDisposedException(nameof(DefaultDokodemoUdpResponseWriter));
        }
    }

    [DllImport("libc", SetLastError = true, EntryPoint = "setsockopt")]
    private static extern int SetSockOpt(
        int socket,
        int level,
        int optionName,
        ref int optionValue,
        uint optionLength);
}

using System.Buffers.Binary;
using System.Net;
using System.Net.Sockets;
using System.Runtime.InteropServices;

namespace NodePanel.Core.Runtime;

internal static partial class OriginalTcpDestinationResolver
{
    private const int SoOriginalDst = 80;
    private const int SolIp = 0;
    private const int SolIpv6 = 41;

    public static bool TryResolve(Socket? socket, out IPEndPoint? endPoint)
    {
        endPoint = null;
        if (socket is null || !OperatingSystem.IsLinux())
        {
            return false;
        }

        var handle = socket.Handle;
        if (handle == IntPtr.Zero)
        {
            return false;
        }

        return TryResolve(handle, SolIp, AddressFamily.InterNetwork, out endPoint) ||
               TryResolve(handle, SolIpv6, AddressFamily.InterNetworkV6, out endPoint);
    }

    private static bool TryResolve(
        IntPtr handle,
        int level,
        AddressFamily addressFamily,
        out IPEndPoint? endPoint)
    {
        var buffer = new byte[addressFamily == AddressFamily.InterNetworkV6 ? 28 : 16];
        var optionLength = (uint)buffer.Length;
        if (GetSockOpt(checked((int)handle), level, SoOriginalDst, buffer, ref optionLength) != 0)
        {
            endPoint = null;
            return false;
        }

        return addressFamily == AddressFamily.InterNetwork
            ? TryParseIpv4(buffer, out endPoint)
            : TryParseIpv6(buffer, out endPoint);
    }

    private static bool TryParseIpv4(ReadOnlySpan<byte> buffer, out IPEndPoint? endPoint)
    {
        endPoint = null;
        if (buffer.Length < 8 || BinaryPrimitives.ReadUInt16LittleEndian(buffer[..2]) != (ushort)AddressFamily.InterNetwork)
        {
            return false;
        }

        var port = BinaryPrimitives.ReadUInt16BigEndian(buffer.Slice(2, 2));
        endPoint = new IPEndPoint(new IPAddress(buffer.Slice(4, 4)), port);
        return true;
    }

    private static bool TryParseIpv6(ReadOnlySpan<byte> buffer, out IPEndPoint? endPoint)
    {
        endPoint = null;
        if (buffer.Length < 28 || BinaryPrimitives.ReadUInt16LittleEndian(buffer[..2]) != (ushort)AddressFamily.InterNetworkV6)
        {
            return false;
        }

        var port = BinaryPrimitives.ReadUInt16BigEndian(buffer.Slice(2, 2));
        var addressBytes = buffer.Slice(8, 16).ToArray();
        var scopeId = BinaryPrimitives.ReadUInt32LittleEndian(buffer.Slice(24, 4));
        endPoint = new IPEndPoint(new IPAddress(addressBytes, scopeId), port);
        return true;
    }

    [DllImport("libc", SetLastError = true, EntryPoint = "getsockopt")]
    private static extern int GetSockOpt(
        int socket,
        int level,
        int optionName,
        byte[] optionValue,
        ref uint optionLength);
}

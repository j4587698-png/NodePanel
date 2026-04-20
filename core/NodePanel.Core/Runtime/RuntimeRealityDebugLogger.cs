using System.Net;
using System.Net.Sockets;

namespace NodePanel.Core.Runtime;

internal static class RuntimeRealityDebugLogger
{
    public static void TryWriteLine(bool enabled, string message)
    {
        if (!enabled ||
            string.IsNullOrWhiteSpace(message))
        {
            return;
        }

        try
        {
            Console.WriteLine(message);
        }
        catch (IOException)
        {
        }
    }

    public static string DescribeLocalEndPoint(Stream stream)
    {
        ArgumentNullException.ThrowIfNull(stream);

        var current = stream;
        while (current is IInnerStreamAccessor accessor)
        {
            current = accessor.InnerStream;
        }

        return current is NetworkStream networkStream &&
               networkStream.Socket.LocalEndPoint is EndPoint localEndPoint
            ? localEndPoint.ToString() ?? "unknown"
            : "unknown";
    }

    public static string FormatHexPrefix(ReadOnlySpan<byte> bytes, int length)
    {
        if (length <= 0 || bytes.Length == 0)
        {
            return string.Empty;
        }

        return Convert.ToHexString(bytes[..Math.Min(length, bytes.Length)]);
    }
}

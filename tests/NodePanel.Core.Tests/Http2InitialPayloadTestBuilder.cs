using System.Text;

namespace NodePanel.Core.Tests;

internal static class Http2InitialPayloadTestBuilder
{
    private const byte SettingsFrameType = 0x4;
    private const byte HeadersFrameType = 0x1;
    private const byte EndHeadersFlag = 0x4;
    private static readonly byte[] ClientConnectionPreface = "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"u8.ToArray();

    public static byte[] BuildPrefaceOnly()
    {
        using var buffer = new MemoryStream();
        buffer.Write(ClientConnectionPreface, 0, ClientConnectionPreface.Length);
        return buffer.ToArray();
    }

    public static byte[] BuildRequestInitialPayload(
        string method,
        string path,
        string authority = "edge.example.com",
        string scheme = "https")
    {
        using var buffer = new MemoryStream();
        buffer.Write(ClientConnectionPreface, 0, ClientConnectionPreface.Length);
        WriteFrame(buffer, SettingsFrameType, flags: 0, streamId: 0, payload: Array.Empty<byte>());
        WriteFrame(
            buffer,
            HeadersFrameType,
            flags: EndHeadersFlag,
            streamId: 1,
            payload: BuildRequestHeaderBlock(method, authority, scheme, path));
        return buffer.ToArray();
    }

    private static byte[] BuildRequestHeaderBlock(
        string method,
        string authority,
        string scheme,
        string path)
    {
        using var buffer = new MemoryStream(128);
        WriteLiteralHeaderFieldWithoutIndexing(buffer, nameIndex: 2, name: null, value: method.Trim().ToUpperInvariant());
        WriteLiteralHeaderFieldWithoutIndexing(buffer, nameIndex: 1, name: null, value: authority);
        WriteLiteralHeaderFieldWithoutIndexing(buffer, nameIndex: 6, name: null, value: scheme);
        WriteLiteralHeaderFieldWithoutIndexing(buffer, nameIndex: 4, name: null, value: path);
        return buffer.ToArray();
    }

    private static void WriteFrame(
        MemoryStream stream,
        byte type,
        byte flags,
        int streamId,
        byte[] payload)
    {
        var header = new byte[9];
        header[0] = (byte)((payload.Length >> 16) & 0xFF);
        header[1] = (byte)((payload.Length >> 8) & 0xFF);
        header[2] = (byte)(payload.Length & 0xFF);
        header[3] = type;
        header[4] = flags;
        header[5] = (byte)((streamId >> 24) & 0x7F);
        header[6] = (byte)((streamId >> 16) & 0xFF);
        header[7] = (byte)((streamId >> 8) & 0xFF);
        header[8] = (byte)(streamId & 0xFF);

        stream.Write(header, 0, header.Length);
        if (payload.Length > 0)
        {
            stream.Write(payload, 0, payload.Length);
        }
    }

    private static void WriteLiteralHeaderFieldWithoutIndexing(
        MemoryStream buffer,
        int nameIndex,
        string? name,
        string value)
    {
        WriteInteger(buffer, nameIndex, prefixBits: 4, prefixMask: 0x00);
        if (nameIndex == 0)
        {
            WriteString(buffer, name ?? string.Empty);
        }

        WriteString(buffer, value);
    }

    private static void WriteInteger(MemoryStream buffer, int value, int prefixBits, byte prefixMask)
    {
        var maxPrefixValue = (1 << prefixBits) - 1;
        if (value < maxPrefixValue)
        {
            buffer.WriteByte((byte)(prefixMask | value));
            return;
        }

        buffer.WriteByte((byte)(prefixMask | maxPrefixValue));
        var remaining = value - maxPrefixValue;
        while (remaining >= 128)
        {
            buffer.WriteByte((byte)((remaining % 128) + 128));
            remaining /= 128;
        }

        buffer.WriteByte((byte)remaining);
    }

    private static void WriteString(MemoryStream buffer, string value)
    {
        var bytes = Encoding.UTF8.GetBytes(value);
        WriteInteger(buffer, bytes.Length, prefixBits: 7, prefixMask: 0x00);
        buffer.Write(bytes, 0, bytes.Length);
    }
}

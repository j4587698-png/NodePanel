using System.Text;

namespace NodePanel.Core.Runtime;

internal static class RuntimeHttp2RequestProbe
{
    private const byte HeadersFrameType = 0x1;
    private const byte ContinuationFrameType = 0x9;
    private const byte EndHeadersFlag = 0x4;
    private const byte PaddedFlag = 0x8;
    private const byte PriorityFlag = 0x20;
    private static readonly byte[] ClientConnectionPreface = "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"u8.ToArray();

    public static bool LooksLikeConnectionPreface(ReadOnlySpan<byte> initialPayload)
        => initialPayload.Length >= ClientConnectionPreface.Length &&
           initialPayload[..ClientConnectionPreface.Length].SequenceEqual(ClientConnectionPreface);

    public static bool TryExtractRequestPath(
        ReadOnlySpan<byte> initialPayload,
        out string path)
        => TryExtractHeaderValue(initialPayload, ":path", out path);

    private static bool TryExtractHeaderValue(
        ReadOnlySpan<byte> initialPayload,
        string headerName,
        out string value)
    {
        value = string.Empty;
        if (!LooksLikeConnectionPreface(initialPayload))
        {
            return false;
        }

        try
        {
            var headerBlock = TryReadFirstRequestHeaderBlock(initialPayload);
            return headerBlock.Length != 0 &&
                   TryReadHeaderValue(headerBlock, headerName, out value);
        }
        catch (InvalidDataException)
        {
            return false;
        }
    }

    private static byte[] TryReadFirstRequestHeaderBlock(ReadOnlySpan<byte> initialPayload)
    {
        var offset = ClientConnectionPreface.Length;
        while (offset + 9 <= initialPayload.Length)
        {
            var payloadLength = ReadFramePayloadLength(initialPayload[offset..]);
            var frameType = initialPayload[offset + 3];
            var frameFlags = initialPayload[offset + 4];
            var streamId = ReadFrameStreamId(initialPayload[offset..]);
            offset += 9;

            if (offset + payloadLength > initialPayload.Length)
            {
                return Array.Empty<byte>();
            }

            var payload = initialPayload.Slice(offset, payloadLength);
            offset += payloadLength;

            if (frameType != HeadersFrameType || streamId == 0)
            {
                continue;
            }

            using var headerBlock = new MemoryStream(payload.Length + 64);
            AppendHeadersPayload(headerBlock, payload, frameFlags);

            while ((frameFlags & EndHeadersFlag) == 0)
            {
                if (offset + 9 > initialPayload.Length)
                {
                    return Array.Empty<byte>();
                }

                payloadLength = ReadFramePayloadLength(initialPayload[offset..]);
                frameType = initialPayload[offset + 3];
                frameFlags = initialPayload[offset + 4];
                var continuationStreamId = ReadFrameStreamId(initialPayload[offset..]);
                offset += 9;

                if (frameType != ContinuationFrameType ||
                    continuationStreamId != streamId ||
                    offset + payloadLength > initialPayload.Length)
                {
                    return Array.Empty<byte>();
                }

                headerBlock.Write(initialPayload.Slice(offset, payloadLength));
                offset += payloadLength;
            }

            return headerBlock.ToArray();
        }

        return Array.Empty<byte>();
    }

    private static void AppendHeadersPayload(
        MemoryStream destination,
        ReadOnlySpan<byte> payload,
        byte frameFlags)
    {
        var start = 0;
        var end = payload.Length;

        if ((frameFlags & PaddedFlag) == PaddedFlag)
        {
            if (payload.Length == 0)
            {
                throw new InvalidDataException("HTTP/2 PADDED frame payload is empty.");
            }

            var paddingLength = payload[0];
            start++;
            end -= paddingLength;
        }

        if ((frameFlags & PriorityFlag) == PriorityFlag)
        {
            start += 5;
        }

        if (start > end || end > payload.Length)
        {
            throw new InvalidDataException("HTTP/2 HEADERS frame padding is invalid.");
        }

        if (end > start)
        {
            destination.Write(payload[start..end]);
        }
    }

    private static bool TryReadHeaderValue(
        ReadOnlySpan<byte> headerBlock,
        string headerName,
        out string headerValue)
    {
        headerValue = string.Empty;
        var offset = 0;

        while (offset < headerBlock.Length)
        {
            var first = headerBlock[offset];
            if ((first & 0x80) != 0)
            {
                var index = ReadHpackInteger(headerBlock, ref offset, 7);
                if (TryResolveStaticHeader(index, out var indexedHeader) &&
                    string.Equals(indexedHeader.Name, headerName, StringComparison.Ordinal))
                {
                    headerValue = indexedHeader.Value;
                    return true;
                }

                continue;
            }

            if ((first & 0xE0) == 0x20)
            {
                _ = ReadHpackInteger(headerBlock, ref offset, 5);
                continue;
            }

            var nameIndex = ReadHpackInteger(headerBlock, ref offset, (first & 0x40) != 0 ? 6 : 4);
            var currentName = nameIndex == 0
                ? ReadHpackString(headerBlock, ref offset)
                : TryResolveStaticHeader(nameIndex, out var literalHeader)
                    ? literalHeader.Name
                    : string.Empty;
            var currentValue = ReadHpackString(headerBlock, ref offset);
            if (string.Equals(currentName, headerName, StringComparison.Ordinal))
            {
                headerValue = currentValue;
                return true;
            }
        }

        return false;
    }

    private static int ReadFramePayloadLength(ReadOnlySpan<byte> header)
        => (header[0] << 16) | (header[1] << 8) | header[2];

    private static int ReadFrameStreamId(ReadOnlySpan<byte> header)
        => ((header[5] & 0x7F) << 24) |
           (header[6] << 16) |
           (header[7] << 8) |
           header[8];

    private static int ReadHpackInteger(
        ReadOnlySpan<byte> buffer,
        ref int offset,
        int prefixBits)
    {
        if (offset >= buffer.Length)
        {
            throw new InvalidDataException("HPACK integer exceeded the available header block bytes.");
        }

        var maxPrefixValue = (1 << prefixBits) - 1;
        var value = buffer[offset] & maxPrefixValue;
        offset++;

        if (value < maxPrefixValue)
        {
            return value;
        }

        var shift = 0;
        while (true)
        {
            if (offset >= buffer.Length)
            {
                throw new InvalidDataException("HPACK integer exceeded the available header block bytes.");
            }

            var next = buffer[offset++];
            value += (next & 0x7F) << shift;
            if ((next & 0x80) == 0)
            {
                return value;
            }

            shift += 7;
        }
    }

    private static string ReadHpackString(ReadOnlySpan<byte> buffer, ref int offset)
    {
        if (offset >= buffer.Length)
        {
            throw new InvalidDataException("HPACK string literal exceeded the available header block bytes.");
        }

        var huffmanEncoded = (buffer[offset] & 0x80) != 0;
        var length = ReadHpackInteger(buffer, ref offset, 7);
        if (length < 0 || offset + length > buffer.Length)
        {
            throw new InvalidDataException("HPACK string literal exceeded the available header block bytes.");
        }

        var valueSlice = buffer.Slice(offset, length);
        offset += length;
        return huffmanEncoded
            ? RuntimeHpackHuffman.DecodeToUtf8String(valueSlice)
            : Encoding.UTF8.GetString(valueSlice);
    }

    private static bool TryResolveStaticHeader(int index, out Http2StaticHeader header)
    {
        header = default;
        if (index <= 0 || index >= Http2StaticHeaders.Length)
        {
            return false;
        }

        header = Http2StaticHeaders[index];
        return true;
    }

    private readonly record struct Http2StaticHeader(string Name, string Value);

    private static readonly Http2StaticHeader[] Http2StaticHeaders =
    [
        default,
        new(":authority", string.Empty),
        new(":method", "GET"),
        new(":method", "POST"),
        new(":path", "/"),
        new(":path", "/index.html"),
        new(":scheme", "http"),
        new(":scheme", "https"),
        new(":status", "200"),
        new(":status", "204"),
        new(":status", "206"),
        new(":status", "304"),
        new(":status", "400"),
        new(":status", "404"),
        new(":status", "500"),
        new("accept-charset", string.Empty),
        new("accept-encoding", "gzip, deflate"),
        new("accept-language", string.Empty),
        new("accept-ranges", string.Empty),
        new("accept", string.Empty),
        new("access-control-allow-origin", string.Empty),
        new("age", string.Empty),
        new("allow", string.Empty),
        new("authorization", string.Empty),
        new("cache-control", string.Empty),
        new("content-disposition", string.Empty),
        new("content-encoding", string.Empty),
        new("content-language", string.Empty),
        new("content-length", string.Empty),
        new("content-location", string.Empty),
        new("content-range", string.Empty),
        new("content-type", string.Empty),
        new("cookie", string.Empty),
        new("date", string.Empty),
        new("etag", string.Empty),
        new("expect", string.Empty),
        new("expires", string.Empty),
        new("from", string.Empty),
        new("host", string.Empty),
        new("if-match", string.Empty),
        new("if-modified-since", string.Empty),
        new("if-none-match", string.Empty),
        new("if-range", string.Empty),
        new("if-unmodified-since", string.Empty),
        new("last-modified", string.Empty),
        new("link", string.Empty),
        new("location", string.Empty),
        new("max-forwards", string.Empty),
        new("proxy-authenticate", string.Empty),
        new("proxy-authorization", string.Empty),
        new("range", string.Empty),
        new("referer", string.Empty),
        new("refresh", string.Empty),
        new("retry-after", string.Empty),
        new("server", string.Empty),
        new("set-cookie", string.Empty),
        new("strict-transport-security", string.Empty),
        new("transfer-encoding", string.Empty),
        new("user-agent", string.Empty),
        new("vary", string.Empty),
        new("via", string.Empty),
        new("www-authenticate", string.Empty)
    ];
}

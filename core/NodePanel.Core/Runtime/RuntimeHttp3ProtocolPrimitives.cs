#pragma warning disable CA1416
using System.Net.Quic;
using System.Text;

namespace NodePanel.Core.Runtime;

internal static class RuntimeHttp3ProtocolPrimitives
{
    public const long ControlStreamType = 0x00;
    public const long QPackEncoderStreamType = 0x02;
    public const long QPackDecoderStreamType = 0x03;
    public const long DataFrameType = 0x00;
    public const long HeadersFrameType = 0x01;
    public const long SettingsFrameType = 0x04;
    public const long GoAwayFrameType = 0x07;

    public static async ValueTask WriteControlStreamPreambleAsync(
        QuicStream stream,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(stream);

        await WriteVariableLengthIntegerAsync(stream, ControlStreamType, cancellationToken).ConfigureAwait(false);
        await WriteFrameAsync(
                stream,
                SettingsFrameType,
                RuntimeQPackDecoderState.BuildSettingsPayload(),
                completeWrites: false,
                cancellationToken)
            .ConfigureAwait(false);
        await stream.FlushAsync(cancellationToken).ConfigureAwait(false);
    }

    public static async ValueTask WriteUnidirectionalStreamTypeAsync(
        QuicStream stream,
        long streamType,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(stream);

        await WriteVariableLengthIntegerAsync(stream, streamType, cancellationToken).ConfigureAwait(false);
        await stream.FlushAsync(cancellationToken).ConfigureAwait(false);
    }

    public static async ValueTask WriteFrameAsync(
        QuicStream stream,
        long frameType,
        ReadOnlyMemory<byte> payload,
        bool completeWrites,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(stream);

        Span<byte> header = stackalloc byte[16];
        var offset = 0;
        WriteVariableLengthInteger(header, ref offset, frameType);
        WriteVariableLengthInteger(header, ref offset, payload.Length);

        if (payload.IsEmpty)
        {
            await stream.WriteAsync(header[..offset].ToArray(), completeWrites, cancellationToken)
                .ConfigureAwait(false);
            return;
        }

        await stream.WriteAsync(header[..offset].ToArray(), cancellationToken).ConfigureAwait(false);
        await stream.WriteAsync(payload, completeWrites, cancellationToken).ConfigureAwait(false);
    }

    public static async ValueTask WriteVariableLengthIntegerAsync(
        Stream stream,
        long value,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(stream);

        Span<byte> buffer = stackalloc byte[8];
        var offset = 0;
        WriteVariableLengthInteger(buffer, ref offset, value);
        await stream.WriteAsync(buffer[..offset].ToArray(), cancellationToken).ConfigureAwait(false);
    }

    public static void WriteVariableLengthInteger(
        Span<byte> buffer,
        ref int offset,
        long value)
    {
        ArgumentOutOfRangeException.ThrowIfNegative(value);
        if (value < 64)
        {
            buffer[offset++] = (byte)value;
            return;
        }

        if (value < 16_384)
        {
            buffer[offset++] = (byte)(0x40 | ((value >> 8) & 0x3F));
            buffer[offset++] = (byte)(value & 0xFF);
            return;
        }

        if (value < 1_073_741_824L)
        {
            buffer[offset++] = (byte)(0x80 | ((value >> 24) & 0x3F));
            buffer[offset++] = (byte)((value >> 16) & 0xFF);
            buffer[offset++] = (byte)((value >> 8) & 0xFF);
            buffer[offset++] = (byte)(value & 0xFF);
            return;
        }

        if (value < 4_611_686_018_427_387_904L)
        {
            buffer[offset++] = (byte)(0xC0 | ((value >> 56) & 0x3F));
            buffer[offset++] = (byte)((value >> 48) & 0xFF);
            buffer[offset++] = (byte)((value >> 40) & 0xFF);
            buffer[offset++] = (byte)((value >> 32) & 0xFF);
            buffer[offset++] = (byte)((value >> 24) & 0xFF);
            buffer[offset++] = (byte)((value >> 16) & 0xFF);
            buffer[offset++] = (byte)((value >> 8) & 0xFF);
            buffer[offset++] = (byte)(value & 0xFF);
            return;
        }

        throw new ArgumentOutOfRangeException(
            nameof(value),
            value,
            "HTTP/3 variable-length integers must be smaller than 2^62.");
    }

    public static async ValueTask<(bool HasValue, long Value)> ReadOptionalVariableLengthIntegerAsync(
        Stream stream,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(stream);

        var firstByteBuffer = new byte[1];
        var firstRead = await stream.ReadAsync(firstByteBuffer.AsMemory(0, 1), cancellationToken).ConfigureAwait(false);
        if (firstRead == 0)
        {
            return (false, 0);
        }

        var firstByte = firstByteBuffer[0];
        var encodedLength = 1 << (firstByte >> 6);
        long value = firstByte & 0x3F;
        if (encodedLength == 1)
        {
            return (true, value);
        }

        var remaining = new byte[encodedLength - 1];
        await ReadExactAsync(stream, remaining, cancellationToken).ConfigureAwait(false);
        for (var index = 0; index < remaining.Length; index++)
        {
            value = (value << 8) | remaining[index];
        }

        return (true, value);
    }

    public static async ValueTask ReadExactAsync(
        Stream stream,
        Memory<byte> buffer,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(stream);

        var offset = 0;
        while (offset < buffer.Length)
        {
            var read = await stream.ReadAsync(buffer[offset..], cancellationToken).ConfigureAwait(false);
            if (read == 0)
            {
                throw new EndOfStreamException("Unexpected EOF while reading an HTTP/3 frame.");
            }

            offset += read;
        }
    }

    public static async ValueTask<Http3Frame?> ReadFrameAsync(
        Stream stream,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(stream);

        var frameType = await ReadOptionalVariableLengthIntegerAsync(stream, cancellationToken).ConfigureAwait(false);
        if (!frameType.HasValue)
        {
            return null;
        }

        var frameLength = await ReadOptionalVariableLengthIntegerAsync(stream, cancellationToken).ConfigureAwait(false);
        if (!frameLength.HasValue)
        {
            throw new EndOfStreamException("Unexpected EOF while reading an HTTP/3 frame length.");
        }

        if (frameLength.Value > int.MaxValue)
        {
            throw new NotSupportedException("SplitHTTP HTTP/3 frames larger than Int32 are not supported.");
        }

        var payload = frameLength.Value == 0
            ? Array.Empty<byte>()
            : new byte[checked((int)frameLength.Value)];
        if (payload.Length > 0)
        {
            await ReadExactAsync(stream, payload, cancellationToken).ConfigureAwait(false);
        }

        return new Http3Frame(frameType.Value, payload);
    }

    public static byte[] BuildRequestHeaderBlock(
        IReadOnlyDictionary<string, string> requestHeaders,
        string method,
        string authority,
        string scheme,
        string path)
    {
        ArgumentNullException.ThrowIfNull(requestHeaders);
        ArgumentException.ThrowIfNullOrWhiteSpace(method);
        ArgumentException.ThrowIfNullOrWhiteSpace(authority);
        ArgumentException.ThrowIfNullOrWhiteSpace(scheme);
        ArgumentException.ThrowIfNullOrWhiteSpace(path);

        var buffer = new MemoryStream(256);
        WriteQPackHeaderBlockPrefix(buffer);
        WriteLiteralFieldLineWithLiteralName(buffer, ":method", method.Trim().ToUpperInvariant());
        WriteLiteralFieldLineWithLiteralName(buffer, ":authority", authority.Trim());
        WriteLiteralFieldLineWithLiteralName(buffer, ":scheme", scheme.Trim());
        WriteLiteralFieldLineWithLiteralName(buffer, ":path", path.Trim());

        foreach (var (name, value) in requestHeaders)
        {
            if (string.IsNullOrWhiteSpace(name) ||
                string.IsNullOrWhiteSpace(value) ||
                string.Equals(name, "Host", StringComparison.OrdinalIgnoreCase) ||
                IsConnectionSpecificHeader(name))
            {
                continue;
            }

            WriteLiteralFieldLineWithLiteralName(
                buffer,
                name.Trim().ToLowerInvariant(),
                value.Trim());
        }

        return buffer.ToArray();
    }

    public static byte[] BuildResponseHeaderBlock(
        int statusCode,
        IReadOnlyDictionary<string, string> headers)
    {
        ArgumentNullException.ThrowIfNull(headers);

        return BuildResponseHeaderBlockCore(
            headers,
            statusCode.ToString(System.Globalization.CultureInfo.InvariantCulture));
    }

    public static byte[] BuildResponseHeaderBlock(IReadOnlyDictionary<string, string> headers)
    {
        ArgumentNullException.ThrowIfNull(headers);

        return BuildResponseHeaderBlockCore(headers, statusCode: null);
    }

    private static byte[] BuildResponseHeaderBlockCore(
        IReadOnlyDictionary<string, string> headers,
        string? statusCode)
    {
        var buffer = new MemoryStream(256);
        WriteQPackHeaderBlockPrefix(buffer);
        if (!string.IsNullOrWhiteSpace(statusCode))
        {
            WriteLiteralFieldLineWithLiteralName(
                buffer,
                ":status",
                statusCode);
        }

        foreach (var (name, value) in headers)
        {
            if (string.IsNullOrWhiteSpace(name) ||
                string.IsNullOrWhiteSpace(value) ||
                name.StartsWith(':') ||
                IsConnectionSpecificHeader(name))
            {
                continue;
            }

            WriteLiteralFieldLineWithLiteralName(
                buffer,
                name.Trim().ToLowerInvariant(),
                value.Trim());
        }

        return buffer.ToArray();
    }

    private static void WriteQPackHeaderBlockPrefix(MemoryStream buffer)
    {
        buffer.WriteByte(0x00);
        buffer.WriteByte(0x00);
    }

    private static bool IsConnectionSpecificHeader(string name)
        => name.Trim().ToLowerInvariant() switch
        {
            "connection" => true,
            "proxy-connection" => true,
            "keep-alive" => true,
            "transfer-encoding" => true,
            "upgrade" => true,
            _ => false
        };

    private static void WriteLiteralFieldLineWithLiteralName(
        MemoryStream buffer,
        string name,
        string value)
    {
        var nameBytes = Encoding.UTF8.GetBytes(name);
        WritePrefixedInteger(buffer, nameBytes.Length, prefixBits: 3, prefixMask: 0x20);
        buffer.Write(nameBytes, 0, nameBytes.Length);
        WriteStringLiteral(buffer, value);
    }

    private static void WriteStringLiteral(MemoryStream buffer, string value)
    {
        var bytes = Encoding.UTF8.GetBytes(value);
        WritePrefixedInteger(buffer, bytes.Length, prefixBits: 7, prefixMask: 0x00);
        buffer.Write(bytes, 0, bytes.Length);
    }

    private static void WritePrefixedInteger(
        MemoryStream buffer,
        int value,
        int prefixBits,
        byte prefixMask)
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

    internal readonly record struct Http3Frame(long Type, byte[] Payload);
}

#pragma warning restore CA1416

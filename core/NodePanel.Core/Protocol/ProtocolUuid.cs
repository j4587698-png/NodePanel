using System.Globalization;

namespace NodePanel.Core.Protocol;

internal static class ProtocolUuid
{
    public static bool TryNormalize(string? value, out string normalized)
    {
        if (Guid.TryParse(value?.Trim(), out var uuid))
        {
            normalized = uuid.ToString("D");
            return true;
        }

        normalized = string.Empty;
        return false;
    }

    public static bool TryWriteBytes(string? value, Span<byte> destination)
    {
        if (destination.Length < 16 || !TryNormalize(value, out var normalized))
        {
            return false;
        }

        var compact = normalized.Replace("-", string.Empty, StringComparison.Ordinal);
        for (var index = 0; index < 16; index++)
        {
            if (!byte.TryParse(compact.AsSpan(index * 2, 2), NumberStyles.HexNumber, CultureInfo.InvariantCulture, out var parsed))
            {
                return false;
            }

            destination[index] = parsed;
        }

        return true;
    }

    public static string Format(ReadOnlySpan<byte> bytes)
    {
        if (bytes.Length < 16)
        {
            return string.Empty;
        }

        Span<char> buffer = stackalloc char[36];
        var writeIndex = 0;
        for (var index = 0; index < 16; index++)
        {
            if (index is 4 or 6 or 8 or 10)
            {
                buffer[writeIndex++] = '-';
            }

            var value = bytes[index];
            buffer[writeIndex++] = GetHexChar(value >> 4);
            buffer[writeIndex++] = GetHexChar(value & 0x0F);
        }

        return new string(buffer);
    }

    private static char GetHexChar(int value)
        => (char)(value < 10 ? '0' + value : 'a' + (value - 10));
}

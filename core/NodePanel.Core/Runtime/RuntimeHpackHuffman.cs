namespace NodePanel.Core.Runtime;

internal static partial class RuntimeHpackHuffman
{
    public static int GetBase62EncodedLength(string value)
    {
        ArgumentNullException.ThrowIfNull(value);
        return GetBase62EncodedLength(value.AsSpan());
    }

    public static int GetBase62EncodedLength(ReadOnlySpan<char> value)
    {
        var totalBits = 0;
        foreach (var character in value)
        {
            totalBits += GetBase62BitLength(character);
        }

        return (totalBits + 7) / 8;
    }

    // RFC 7541 Appendix B bit lengths for the base62 subset used by split-http tokenish padding.
    private static int GetBase62BitLength(char value)
        => value switch
        {
            '0' or '1' or '2' => 5,
            >= '3' and <= '9' => 6,
            'A' => 6,
            >= 'B' and <= 'W' => 7,
            'X' => 8,
            'Y' => 7,
            'Z' => 8,
            'a' => 5,
            'b' => 6,
            'c' => 5,
            'd' => 6,
            'e' => 5,
            'f' => 6,
            'g' => 6,
            'h' => 6,
            'i' => 5,
            'j' => 7,
            'k' => 7,
            'l' => 6,
            'm' => 6,
            'n' => 6,
            'o' => 5,
            'p' => 6,
            'q' => 7,
            'r' => 6,
            's' => 5,
            't' => 5,
            'u' => 6,
            >= 'v' and <= 'z' => 7,
            _ => throw new ArgumentOutOfRangeException(nameof(value), value, "Only base62 characters are supported.")
        };
}

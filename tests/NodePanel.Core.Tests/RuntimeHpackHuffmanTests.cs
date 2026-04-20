using NodePanel.Core.Runtime;

namespace NodePanel.Core.Tests;

public sealed class RuntimeHpackHuffmanTests
{
    [Fact]
    public void DecodeToUtf8String_decodes_known_vector()
    {
        byte[] encodedStatusName = [0xB8, 0x84, 0x8D, 0x36, 0xA3];

        Assert.Equal(":status", RuntimeHpackHuffman.DecodeToUtf8String(encodedStatusName));
    }

    [Fact]
    public void Decode_throws_when_padding_is_invalid()
    {
        byte[] invalidPadding = [0xB8, 0x84, 0x8D, 0x36, 0xA0];

        var exception = Assert.Throws<InvalidDataException>(
            () => RuntimeHpackHuffman.Decode(invalidPadding));

        Assert.Contains("padding", exception.Message, StringComparison.OrdinalIgnoreCase);
    }
}

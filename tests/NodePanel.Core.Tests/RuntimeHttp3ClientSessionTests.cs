using NodePanel.Core.Runtime;

namespace NodePanel.Core.Tests;

public sealed class RuntimeHttp3ClientSessionTests
{
    [Fact]
    public async Task ScanControlStreamAsync_invokes_goaway_callback_when_goaway_frame_is_present()
    {
        var controlStream = new MemoryStream(
        [
            .. BuildFrame(0x04, []),
            .. BuildFrame(0x21, [0xAA, 0xBB]),
            .. BuildFrame(0x07, EncodeVariableLengthInteger(0))
        ]);
        var goAwayCount = 0;

        await RuntimeHttp3ClientSession.ScanControlStreamAsync(
            controlStream,
            () => goAwayCount++,
            CancellationToken.None);

        Assert.Equal(1, goAwayCount);
    }

    [Fact]
    public async Task ScanControlStreamAsync_ignores_non_goaway_frames()
    {
        var controlStream = new MemoryStream(
        [
            .. BuildFrame(0x04, []),
            .. BuildFrame(0x21, [0xAA, 0xBB, 0xCC])
        ]);
        var goAwaySeen = false;

        await RuntimeHttp3ClientSession.ScanControlStreamAsync(
            controlStream,
            () => goAwaySeen = true,
            CancellationToken.None);

        Assert.False(goAwaySeen);
    }

    [Fact]
    public async Task ScanControlStreamAsync_throws_when_frame_payload_is_truncated()
    {
        var frame = BuildFrame(0x07, EncodeVariableLengthInteger(0));
        var truncatedFrame = frame.AsSpan(0, frame.Length - 1).ToArray();

        var exception = await Assert.ThrowsAsync<EndOfStreamException>(
            () => RuntimeHttp3ClientSession.ScanControlStreamAsync(
                    new MemoryStream(truncatedFrame),
                    static () => { },
                    CancellationToken.None)
                .AsTask());

        Assert.Contains("Unexpected EOF", exception.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void DecodeStatusCodeForHeaderBlock_decodes_huffman_encoded_literal_header_name_and_value()
    {
        byte[] headerBlock =
        [
            0x00, 0x00,
            0x2D, 0xB8, 0x84, 0x8D, 0x36, 0xA3,
            0x82, 0x10, 0x01
        ];

        Assert.Equal(200, RuntimeHttp3ClientSession.Http3RequestStream.DecodeStatusCodeForHeaderBlock(headerBlock));
    }

    private static byte[] BuildFrame(long frameType, byte[] payload)
    {
        var buffer = new List<byte>(16 + payload.Length);
        buffer.AddRange(EncodeVariableLengthInteger(frameType));
        buffer.AddRange(EncodeVariableLengthInteger(payload.Length));
        buffer.AddRange(payload);
        return [.. buffer];
    }

    private static byte[] EncodeVariableLengthInteger(long value)
    {
        ArgumentOutOfRangeException.ThrowIfNegative(value);
        if (value < 64)
        {
            return [(byte)value];
        }

        if (value < 16_384)
        {
            return
            [
                (byte)(0x40 | ((value >> 8) & 0x3F)),
                (byte)(value & 0xFF)
            ];
        }

        if (value < 1_073_741_824L)
        {
            return
            [
                (byte)(0x80 | ((value >> 24) & 0x3F)),
                (byte)((value >> 16) & 0xFF),
                (byte)((value >> 8) & 0xFF),
                (byte)(value & 0xFF)
            ];
        }

        if (value < 4_611_686_018_427_387_904L)
        {
            return
            [
                (byte)(0xC0 | ((value >> 56) & 0x3F)),
                (byte)((value >> 48) & 0xFF),
                (byte)((value >> 40) & 0xFF),
                (byte)((value >> 32) & 0xFF),
                (byte)((value >> 24) & 0xFF),
                (byte)((value >> 16) & 0xFF),
                (byte)((value >> 8) & 0xFF),
                (byte)(value & 0xFF)
            ];
        }

        throw new ArgumentOutOfRangeException(
            nameof(value),
            value,
            "HTTP/3 variable-length integers must be smaller than 2^62.");
    }
}

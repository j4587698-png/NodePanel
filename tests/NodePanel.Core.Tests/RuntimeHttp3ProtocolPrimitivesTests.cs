using NodePanel.Core.Runtime;

namespace NodePanel.Core.Tests;

public sealed class RuntimeHttp3ProtocolPrimitivesTests
{
    [Fact]
    public void BuildResponseHeaderBlock_roundtrips_through_static_qpack_decoder()
    {
        var headerBlock = RuntimeHttp3ProtocolPrimitives.BuildResponseHeaderBlock(
            200,
            new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
            {
                ["Content-Type"] = "application/grpc",
                ["X-Trace"] = "alpha",
                ["Connection"] = "close"
            });

        var headers = RuntimeQPackDecoderState.DecodeHeaders(headerBlock);

        Assert.Equal("200", headers[":status"]);
        Assert.Equal("application/grpc", headers["content-type"]);
        Assert.Equal("alpha", headers["x-trace"]);
        Assert.False(headers.ContainsKey("connection"));
    }

    [Fact]
    public async Task ReadFrameAsync_reads_headers_frame_payload_from_memory_stream()
    {
        byte[] frameBytes =
        [
            .. EncodeVariableLengthInteger(RuntimeHttp3ProtocolPrimitives.HeadersFrameType),
            .. EncodeVariableLengthInteger(3),
            0xAA, 0xBB, 0xCC
        ];

        var frame = await RuntimeHttp3ProtocolPrimitives.ReadFrameAsync(
            new MemoryStream(frameBytes),
            CancellationToken.None);

        Assert.NotNull(frame);
        Assert.Equal(RuntimeHttp3ProtocolPrimitives.HeadersFrameType, frame.Value.Type);
        Assert.Equal([0xAA, 0xBB, 0xCC], frame.Value.Payload);
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

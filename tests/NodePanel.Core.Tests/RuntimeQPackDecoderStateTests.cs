using System.Text;
using NodePanel.Core.Runtime;

namespace NodePanel.Core.Tests;

public sealed class RuntimeQPackDecoderStateTests
{
    [Fact]
    public async Task DecodeStatusCodeAsync_decodes_pre_base_dynamic_indexed_field()
    {
        var state = new RuntimeQPackDecoderState();
        var instructions = new List<byte[]>();

        await state.ProcessEncoderStreamAsync(
            new MemoryStream(
            [
                .. EncodeEncoderSetDynamicTableCapacity(4096),
                .. EncodeEncoderInsertWithStaticNameReference(25, "204")
            ]),
            (payload, _) =>
            {
                instructions.Add(payload.ToArray());
                return ValueTask.CompletedTask;
            },
            CancellationToken.None);

        byte[] headerBlock =
        [
            .. EncodeHeaderBlockPrefix(requiredInsertCount: 1, baseValue: 1),
            .. EncodeDynamicIndexedField(index: 0)
        ];

        var statusCode = await state.DecodeStatusCodeAsync(
            headerBlock,
            streamId: 4,
            (payload, _) =>
            {
                instructions.Add(payload.ToArray());
                return ValueTask.CompletedTask;
            },
            CancellationToken.None);

        Assert.Equal(204, statusCode);
        Assert.Collection(
            instructions,
            payload => Assert.Equal([0x01], payload),
            payload => Assert.Equal([0x81], payload));
    }

    [Fact]
    public async Task DecodeStatusCodeAsync_decodes_post_base_dynamic_indexed_field()
    {
        var state = new RuntimeQPackDecoderState();
        var instructions = new List<byte[]>();

        await state.ProcessEncoderStreamAsync(
            new MemoryStream(
            [
                .. EncodeEncoderSetDynamicTableCapacity(4096),
                .. EncodeEncoderInsertWithStaticNameReference(25, "200"),
                .. EncodeEncoderInsertWithStaticNameReference(25, "204")
            ]),
            (payload, _) =>
            {
                instructions.Add(payload.ToArray());
                return ValueTask.CompletedTask;
            },
            CancellationToken.None);

        byte[] headerBlock =
        [
            .. EncodeHeaderBlockPrefix(requiredInsertCount: 2, baseValue: 1),
            .. EncodePostBaseIndexedField(index: 0)
        ];

        var statusCode = await state.DecodeStatusCodeAsync(
            headerBlock,
            streamId: 4,
            (payload, _) =>
            {
                instructions.Add(payload.ToArray());
                return ValueTask.CompletedTask;
            },
            CancellationToken.None);

        Assert.Equal(204, statusCode);
        Assert.Collection(
            instructions,
            payload => Assert.Equal([0x01], payload),
            payload => Assert.Equal([0x01], payload),
            payload => Assert.Equal([0x81], payload));
    }

    [Fact]
    public async Task DecodeStatusCodeAsync_decodes_post_base_name_reference_literal()
    {
        var state = new RuntimeQPackDecoderState();
        var instructions = new List<byte[]>();

        await state.ProcessEncoderStreamAsync(
            new MemoryStream(
            [
                .. EncodeEncoderSetDynamicTableCapacity(4096),
                .. EncodeEncoderInsertWithStaticNameReference(25, "200"),
                .. EncodeEncoderInsertWithStaticNameReference(25, "204")
            ]),
            (payload, _) =>
            {
                instructions.Add(payload.ToArray());
                return ValueTask.CompletedTask;
            },
            CancellationToken.None);

        byte[] headerBlock =
        [
            .. EncodeHeaderBlockPrefix(requiredInsertCount: 2, baseValue: 1),
            .. EncodePostBaseNameReferenceLiteral(index: 0, value: "205")
        ];

        var statusCode = await state.DecodeStatusCodeAsync(
            headerBlock,
            streamId: 4,
            (payload, _) =>
            {
                instructions.Add(payload.ToArray());
                return ValueTask.CompletedTask;
            },
            CancellationToken.None);

        Assert.Equal(205, statusCode);
        Assert.Collection(
            instructions,
            payload => Assert.Equal([0x01], payload),
            payload => Assert.Equal([0x01], payload),
            payload => Assert.Equal([0x81], payload));
    }

    [Fact]
    public async Task DecodeStatusCodeAsync_decodes_insert_without_name_reference_and_duplicate()
    {
        var state = new RuntimeQPackDecoderState();
        var instructions = new List<byte[]>();

        await state.ProcessEncoderStreamAsync(
            new MemoryStream(
            [
                .. EncodeEncoderSetDynamicTableCapacity(4096),
                .. EncodeEncoderInsertWithoutNameReference(":status", "418"),
                .. EncodeEncoderDuplicate(index: 0)
            ]),
            (payload, _) =>
            {
                instructions.Add(payload.ToArray());
                return ValueTask.CompletedTask;
            },
            CancellationToken.None);

        byte[] headerBlock =
        [
            .. EncodeHeaderBlockPrefix(requiredInsertCount: 2, baseValue: 2),
            .. EncodeDynamicIndexedField(index: 0)
        ];

        var statusCode = await state.DecodeStatusCodeAsync(
            headerBlock,
            streamId: 4,
            (payload, _) =>
            {
                instructions.Add(payload.ToArray());
                return ValueTask.CompletedTask;
            },
            CancellationToken.None);

        Assert.Equal(418, statusCode);
        Assert.Collection(
            instructions,
            payload => Assert.Equal([0x01], payload),
            payload => Assert.Equal([0x01], payload),
            payload => Assert.Equal([0x81], payload));
    }

    [Fact]
    public async Task DecodeStatusCodeAsync_sends_stream_cancellation_when_blocked_decode_is_canceled()
    {
        var state = new RuntimeQPackDecoderState();
        var instructions = new List<byte[]>();
        using var cancellationTokenSource = new CancellationTokenSource();
        cancellationTokenSource.CancelAfter(TimeSpan.FromMilliseconds(50));

        byte[] headerBlock =
        [
            .. EncodeHeaderBlockPrefix(requiredInsertCount: 1, baseValue: 1),
            .. EncodeDynamicIndexedField(index: 0)
        ];

        await Assert.ThrowsAnyAsync<OperationCanceledException>(
            () => state.DecodeStatusCodeAsync(
                    headerBlock,
                    streamId: 4,
                    (payload, _) =>
                    {
                        instructions.Add(payload.ToArray());
                        return ValueTask.CompletedTask;
                    },
                    cancellationTokenSource.Token)
                .AsTask());

        Assert.Collection(
            instructions,
            payload => Assert.Equal([0x41], payload));
    }

    [Fact]
    public async Task DecodeHeadersAsync_decodes_request_headers_and_acknowledges_dynamic_section()
    {
        var state = new RuntimeQPackDecoderState();
        var instructions = new List<byte[]>();

        await state.ProcessEncoderStreamAsync(
            new MemoryStream(
            [
                .. EncodeEncoderSetDynamicTableCapacity(4096),
                .. EncodeEncoderInsertWithoutNameReference("x-trace", "alpha")
            ]),
            (payload, _) =>
            {
                instructions.Add(payload.ToArray());
                return ValueTask.CompletedTask;
            },
            CancellationToken.None);

        byte[] headerBlock =
        [
            .. EncodeHeaderBlockPrefix(requiredInsertCount: 1, baseValue: 1),
            .. EncodeLiteralFieldWithoutNameReference(":method", "GET"),
            .. EncodeLiteralFieldWithoutNameReference(":authority", "edge.example.com"),
            .. EncodeLiteralFieldWithoutNameReference(":path", "/xhttp/?route=1"),
            .. EncodeDynamicIndexedField(index: 0)
        ];

        var headers = await state.DecodeHeadersAsync(
            headerBlock,
            streamId: 4,
            (payload, _) =>
            {
                instructions.Add(payload.ToArray());
                return ValueTask.CompletedTask;
            },
            CancellationToken.None);

        Assert.Equal("GET", headers[":method"]);
        Assert.Equal("edge.example.com", headers[":authority"]);
        Assert.Equal("/xhttp/?route=1", headers[":path"]);
        Assert.Equal("alpha", headers["x-trace"]);
        Assert.Collection(
            instructions,
            payload => Assert.Equal([0x01], payload),
            payload => Assert.Equal([0x81], payload));
    }

    [Fact]
    public void DecodeHeaders_decodes_static_literal_request_header_block()
    {
        var headerBlock = RuntimeHttp3ProtocolPrimitives.BuildRequestHeaderBlock(
            new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
            {
                ["User-Agent"] = "UnitTest/1.0",
                ["Connection"] = "keep-alive",
                ["Host"] = "ignored.example.com"
            },
            method: "GET",
            authority: "edge.example.com",
            scheme: "https",
            path: "/xhttp/?route=1");

        var headers = RuntimeQPackDecoderState.DecodeHeaders(headerBlock);

        Assert.Equal("GET", headers[":method"]);
        Assert.Equal("edge.example.com", headers[":authority"]);
        Assert.Equal("https", headers[":scheme"]);
        Assert.Equal("/xhttp/?route=1", headers[":path"]);
        Assert.Equal("UnitTest/1.0", headers["user-agent"]);
        Assert.False(headers.ContainsKey("connection"));
        Assert.False(headers.ContainsKey("host"));
    }

    private static byte[] EncodeHeaderBlockPrefix(int requiredInsertCount, int baseValue)
    {
        var buffer = new List<byte>(8);
        buffer.AddRange(EncodePrefixedInteger(EncodeRequiredInsertCount(requiredInsertCount), prefixBits: 8, prefixMask: 0x00));

        var deltaBaseNegative = baseValue < requiredInsertCount;
        var deltaBase = deltaBaseNegative
            ? requiredInsertCount - baseValue - 1
            : baseValue - requiredInsertCount;
        buffer.AddRange(EncodePrefixedInteger(deltaBase, prefixBits: 7, prefixMask: deltaBaseNegative ? (byte)0x80 : (byte)0x00));
        return [.. buffer];
    }

    private static int EncodeRequiredInsertCount(int requiredInsertCount)
    {
        if (requiredInsertCount == 0)
        {
            return 0;
        }

        const int maxEntries = 4096 / 32;
        const int fullRange = 2 * maxEntries;
        return (requiredInsertCount % fullRange) + 1;
    }

    private static byte[] EncodeDynamicIndexedField(int index)
        => EncodePrefixedInteger(index, prefixBits: 6, prefixMask: 0x80);

    private static byte[] EncodePostBaseIndexedField(int index)
        => EncodePrefixedInteger(index, prefixBits: 4, prefixMask: 0x10);

    private static byte[] EncodePostBaseNameReferenceLiteral(int index, string value)
        => [.. EncodePrefixedInteger(index, prefixBits: 3, prefixMask: 0x00), .. EncodeStringLiteral(value, prefixBits: 7, prefixMask: 0x00)];

    private static byte[] EncodeEncoderSetDynamicTableCapacity(int capacity)
        => EncodePrefixedInteger(capacity, prefixBits: 5, prefixMask: 0x20);

    private static byte[] EncodeEncoderInsertWithStaticNameReference(int nameIndex, string value)
        => [.. EncodePrefixedInteger(nameIndex, prefixBits: 6, prefixMask: 0xC0), .. EncodeStringLiteral(value, prefixBits: 7, prefixMask: 0x00)];

    private static byte[] EncodeEncoderInsertWithoutNameReference(string name, string value)
        => [.. EncodeStringLiteral(name, prefixBits: 5, prefixMask: 0x40), .. EncodeStringLiteral(value, prefixBits: 7, prefixMask: 0x00)];

    private static byte[] EncodeEncoderDuplicate(int index)
        => EncodePrefixedInteger(index, prefixBits: 5, prefixMask: 0x00);

    private static byte[] EncodeLiteralFieldWithoutNameReference(string name, string value)
        => [.. EncodeStringLiteral(name, prefixBits: 3, prefixMask: 0x20), .. EncodeStringLiteral(value, prefixBits: 7, prefixMask: 0x00)];

    private static byte[] EncodeStringLiteral(string value, int prefixBits, byte prefixMask)
    {
        var bytes = Encoding.ASCII.GetBytes(value);
        return [.. EncodePrefixedInteger(bytes.Length, prefixBits, prefixMask), .. bytes];
    }

    private static byte[] EncodePrefixedInteger(long value, int prefixBits, byte prefixMask)
    {
        ArgumentOutOfRangeException.ThrowIfNegative(value);

        var buffer = new List<byte>(8);
        var maxPrefixValue = (1 << prefixBits) - 1;
        if (value < maxPrefixValue)
        {
            buffer.Add((byte)(prefixMask | value));
            return [.. buffer];
        }

        buffer.Add((byte)(prefixMask | maxPrefixValue));
        value -= maxPrefixValue;
        while (value >= 128)
        {
            buffer.Add((byte)((value & 0x7F) | 0x80));
            value >>= 7;
        }

        buffer.Add((byte)value);
        return [.. buffer];
    }
}

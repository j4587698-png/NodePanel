using System.Buffers;
using System.Text;

namespace NodePanel.Core.Runtime;

internal static partial class RuntimeHpackHuffman
{
    private static readonly DecoderNode[] DecoderNodes;

    static RuntimeHpackHuffman()
    {
        DecoderNodes = CreateDecoderNodes();
    }

    public static byte[] Decode(ReadOnlySpan<byte> value)
    {
        if (value.IsEmpty)
        {
            return [];
        }

        var writer = new ArrayBufferWriter<byte>(Math.Max(4, checked(value.Length * 2)));
        var nodeIndex = 0;
        foreach (var current in value)
        {
            for (var bitIndex = 7; bitIndex >= 0; bitIndex--)
            {
                nodeIndex = ((current >> bitIndex) & 0x01) == 0
                    ? DecoderNodes[nodeIndex].ZeroChild
                    : DecoderNodes[nodeIndex].OneChild;
                if (nodeIndex < 0)
                {
                    throw new InvalidDataException("HPACK Huffman-coded string literal contained an invalid bit sequence.");
                }

                ref readonly var node = ref DecoderNodes[nodeIndex];
                if (node.Symbol < 0)
                {
                    continue;
                }

                if (node.Symbol == 256)
                {
                    throw new InvalidDataException("HPACK Huffman-coded string literal must not contain the EOS symbol.");
                }

                var span = writer.GetSpan(1);
                span[0] = checked((byte)node.Symbol);
                writer.Advance(1);
                nodeIndex = 0;
            }
        }

        ref readonly var tailNode = ref DecoderNodes[nodeIndex];
        if (nodeIndex != 0 &&
            (!tailNode.IsAllOnesPath || tailNode.Depth > 7))
        {
            throw new InvalidDataException("HPACK Huffman-coded string literal ended with invalid padding.");
        }

        return writer.WrittenSpan.ToArray();
    }

    public static string DecodeToUtf8String(ReadOnlySpan<byte> value)
        => Encoding.UTF8.GetString(Decode(value));

    private static DecoderNode[] CreateDecoderNodes()
    {
        var builders = new List<DecoderNodeBuilder>(512)
        {
            new(depth: 0, isAllOnesPath: true)
        };

        for (var symbol = 0; symbol < EncodingTableCodes.Length; symbol++)
        {
            AddSymbol(
                builders,
                symbol,
                EncodingTableCodes[symbol],
                EncodingTableBitLengths[symbol]);
        }

        var result = new DecoderNode[builders.Count];
        for (var index = 0; index < builders.Count; index++)
        {
            var builder = builders[index];
            result[index] = new DecoderNode(
                builder.ZeroChild,
                builder.OneChild,
                builder.Symbol,
                builder.Depth,
                builder.IsAllOnesPath);
        }

        return result;
    }

    private static void AddSymbol(
        List<DecoderNodeBuilder> builders,
        int symbol,
        uint code,
        int bitLength)
    {
        var nodeIndex = 0;
        for (var bitPosition = 0; bitPosition < bitLength; bitPosition++)
        {
            var currentNode = builders[nodeIndex];
            if (currentNode.Symbol >= 0)
            {
                throw new InvalidOperationException("HPACK Huffman table contains a prefix conflict.");
            }

            var bit = (int)((code >> (31 - bitPosition)) & 0x01u);
            var nextIndex = bit == 0
                ? currentNode.ZeroChild
                : currentNode.OneChild;
            if (nextIndex < 0)
            {
                nextIndex = builders.Count;
                builders.Add(new DecoderNodeBuilder(
                    depth: currentNode.Depth + 1,
                    isAllOnesPath: currentNode.IsAllOnesPath && bit == 1));
                if (bit == 0)
                {
                    currentNode.ZeroChild = nextIndex;
                }
                else
                {
                    currentNode.OneChild = nextIndex;
                }
            }

            nodeIndex = nextIndex;
        }

        var targetNode = builders[nodeIndex];
        if (targetNode.Symbol >= 0 ||
            targetNode.ZeroChild >= 0 ||
            targetNode.OneChild >= 0)
        {
            throw new InvalidOperationException("HPACK Huffman table contains a duplicate or overlapping symbol.");
        }

        targetNode.Symbol = symbol;
    }

    private sealed class DecoderNodeBuilder(int depth, bool isAllOnesPath)
    {
        public int ZeroChild { get; set; } = -1;

        public int OneChild { get; set; } = -1;

        public int Symbol { get; set; } = -1;

        public int Depth { get; } = depth;

        public bool IsAllOnesPath { get; } = isAllOnesPath;
    }

    private readonly record struct DecoderNode(
        int ZeroChild,
        int OneChild,
        int Symbol,
        int Depth,
        bool IsAllOnesPath);

    private static readonly uint[] EncodingTableCodes =
    [
            0xFFC00000u, 0xFFFFB000u, 0xFFFFFE20u, 0xFFFFFE30u, 0xFFFFFE40u, 0xFFFFFE50u, 0xFFFFFE60u, 0xFFFFFE70u,
            0xFFFFFE80u, 0xFFFFEA00u, 0xFFFFFFF0u, 0xFFFFFE90u, 0xFFFFFEA0u, 0xFFFFFFF4u, 0xFFFFFEB0u, 0xFFFFFEC0u,
            0xFFFFFED0u, 0xFFFFFEE0u, 0xFFFFFEF0u, 0xFFFFFF00u, 0xFFFFFF10u, 0xFFFFFF20u, 0xFFFFFFF8u, 0xFFFFFF30u,
            0xFFFFFF40u, 0xFFFFFF50u, 0xFFFFFF60u, 0xFFFFFF70u, 0xFFFFFF80u, 0xFFFFFF90u, 0xFFFFFFA0u, 0xFFFFFFB0u,
            0x50000000u, 0xFE000000u, 0xFE400000u, 0xFFA00000u, 0xFFC80000u, 0x54000000u, 0xF8000000u, 0xFF400000u,
            0xFE800000u, 0xFEC00000u, 0xF9000000u, 0xFF600000u, 0xFA000000u, 0x58000000u, 0x5C000000u, 0x60000000u,
            0x00000000u, 0x08000000u, 0x10000000u, 0x64000000u, 0x68000000u, 0x6C000000u, 0x70000000u, 0x74000000u,
            0x78000000u, 0x7C000000u, 0xB8000000u, 0xFB000000u, 0xFFF80000u, 0x80000000u, 0xFFB00000u, 0xFF000000u,
            0xFFD00000u, 0x84000000u, 0xBA000000u, 0xBC000000u, 0xBE000000u, 0xC0000000u, 0xC2000000u, 0xC4000000u,
            0xC6000000u, 0xC8000000u, 0xCA000000u, 0xCC000000u, 0xCE000000u, 0xD0000000u, 0xD2000000u, 0xD4000000u,
            0xD6000000u, 0xD8000000u, 0xDA000000u, 0xDC000000u, 0xDE000000u, 0xE0000000u, 0xE2000000u, 0xE4000000u,
            0xFC000000u, 0xE6000000u, 0xFD000000u, 0xFFD80000u, 0xFFFE0000u, 0xFFE00000u, 0xFFF00000u, 0x88000000u,
            0xFFFA0000u, 0x18000000u, 0x8C000000u, 0x20000000u, 0x90000000u, 0x28000000u, 0x94000000u, 0x98000000u,
            0x9C000000u, 0x30000000u, 0xE8000000u, 0xEA000000u, 0xA0000000u, 0xA4000000u, 0xA8000000u, 0x38000000u,
            0xAC000000u, 0xEC000000u, 0xB0000000u, 0x40000000u, 0x48000000u, 0xB4000000u, 0xEE000000u, 0xF0000000u,
            0xF2000000u, 0xF4000000u, 0xF6000000u, 0xFFFC0000u, 0xFF800000u, 0xFFF40000u, 0xFFE80000u, 0xFFFFFFC0u,
            0xFFFE6000u, 0xFFFF4800u, 0xFFFE7000u, 0xFFFE8000u, 0xFFFF4C00u, 0xFFFF5000u, 0xFFFF5400u, 0xFFFFB200u,
            0xFFFF5800u, 0xFFFFB400u, 0xFFFFB600u, 0xFFFFB800u, 0xFFFFBA00u, 0xFFFFBC00u, 0xFFFFEB00u, 0xFFFFBE00u,
            0xFFFFEC00u, 0xFFFFED00u, 0xFFFF5C00u, 0xFFFFC000u, 0xFFFFEE00u, 0xFFFFC200u, 0xFFFFC400u, 0xFFFFC600u,
            0xFFFFC800u, 0xFFFEE000u, 0xFFFF6000u, 0xFFFFCA00u, 0xFFFF6400u, 0xFFFFCC00u, 0xFFFFCE00u, 0xFFFFEF00u,
            0xFFFF6800u, 0xFFFEE800u, 0xFFFE9000u, 0xFFFF6C00u, 0xFFFF7000u, 0xFFFFD000u, 0xFFFFD200u, 0xFFFEF000u,
            0xFFFFD400u, 0xFFFF7400u, 0xFFFF7800u, 0xFFFFF000u, 0xFFFEF800u, 0xFFFF7C00u, 0xFFFFD600u, 0xFFFFD800u,
            0xFFFF0000u, 0xFFFF0800u, 0xFFFF8000u, 0xFFFF1000u, 0xFFFFDA00u, 0xFFFF8400u, 0xFFFFDC00u, 0xFFFFDE00u,
            0xFFFEA000u, 0xFFFF8800u, 0xFFFF8C00u, 0xFFFF9000u, 0xFFFFE000u, 0xFFFF9400u, 0xFFFF9800u, 0xFFFFE200u,
            0xFFFFF800u, 0xFFFFF840u, 0xFFFEB000u, 0xFFFE2000u, 0xFFFF9C00u, 0xFFFFE400u, 0xFFFFA000u, 0xFFFFF600u,
            0xFFFFF880u, 0xFFFFF8C0u, 0xFFFFF900u, 0xFFFFFBC0u, 0xFFFFFBE0u, 0xFFFFF940u, 0xFFFFF100u, 0xFFFFF680u,
            0xFFFE4000u, 0xFFFF1800u, 0xFFFFF980u, 0xFFFFFC00u, 0xFFFFFC20u, 0xFFFFF9C0u, 0xFFFFFC40u, 0xFFFFF200u,
            0xFFFF2000u, 0xFFFF2800u, 0xFFFFFA00u, 0xFFFFFA40u, 0xFFFFFFD0u, 0xFFFFFC60u, 0xFFFFFC80u, 0xFFFFFCA0u,
            0xFFFEC000u, 0xFFFFF300u, 0xFFFED000u, 0xFFFF3000u, 0xFFFFA400u, 0xFFFF3800u, 0xFFFF4000u, 0xFFFFE600u,
            0xFFFFA800u, 0xFFFFAC00u, 0xFFFFF700u, 0xFFFFF780u, 0xFFFFF400u, 0xFFFFF500u, 0xFFFFFA80u, 0xFFFFE800u,
            0xFFFFFAC0u, 0xFFFFFCC0u, 0xFFFFFB00u, 0xFFFFFB40u, 0xFFFFFCE0u, 0xFFFFFD00u, 0xFFFFFD20u, 0xFFFFFD40u,
            0xFFFFFD60u, 0xFFFFFFE0u, 0xFFFFFD80u, 0xFFFFFDA0u, 0xFFFFFDC0u, 0xFFFFFDE0u, 0xFFFFFE00u, 0xFFFFFB80u,
            0xFFFFFFFCu
    ];

    private static readonly byte[] EncodingTableBitLengths =
    [
            13, 23, 28, 28, 28, 28, 28, 28, 28, 24, 30, 28, 28, 30, 28, 28,
            28, 28, 28, 28, 28, 28, 30, 28, 28, 28, 28, 28, 28, 28, 28, 28,
            6, 10, 10, 12, 13, 6, 8, 11, 10, 10, 8, 11, 8, 6, 6, 6,
            5, 5, 5, 6, 6, 6, 6, 6, 6, 6, 7, 8, 15, 6, 12, 10,
            13, 6, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7,
            7, 7, 7, 7, 7, 7, 7, 7, 8, 7, 8, 13, 19, 13, 14, 6,
            15, 5, 6, 5, 6, 5, 6, 6, 6, 5, 7, 7, 6, 6, 6, 5,
            6, 7, 6, 5, 5, 6, 7, 7, 7, 7, 7, 15, 11, 14, 13, 28,
            20, 22, 20, 20, 22, 22, 22, 23, 22, 23, 23, 23, 23, 23, 24, 23,
            24, 24, 22, 23, 24, 23, 23, 23, 23, 21, 22, 23, 22, 23, 23, 24,
            22, 21, 20, 22, 22, 23, 23, 21, 23, 22, 22, 24, 21, 22, 23, 23,
            21, 21, 22, 21, 23, 22, 23, 23, 20, 22, 22, 22, 23, 22, 22, 23,
            26, 26, 20, 19, 22, 23, 22, 25, 26, 26, 26, 27, 27, 26, 24, 25,
            19, 21, 26, 27, 27, 26, 27, 24, 21, 21, 26, 26, 28, 27, 27, 27,
            20, 24, 20, 21, 22, 21, 21, 23, 22, 22, 25, 25, 24, 24, 26, 23,
            26, 27, 26, 26, 27, 27, 27, 27, 27, 28, 27, 27, 27, 27, 27, 26,
            30
    ];
}

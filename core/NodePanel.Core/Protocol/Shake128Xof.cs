using System.Buffers.Binary;
using System.Numerics;

namespace NodePanel.Core.Protocol;

internal sealed class Shake128Xof
{
    private const int RateBytes = 168;
    private const byte DomainSeparator = 0x1F;

    private static readonly int[] RhoOffsets =
    [
        1, 3, 6, 10, 15, 21, 28, 36, 45, 55, 2, 14,
        27, 41, 56, 8, 25, 43, 62, 18, 39, 61, 20, 44
    ];

    private static readonly int[] PiLaneIndices =
    [
        10, 7, 11, 17, 18, 3, 5, 16, 8, 21, 24, 4,
        15, 23, 19, 13, 12, 2, 20, 14, 22, 9, 6, 1
    ];

    private static readonly ulong[] RoundConstants =
    [
        0x0000000000000001UL, 0x0000000000008082UL,
        0x800000000000808AUL, 0x8000000080008000UL,
        0x000000000000808BUL, 0x0000000080000001UL,
        0x8000000080008081UL, 0x8000000000008009UL,
        0x000000000000008AUL, 0x0000000000000088UL,
        0x0000000080008009UL, 0x000000008000000AUL,
        0x000000008000808BUL, 0x800000000000008BUL,
        0x8000000000008089UL, 0x8000000000008003UL,
        0x8000000000008002UL, 0x8000000000000080UL,
        0x000000000000800AUL, 0x800000008000000AUL,
        0x8000000080008081UL, 0x8000000000008080UL,
        0x0000000080000001UL, 0x8000000080008008UL
    ];

    private readonly byte[] _absorbBuffer = new byte[RateBytes];
    private readonly byte[] _squeezeBuffer = new byte[RateBytes];
    private readonly ulong[] _state = new ulong[25];

    private int _absorbOffset;
    private int _squeezeOffset = RateBytes;

    public Shake128Xof(ReadOnlySpan<byte> seed)
    {
        Absorb(seed);
        FinalizeAbsorb();
    }

    public ushort NextUInt16()
    {
        Span<byte> buffer = stackalloc byte[2];
        Read(buffer);
        return BinaryPrimitives.ReadUInt16BigEndian(buffer);
    }

    public void Read(Span<byte> destination)
    {
        var written = 0;
        while (written < destination.Length)
        {
            if (_squeezeOffset >= RateBytes)
            {
                Permute();
                CopyStateToRateBuffer();
                _squeezeOffset = 0;
            }

            var count = Math.Min(destination.Length - written, RateBytes - _squeezeOffset);
            _squeezeBuffer.AsSpan(_squeezeOffset, count).CopyTo(destination.Slice(written, count));
            _squeezeOffset += count;
            written += count;
        }
    }

    private void Absorb(ReadOnlySpan<byte> data)
    {
        var offset = 0;
        while (offset < data.Length)
        {
            var count = Math.Min(RateBytes - _absorbOffset, data.Length - offset);
            data.Slice(offset, count).CopyTo(_absorbBuffer.AsSpan(_absorbOffset, count));
            _absorbOffset += count;
            offset += count;

            if (_absorbOffset == RateBytes)
            {
                XorBufferIntoState(_absorbBuffer);
                Permute();
                Array.Clear(_absorbBuffer);
                _absorbOffset = 0;
            }
        }
    }

    private void FinalizeAbsorb()
    {
        _absorbBuffer[_absorbOffset] ^= DomainSeparator;
        _absorbBuffer[RateBytes - 1] ^= 0x80;
        XorBufferIntoState(_absorbBuffer);
        Permute();
        CopyStateToRateBuffer();
        Array.Clear(_absorbBuffer);
        _absorbOffset = 0;
        _squeezeOffset = 0;
    }

    private void XorBufferIntoState(ReadOnlySpan<byte> block)
    {
        for (var index = 0; index < RateBytes / 8; index++)
        {
            _state[index] ^= BinaryPrimitives.ReadUInt64LittleEndian(block.Slice(index * 8, 8));
        }
    }

    private void CopyStateToRateBuffer()
    {
        for (var index = 0; index < RateBytes / 8; index++)
        {
            BinaryPrimitives.WriteUInt64LittleEndian(_squeezeBuffer.AsSpan(index * 8, 8), _state[index]);
        }
    }

    private void Permute()
    {
        Span<ulong> c = stackalloc ulong[5];
        Span<ulong> d = stackalloc ulong[5];

        for (var round = 0; round < RoundConstants.Length; round++)
        {
            for (var x = 0; x < 5; x++)
            {
                c[x] = _state[x] ^ _state[x + 5] ^ _state[x + 10] ^ _state[x + 15] ^ _state[x + 20];
            }

            for (var x = 0; x < 5; x++)
            {
                d[x] = c[(x + 4) % 5] ^ BitOperations.RotateLeft(c[(x + 1) % 5], 1);
            }

            for (var index = 0; index < 25; index++)
            {
                _state[index] ^= d[index % 5];
            }

            var current = _state[1];
            for (var index = 0; index < PiLaneIndices.Length; index++)
            {
                var laneIndex = PiLaneIndices[index];
                var temp = _state[laneIndex];
                _state[laneIndex] = BitOperations.RotateLeft(current, RhoOffsets[index]);
                current = temp;
            }

            for (var row = 0; row < 25; row += 5)
            {
                var a0 = _state[row];
                var a1 = _state[row + 1];
                var a2 = _state[row + 2];
                var a3 = _state[row + 3];
                var a4 = _state[row + 4];

                _state[row] ^= (~a1) & a2;
                _state[row + 1] ^= (~a2) & a3;
                _state[row + 2] ^= (~a3) & a4;
                _state[row + 3] ^= (~a4) & a0;
                _state[row + 4] ^= (~a0) & a1;
            }

            _state[0] ^= RoundConstants[round];
        }
    }
}

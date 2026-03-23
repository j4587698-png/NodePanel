using System.Buffers.Binary;

namespace NodePanel.Core.Cryptography;

public static class Sha224
{
    private static ReadOnlySpan<uint> InitialState =>
    [
        0xc1059ed8u,
        0x367cd507u,
        0x3070dd17u,
        0xf70e5939u,
        0xffc00b31u,
        0x68581511u,
        0x64f98fa7u,
        0xbefa4fa4u
    ];

    private static ReadOnlySpan<uint> K =>
    [
        0x428a2f98u, 0x71374491u, 0xb5c0fbcfu, 0xe9b5dba5u,
        0x3956c25bu, 0x59f111f1u, 0x923f82a4u, 0xab1c5ed5u,
        0xd807aa98u, 0x12835b01u, 0x243185beu, 0x550c7dc3u,
        0x72be5d74u, 0x80deb1feu, 0x9bdc06a7u, 0xc19bf174u,
        0xe49b69c1u, 0xefbe4786u, 0x0fc19dc6u, 0x240ca1ccu,
        0x2de92c6fu, 0x4a7484aau, 0x5cb0a9dcu, 0x76f988dau,
        0x983e5152u, 0xa831c66du, 0xb00327c8u, 0xbf597fc7u,
        0xc6e00bf3u, 0xd5a79147u, 0x06ca6351u, 0x14292967u,
        0x27b70a85u, 0x2e1b2138u, 0x4d2c6dfcu, 0x53380d13u,
        0x650a7354u, 0x766a0abbu, 0x81c2c92eu, 0x92722c85u,
        0xa2bfe8a1u, 0xa81a664bu, 0xc24b8b70u, 0xc76c51a3u,
        0xd192e819u, 0xd6990624u, 0xf40e3585u, 0x106aa070u,
        0x19a4c116u, 0x1e376c08u, 0x2748774cu, 0x34b0bcb5u,
        0x391c0cb3u, 0x4ed8aa4au, 0x5b9cca4fu, 0x682e6ff3u,
        0x748f82eeu, 0x78a5636fu, 0x84c87814u, 0x8cc70208u,
        0x90befffau, 0xa4506cebu, 0xbef9a3f7u, 0xc67178f2u
    ];

    public static byte[] HashData(ReadOnlySpan<byte> data)
    {
        var paddedLength = GetPaddedLength(data.Length);
        var padded = GC.AllocateUninitializedArray<byte>(paddedLength);
        data.CopyTo(padded);
        padded[data.Length] = 0x80;
        BinaryPrimitives.WriteUInt64BigEndian(padded.AsSpan(paddedLength - sizeof(ulong)), checked((ulong)data.Length * 8UL));

        var state = new uint[8];
        InitialState.CopyTo(state);
        Span<uint> schedule = stackalloc uint[64];

        for (var offset = 0; offset < padded.Length; offset += 64)
        {
            var block = padded.AsSpan(offset, 64);
            for (var i = 0; i < 16; i++)
            {
                schedule[i] = BinaryPrimitives.ReadUInt32BigEndian(block[(i * 4)..((i + 1) * 4)]);
            }

            for (var i = 16; i < 64; i++)
            {
                schedule[i] = unchecked(SmallSigma1(schedule[i - 2]) + schedule[i - 7] + SmallSigma0(schedule[i - 15]) + schedule[i - 16]);
            }

            var a = state[0];
            var b = state[1];
            var c = state[2];
            var d = state[3];
            var e = state[4];
            var f = state[5];
            var g = state[6];
            var h = state[7];

            for (var i = 0; i < 64; i++)
            {
                var t1 = unchecked(h + BigSigma1(e) + Ch(e, f, g) + K[i] + schedule[i]);
                var t2 = unchecked(BigSigma0(a) + Maj(a, b, c));

                h = g;
                g = f;
                f = e;
                e = unchecked(d + t1);
                d = c;
                c = b;
                b = a;
                a = unchecked(t1 + t2);
            }

            state[0] = unchecked(state[0] + a);
            state[1] = unchecked(state[1] + b);
            state[2] = unchecked(state[2] + c);
            state[3] = unchecked(state[3] + d);
            state[4] = unchecked(state[4] + e);
            state[5] = unchecked(state[5] + f);
            state[6] = unchecked(state[6] + g);
            state[7] = unchecked(state[7] + h);
        }

        var result = new byte[28];
        for (var i = 0; i < 7; i++)
        {
            BinaryPrimitives.WriteUInt32BigEndian(result.AsSpan(i * 4, 4), state[i]);
        }

        return result;
    }

    private static int GetPaddedLength(int dataLength)
    {
        var withPadding = dataLength + 1 + sizeof(ulong);
        var remainder = withPadding % 64;
        return remainder == 0 ? withPadding : withPadding + (64 - remainder);
    }

    private static uint RotateRight(uint value, int bits) => (value >> bits) | (value << (32 - bits));

    private static uint Ch(uint x, uint y, uint z) => (x & y) ^ (~x & z);

    private static uint Maj(uint x, uint y, uint z) => (x & y) ^ (x & z) ^ (y & z);

    private static uint BigSigma0(uint value) => RotateRight(value, 2) ^ RotateRight(value, 13) ^ RotateRight(value, 22);

    private static uint BigSigma1(uint value) => RotateRight(value, 6) ^ RotateRight(value, 11) ^ RotateRight(value, 25);

    private static uint SmallSigma0(uint value) => RotateRight(value, 7) ^ RotateRight(value, 18) ^ (value >> 3);

    private static uint SmallSigma1(uint value) => RotateRight(value, 17) ^ RotateRight(value, 19) ^ (value >> 10);
}

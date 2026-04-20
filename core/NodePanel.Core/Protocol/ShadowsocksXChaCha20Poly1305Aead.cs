using System.Buffers.Binary;
using System.Numerics;
using System.Security.Cryptography;

namespace NodePanel.Core.Protocol;

internal sealed class XChaCha20Poly1305ShadowsocksAead : IShadowsocksAead
{
    private const int KeyBytes = 32;
    private const int NonceBytes = 24;
    private const int HChaChaNonceBytes = 16;
    private const int InnerNonceBytes = 12;
    private const int TagBytes = 16;

    private readonly byte[] _key;

    public XChaCha20Poly1305ShadowsocksAead(byte[] key)
    {
        ArgumentNullException.ThrowIfNull(key);

        if (key.Length != KeyBytes)
        {
            throw new ArgumentOutOfRangeException(nameof(key), $"XChaCha20-Poly1305 key must be {KeyBytes} bytes.");
        }

        _key = key.ToArray();
    }

    public int NonceSize => NonceBytes;

    public int TagSize => TagBytes;

    public void Encrypt(
        ReadOnlySpan<byte> nonce,
        ReadOnlySpan<byte> plaintext,
        Span<byte> ciphertext,
        Span<byte> tag)
    {
        Span<byte> innerNonce = stackalloc byte[InnerNonceBytes];
        var subkey = DeriveSubkey(nonce, innerNonce);
        try
        {
            using var aead = new ChaCha20Poly1305(subkey);
            aead.Encrypt(innerNonce, plaintext, ciphertext, tag, ReadOnlySpan<byte>.Empty);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(subkey);
            CryptographicOperations.ZeroMemory(innerNonce);
        }
    }

    public void Decrypt(
        ReadOnlySpan<byte> nonce,
        ReadOnlySpan<byte> ciphertext,
        ReadOnlySpan<byte> tag,
        Span<byte> plaintext)
    {
        Span<byte> innerNonce = stackalloc byte[InnerNonceBytes];
        var subkey = DeriveSubkey(nonce, innerNonce);
        try
        {
            using var aead = new ChaCha20Poly1305(subkey);
            aead.Decrypt(innerNonce, ciphertext, tag, plaintext, ReadOnlySpan<byte>.Empty);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(subkey);
            CryptographicOperations.ZeroMemory(innerNonce);
        }
    }

    public void Dispose()
        => CryptographicOperations.ZeroMemory(_key);

    private byte[] DeriveSubkey(ReadOnlySpan<byte> nonce, Span<byte> innerNonce)
    {
        if (nonce.Length != NonceBytes)
        {
            throw new ArgumentOutOfRangeException(nameof(nonce), $"XChaCha20-Poly1305 nonce must be {NonceBytes} bytes.");
        }

        innerNonce.Clear();
        nonce.Slice(HChaChaNonceBytes, 8).CopyTo(innerNonce.Slice(4));
        return HChaCha20(_key, nonce[..HChaChaNonceBytes]);
    }

    private static byte[] HChaCha20(ReadOnlySpan<byte> key, ReadOnlySpan<byte> nonce)
    {
        if (key.Length != KeyBytes)
        {
            throw new ArgumentOutOfRangeException(nameof(key), $"HChaCha20 key must be {KeyBytes} bytes.");
        }

        if (nonce.Length != HChaChaNonceBytes)
        {
            throw new ArgumentOutOfRangeException(nameof(nonce), $"HChaCha20 nonce must be {HChaChaNonceBytes} bytes.");
        }

        Span<uint> state =
        [
            0x6170_7865u,
            0x3320_646Eu,
            0x7962_2D32u,
            0x6B20_6574u,
            BinaryPrimitives.ReadUInt32LittleEndian(key),
            BinaryPrimitives.ReadUInt32LittleEndian(key[4..]),
            BinaryPrimitives.ReadUInt32LittleEndian(key[8..]),
            BinaryPrimitives.ReadUInt32LittleEndian(key[12..]),
            BinaryPrimitives.ReadUInt32LittleEndian(key[16..]),
            BinaryPrimitives.ReadUInt32LittleEndian(key[20..]),
            BinaryPrimitives.ReadUInt32LittleEndian(key[24..]),
            BinaryPrimitives.ReadUInt32LittleEndian(key[28..]),
            BinaryPrimitives.ReadUInt32LittleEndian(nonce),
            BinaryPrimitives.ReadUInt32LittleEndian(nonce[4..]),
            BinaryPrimitives.ReadUInt32LittleEndian(nonce[8..]),
            BinaryPrimitives.ReadUInt32LittleEndian(nonce[12..])
        ];

        for (var round = 0; round < 10; round++)
        {
            QuarterRound(ref state[0], ref state[4], ref state[8], ref state[12]);
            QuarterRound(ref state[1], ref state[5], ref state[9], ref state[13]);
            QuarterRound(ref state[2], ref state[6], ref state[10], ref state[14]);
            QuarterRound(ref state[3], ref state[7], ref state[11], ref state[15]);
            QuarterRound(ref state[0], ref state[5], ref state[10], ref state[15]);
            QuarterRound(ref state[1], ref state[6], ref state[11], ref state[12]);
            QuarterRound(ref state[2], ref state[7], ref state[8], ref state[13]);
            QuarterRound(ref state[3], ref state[4], ref state[9], ref state[14]);
        }

        var subkey = new byte[KeyBytes];
        BinaryPrimitives.WriteUInt32LittleEndian(subkey.AsSpan(0, 4), state[0]);
        BinaryPrimitives.WriteUInt32LittleEndian(subkey.AsSpan(4, 4), state[1]);
        BinaryPrimitives.WriteUInt32LittleEndian(subkey.AsSpan(8, 4), state[2]);
        BinaryPrimitives.WriteUInt32LittleEndian(subkey.AsSpan(12, 4), state[3]);
        BinaryPrimitives.WriteUInt32LittleEndian(subkey.AsSpan(16, 4), state[12]);
        BinaryPrimitives.WriteUInt32LittleEndian(subkey.AsSpan(20, 4), state[13]);
        BinaryPrimitives.WriteUInt32LittleEndian(subkey.AsSpan(24, 4), state[14]);
        BinaryPrimitives.WriteUInt32LittleEndian(subkey.AsSpan(28, 4), state[15]);
        return subkey;
    }

    private static void QuarterRound(ref uint a, ref uint b, ref uint c, ref uint d)
    {
        unchecked
        {
            a += b;
            d ^= a;
            d = BitOperations.RotateLeft(d, 16);

            c += d;
            b ^= c;
            b = BitOperations.RotateLeft(b, 12);

            a += b;
            d ^= a;
            d = BitOperations.RotateLeft(d, 8);

            c += d;
            b ^= c;
            b = BitOperations.RotateLeft(b, 7);
        }
    }
}

using System.Security.Cryptography;
using System.Text;

namespace NodePanel.Core.Protocol;

internal static class VmessAeadKdf
{
    private const int HmacBlockSize = 64;
    private static readonly byte[] RootSalt = Encoding.ASCII.GetBytes("VMess AEAD KDF");

    public static byte[] Kdf(ReadOnlySpan<byte> key, params ReadOnlyMemory<byte>[] path)
    {
        Func<byte[], byte[]> hashFunc = static data => HMACSHA256.HashData(RootSalt, data);

        foreach (var pathSegment in path)
        {
            var segment = pathSegment.ToArray();
            var previous = hashFunc;
            hashFunc = data => ComputeNestedHmac(previous, segment, data);
        }

        return hashFunc(key.ToArray());
    }

    public static byte[] Kdf16(ReadOnlySpan<byte> key, params ReadOnlyMemory<byte>[] path)
    {
        var derived = Kdf(key, path);
        return derived.AsSpan(0, 16).ToArray();
    }

    private static byte[] ComputeNestedHmac(
        Func<byte[], byte[]> hashFunc,
        byte[] key,
        byte[] data)
    {
        var normalizedKey = NormalizeKey(key, hashFunc);
        var innerPrefix = new byte[HmacBlockSize];
        var outerPrefix = new byte[HmacBlockSize];

        for (var index = 0; index < HmacBlockSize; index++)
        {
            innerPrefix[index] = (byte)(normalizedKey[index] ^ 0x36);
            outerPrefix[index] = (byte)(normalizedKey[index] ^ 0x5C);
        }

        var inner = new byte[HmacBlockSize + data.Length];
        Buffer.BlockCopy(innerPrefix, 0, inner, 0, HmacBlockSize);
        Buffer.BlockCopy(data, 0, inner, HmacBlockSize, data.Length);
        var innerHash = hashFunc(inner);

        var outer = new byte[HmacBlockSize + innerHash.Length];
        Buffer.BlockCopy(outerPrefix, 0, outer, 0, HmacBlockSize);
        Buffer.BlockCopy(innerHash, 0, outer, HmacBlockSize, innerHash.Length);
        return hashFunc(outer);
    }

    private static byte[] NormalizeKey(byte[] key, Func<byte[], byte[]> hashFunc)
    {
        var normalized = key.Length > HmacBlockSize
            ? hashFunc(key)
            : key.ToArray();

        if (normalized.Length == HmacBlockSize)
        {
            return normalized;
        }

        var padded = new byte[HmacBlockSize];
        Buffer.BlockCopy(normalized, 0, padded, 0, normalized.Length);
        return padded;
    }
}

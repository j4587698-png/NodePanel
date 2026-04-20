using System.Numerics;
using System.Security.Cryptography;

namespace NodePanel.Core.Runtime;

internal static class RuntimeHkdf
{
    public static byte[] Extract(
        HashAlgorithmName hashAlgorithm,
        ReadOnlySpan<byte> inputKeyMaterial,
        ReadOnlySpan<byte> salt)
        => RuntimeCryptographicHashes.Hmac(hashAlgorithm, salt, inputKeyMaterial);

    public static byte[] ExtractSha256(
        ReadOnlySpan<byte> inputKeyMaterial,
        ReadOnlySpan<byte> salt)
        => Extract(HashAlgorithmName.SHA256, inputKeyMaterial, salt);

    public static byte[] ExtractAndExpandSha256(
        ReadOnlySpan<byte> inputKeyMaterial,
        ReadOnlySpan<byte> salt,
        ReadOnlySpan<byte> info,
        int length)
    {
        if (length < 0)
        {
            throw new ArgumentOutOfRangeException(nameof(length), length, "The HKDF output length must be non-negative.");
        }

        var pseudorandomKey = ExtractSha256(inputKeyMaterial, salt);
        return ExpandSha256(pseudorandomKey, info, length);
    }

    public static byte[] Expand(
        HashAlgorithmName hashAlgorithm,
        int hashLength,
        ReadOnlySpan<byte> pseudorandomKey,
        ReadOnlySpan<byte> info,
        int length)
    {
        if (length < 0)
        {
            throw new ArgumentOutOfRangeException(nameof(length), length, "The HKDF output length must be non-negative.");
        }

        if (length == 0)
        {
            return Array.Empty<byte>();
        }

        var output = new byte[length];
        var previous = Array.Empty<byte>();
        var offset = 0;
        byte counter = 1;

        while (offset < output.Length)
        {
            var input = new byte[previous.Length + info.Length + 1];
            if (previous.Length > 0)
            {
                previous.CopyTo(input, 0);
            }

            info.CopyTo(input.AsSpan(previous.Length));
            input[^1] = counter++;

            var block = RuntimeCryptographicHashes.Hmac(hashAlgorithm, pseudorandomKey, input);
            if (block.Length != hashLength)
            {
                throw new CryptographicException(
                    $"The HMAC output length for '{hashAlgorithm.Name}' did not match the expected digest size.");
            }

            previous = block;

            var copyLength = Math.Min(block.Length, output.Length - offset);
            block.AsSpan(0, copyLength).CopyTo(output.AsSpan(offset));
            offset += copyLength;
        }

        return output;
    }

    public static byte[] ExpandSha256(
        ReadOnlySpan<byte> pseudorandomKey,
        ReadOnlySpan<byte> info,
        int length)
    {
        if (length < 0)
        {
            throw new ArgumentOutOfRangeException(nameof(length), length, "The HKDF output length must be non-negative.");
        }

        if (length == 0)
        {
            return Array.Empty<byte>();
        }

        return Expand(HashAlgorithmName.SHA256, hashLength: 32, pseudorandomKey, info, length);
    }

    public static byte[] ExpandLabelSha256(
        ReadOnlySpan<byte> secret,
        string label,
        int length)
        => ExpandLabelSha256(secret, label, ReadOnlySpan<byte>.Empty, length);

    public static byte[] ExpandLabelSha256(
        ReadOnlySpan<byte> secret,
        string label,
        ReadOnlySpan<byte> context,
        int length)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(label);

        var labelBytes = System.Text.Encoding.ASCII.GetBytes("tls13 " + label.Trim());
        if (context.Length > byte.MaxValue)
        {
            throw new ArgumentOutOfRangeException(nameof(context), "The HKDF label context must be 255 bytes or fewer.");
        }

        var info = new byte[2 + 1 + labelBytes.Length + 1 + context.Length];
        System.Buffers.Binary.BinaryPrimitives.WriteUInt16BigEndian(info.AsSpan(0, 2), checked((ushort)length));
        info[2] = checked((byte)labelBytes.Length);
        labelBytes.CopyTo(info.AsSpan(3));
        var contextOffset = 3 + labelBytes.Length;
        info[contextOffset] = checked((byte)context.Length);
        if (context.Length > 0)
        {
            context.CopyTo(info.AsSpan(contextOffset + 1));
        }

        return ExpandSha256(secret, info, length);
    }

    public static byte[] ExpandLabel(
        HashAlgorithmName hashAlgorithm,
        int hashLength,
        ReadOnlySpan<byte> secret,
        string label,
        ReadOnlySpan<byte> context,
        int length)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(label);

        var labelBytes = System.Text.Encoding.ASCII.GetBytes("tls13 " + label.Trim());
        if (context.Length > byte.MaxValue)
        {
            throw new ArgumentOutOfRangeException(nameof(context), "The HKDF label context must be 255 bytes or fewer.");
        }

        var info = new byte[2 + 1 + labelBytes.Length + 1 + context.Length];
        System.Buffers.Binary.BinaryPrimitives.WriteUInt16BigEndian(info.AsSpan(0, 2), checked((ushort)length));
        info[2] = checked((byte)labelBytes.Length);
        labelBytes.CopyTo(info.AsSpan(3));
        var contextOffset = 3 + labelBytes.Length;
        info[contextOffset] = checked((byte)context.Length);
        if (context.Length > 0)
        {
            context.CopyTo(info.AsSpan(contextOffset + 1));
        }

        return Expand(hashAlgorithm, hashLength, secret, info, length);
    }
}

internal static class RuntimeCryptographicHashes
{
    public static byte[] HashLegacyMd5Sha1(ReadOnlySpan<byte> data)
    {
        var md5 = Hash(HashAlgorithmName.MD5, data);
        var sha1 = Hash(HashAlgorithmName.SHA1, data);
        var digest = new byte[md5.Length + sha1.Length];
        md5.CopyTo(digest, 0);
        sha1.CopyTo(digest.AsSpan(md5.Length));
        return digest;
    }

    public static byte[] Hash(HashAlgorithmName hashAlgorithm, ReadOnlySpan<byte> data)
        => hashAlgorithm.Name switch
        {
            nameof(HashAlgorithmName.MD5) => MD5.HashData(data),
            nameof(HashAlgorithmName.SHA1) => SHA1.HashData(data),
            nameof(HashAlgorithmName.SHA256) => SHA256.HashData(data),
            nameof(HashAlgorithmName.SHA384) => SHA384.HashData(data),
            nameof(HashAlgorithmName.SHA512) => SHA512.HashData(data),
            _ => throw new NotSupportedException(
                $"Hash algorithm '{hashAlgorithm.Name}' is not supported.")
        };

    public static byte[] Hmac(
        HashAlgorithmName hashAlgorithm,
        ReadOnlySpan<byte> key,
        ReadOnlySpan<byte> data)
        => hashAlgorithm.Name switch
        {
            nameof(HashAlgorithmName.MD5) => HMACMD5.HashData(key.ToArray(), data.ToArray()),
            nameof(HashAlgorithmName.SHA1) => HMACSHA1.HashData(key.ToArray(), data.ToArray()),
            nameof(HashAlgorithmName.SHA256) => HMACSHA256.HashData(key.ToArray(), data.ToArray()),
            nameof(HashAlgorithmName.SHA384) => HMACSHA384.HashData(key.ToArray(), data.ToArray()),
            nameof(HashAlgorithmName.SHA512) => HMACSHA512.HashData(key.ToArray(), data.ToArray()),
            _ => throw new NotSupportedException(
                $"HMAC hash algorithm '{hashAlgorithm.Name}' is not supported.")
        };
}

internal static class RuntimeRsaPkcs1SignaturePrimitives
{
    public static byte[] ComputeLegacyMd5Sha1Digest(ReadOnlySpan<byte> data)
        => RuntimeCryptographicHashes.HashLegacyMd5Sha1(data);

    public static byte[] SignLegacyMd5Sha1(RSA rsa, ReadOnlySpan<byte> data)
    {
        ArgumentNullException.ThrowIfNull(rsa);
        return SignLegacyMd5Sha1Digest(
            rsa.ExportParameters(includePrivateParameters: true),
            ComputeLegacyMd5Sha1Digest(data));
    }

    public static bool VerifyLegacyMd5Sha1(
        RSA rsa,
        ReadOnlySpan<byte> data,
        ReadOnlySpan<byte> signature)
    {
        ArgumentNullException.ThrowIfNull(rsa);
        return VerifyLegacyMd5Sha1Digest(
            rsa.ExportParameters(includePrivateParameters: false),
            ComputeLegacyMd5Sha1Digest(data),
            signature);
    }

    public static byte[] SignLegacyMd5Sha1Digest(
        RSAParameters parameters,
        ReadOnlySpan<byte> digest)
    {
        if (parameters.Modulus is null || parameters.D is null)
        {
            throw new CryptographicException("The RSA private key is missing modulus or private exponent data.");
        }

        var encodedMessage = EncodePkcs1V15SignatureBlock(parameters.Modulus.Length, digest);
        var messageInteger = new BigInteger(encodedMessage, isUnsigned: true, isBigEndian: true);
        var privateExponent = new BigInteger(parameters.D, isUnsigned: true, isBigEndian: true);
        var modulus = new BigInteger(parameters.Modulus, isUnsigned: true, isBigEndian: true);
        var signature = BigInteger
            .ModPow(messageInteger, privateExponent, modulus)
            .ToByteArray(isUnsigned: true, isBigEndian: true);
        return LeftPad(signature, parameters.Modulus.Length);
    }

    public static bool VerifyLegacyMd5Sha1Digest(
        RSAParameters parameters,
        ReadOnlySpan<byte> digest,
        ReadOnlySpan<byte> signature)
    {
        if (parameters.Modulus is null || parameters.Exponent is null)
        {
            return false;
        }

        var modulusLength = parameters.Modulus.Length;
        if (signature.Length != modulusLength)
        {
            return false;
        }

        var signatureInteger = new BigInteger(signature, isUnsigned: true, isBigEndian: true);
        var publicExponent = new BigInteger(parameters.Exponent, isUnsigned: true, isBigEndian: true);
        var modulus = new BigInteger(parameters.Modulus, isUnsigned: true, isBigEndian: true);
        if (signatureInteger >= modulus)
        {
            return false;
        }

        var encodedMessage = BigInteger
            .ModPow(signatureInteger, publicExponent, modulus)
            .ToByteArray(isUnsigned: true, isBigEndian: true);
        var expected = EncodePkcs1V15SignatureBlock(modulusLength, digest);
        return CryptographicOperations.FixedTimeEquals(expected, LeftPad(encodedMessage, modulusLength));
    }

    private static byte[] EncodePkcs1V15SignatureBlock(int modulusLength, ReadOnlySpan<byte> digest)
    {
        if (modulusLength < digest.Length + 11)
        {
            throw new CryptographicException("The RSA modulus is too small for a PKCS#1 v1.5 signature block.");
        }

        var encoded = new byte[modulusLength];
        encoded[0] = 0x00;
        encoded[1] = 0x01;
        var separatorIndex = modulusLength - digest.Length - 1;
        encoded.AsSpan(2, separatorIndex - 2).Fill(0xFF);
        encoded[separatorIndex] = 0x00;
        digest.CopyTo(encoded.AsSpan(separatorIndex + 1));
        return encoded;
    }

    private static byte[] LeftPad(ReadOnlySpan<byte> value, int length)
    {
        if (value.Length > length)
        {
            throw new CryptographicException("The RSA primitive returned a value larger than the modulus.");
        }

        if (value.Length == length)
        {
            return value.ToArray();
        }

        var padded = new byte[length];
        value.CopyTo(padded.AsSpan(length - value.Length));
        return padded;
    }
}

internal sealed record RuntimePrimeCurveKeyPair(
    byte[] PrivateKey,
    byte[] PublicKey) : IDisposable
{
    public void Dispose()
    {
    }
}

internal static class RuntimePrimeCurveDiffieHellman
{
    public static RuntimePrimeCurveKeyPair CreateKeyPair(
        ECCurve namedCurve,
        RuntimePrimeCurveDefinition definition)
    {
        using var algorithm = ECDiffieHellman.Create();
        algorithm.GenerateKey(namedCurve);

        var parameters = algorithm.ExportParameters(includePrivateParameters: true);
        if (parameters.D is null || parameters.Q.X is null || parameters.Q.Y is null)
        {
            throw new CryptographicException("Failed to export the elliptic-curve key pair.");
        }

        return new RuntimePrimeCurveKeyPair(
            NormalizeFieldElement(parameters.D, definition.PrivateKeyLength),
            EncodeUncompressedPoint(parameters.Q.X, parameters.Q.Y, definition.PrivateKeyLength));
    }

    public static byte[] DeriveSharedSecret(
        ReadOnlySpan<byte> privateKey,
        ReadOnlySpan<byte> peerPublicKey,
        RuntimePrimeCurveDefinition definition,
        string curveName)
    {
        if (privateKey.Length != definition.PrivateKeyLength)
        {
            throw new ArgumentOutOfRangeException(
                nameof(privateKey),
                $"The {curveName} private key must be {definition.PrivateKeyLength} bytes.");
        }

        if (peerPublicKey.Length != definition.PublicKeyLength)
        {
            throw new ArgumentOutOfRangeException(
                nameof(peerPublicKey),
                $"The {curveName} public key must be {definition.PublicKeyLength} bytes.");
        }

        var scalar = DecodeBigEndian(privateKey);
        if (scalar.Sign <= 0 || scalar >= definition.GroupOrder)
        {
            throw new ArgumentOutOfRangeException(nameof(privateKey), $"The {curveName} private key is out of range.");
        }

        var peerPoint = DecodePeerPublicKey(peerPublicKey, definition, curveName);
        var sharedPoint = Multiply(peerPoint, scalar, definition);
        if (sharedPoint.IsInfinity)
        {
            throw new CryptographicException($"The {curveName} shared secret resolved to the point at infinity.");
        }

        return EncodeFieldElement(sharedPoint.X, definition);
    }

    public static BigInteger ParseHex(string hex)
        => BigInteger.Parse($"00{hex}", System.Globalization.NumberStyles.HexNumber);

    public static byte[] NormalizeFieldElement(ReadOnlySpan<byte> value, int length)
    {
        if (value.Length == length)
        {
            return value.ToArray();
        }

        if (value.Length > length)
        {
            return value.Slice(value.Length - length, length).ToArray();
        }

        var normalized = new byte[length];
        value.CopyTo(normalized.AsSpan(length - value.Length));
        return normalized;
    }

    private static RuntimePrimeCurvePoint DecodePeerPublicKey(
        ReadOnlySpan<byte> peerPublicKey,
        RuntimePrimeCurveDefinition definition,
        string curveName)
    {
        if (peerPublicKey[0] != 0x04)
        {
            throw new CryptographicException($"The {curveName} public key must use uncompressed point format.");
        }

        var x = DecodeBigEndian(peerPublicKey.Slice(1, definition.PrivateKeyLength));
        var y = DecodeBigEndian(peerPublicKey.Slice(1 + definition.PrivateKeyLength, definition.PrivateKeyLength));
        var point = new RuntimePrimeCurvePoint(x, y);
        if (!IsOnCurve(point, definition))
        {
            throw new CryptographicException($"The {curveName} public key is not on the curve.");
        }

        return point;
    }

    private static RuntimePrimeCurvePoint Multiply(
        RuntimePrimeCurvePoint point,
        BigInteger scalar,
        RuntimePrimeCurveDefinition definition)
    {
        var result = RuntimePrimeCurvePoint.Infinity;
        var addend = point;
        var current = scalar;

        while (current > 0)
        {
            if (!current.IsEven)
            {
                result = Add(result, addend, definition);
            }

            addend = Double(addend, definition);
            current >>= 1;
        }

        return result;
    }

    private static RuntimePrimeCurvePoint Add(
        RuntimePrimeCurvePoint left,
        RuntimePrimeCurvePoint right,
        RuntimePrimeCurveDefinition definition)
    {
        if (left.IsInfinity)
        {
            return right;
        }

        if (right.IsInfinity)
        {
            return left;
        }

        if (left.X == right.X)
        {
            if (Mod(left.Y + right.Y, definition) == 0)
            {
                return RuntimePrimeCurvePoint.Infinity;
            }

            return Double(left, definition);
        }

        var lambda = Mod((right.Y - left.Y) * ModInverse(right.X - left.X, definition), definition);
        var x = Mod(lambda * lambda - left.X - right.X, definition);
        var y = Mod(lambda * (left.X - x) - left.Y, definition);
        return new RuntimePrimeCurvePoint(x, y);
    }

    private static RuntimePrimeCurvePoint Double(RuntimePrimeCurvePoint point, RuntimePrimeCurveDefinition definition)
    {
        if (point.IsInfinity || point.Y.IsZero)
        {
            return RuntimePrimeCurvePoint.Infinity;
        }

        var lambda = Mod((3 * point.X * point.X + definition.CurveA) * ModInverse(2 * point.Y, definition), definition);
        var x = Mod(lambda * lambda - (2 * point.X), definition);
        var y = Mod(lambda * (point.X - x) - point.Y, definition);
        return new RuntimePrimeCurvePoint(x, y);
    }

    private static bool IsOnCurve(RuntimePrimeCurvePoint point, RuntimePrimeCurveDefinition definition)
    {
        if (point.IsInfinity)
        {
            return false;
        }

        var left = Mod(point.Y * point.Y, definition);
        var right = Mod((point.X * point.X * point.X) + (definition.CurveA * point.X) + definition.CurveB, definition);
        return left == right;
    }

    private static BigInteger ModInverse(BigInteger value, RuntimePrimeCurveDefinition definition)
        => BigInteger.ModPow(Mod(value, definition), definition.FieldPrime - 2, definition.FieldPrime);

    private static BigInteger Mod(BigInteger value, RuntimePrimeCurveDefinition definition)
    {
        var result = value % definition.FieldPrime;
        return result.Sign < 0 ? result + definition.FieldPrime : result;
    }

    private static BigInteger DecodeBigEndian(ReadOnlySpan<byte> value)
        => new(value.ToArray(), isUnsigned: true, isBigEndian: true);

    private static byte[] EncodeUncompressedPoint(ReadOnlySpan<byte> x, ReadOnlySpan<byte> y, int coordinateLength)
    {
        var publicKey = new byte[(coordinateLength * 2) + 1];
        publicKey[0] = 0x04;
        NormalizeFieldElement(x, coordinateLength).CopyTo(publicKey.AsSpan(1, coordinateLength));
        NormalizeFieldElement(y, coordinateLength).CopyTo(publicKey.AsSpan(1 + coordinateLength, coordinateLength));
        return publicKey;
    }

    private static byte[] EncodeFieldElement(BigInteger value, RuntimePrimeCurveDefinition definition)
    {
        var encoded = Mod(value, definition).ToByteArray(isUnsigned: true, isBigEndian: true);
        if (encoded.Length == definition.PrivateKeyLength)
        {
            return encoded;
        }

        if (encoded.Length > definition.PrivateKeyLength)
        {
            return encoded.AsSpan(encoded.Length - definition.PrivateKeyLength, definition.PrivateKeyLength).ToArray();
        }

        var output = new byte[definition.PrivateKeyLength];
        encoded.CopyTo(output.AsSpan(definition.PrivateKeyLength - encoded.Length));
        return output;
    }

    internal sealed record RuntimePrimeCurveDefinition(
        BigInteger FieldPrime,
        BigInteger CurveA,
        BigInteger CurveB,
        BigInteger GroupOrder,
        int PrivateKeyLength,
        int PublicKeyLength);

    private readonly record struct RuntimePrimeCurvePoint(BigInteger X, BigInteger Y, bool IsInfinity = false)
    {
        public static RuntimePrimeCurvePoint Infinity { get; } = new(BigInteger.Zero, BigInteger.Zero, true);
    }
}

internal static class RuntimeSecp256r1
{
    public const int PrivateKeyLength = 32;
    public const int PublicKeyLength = 65;

    private static readonly RuntimePrimeCurveDiffieHellman.RuntimePrimeCurveDefinition Definition = new(
        FieldPrime: RuntimePrimeCurveDiffieHellman.ParseHex("FFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF"),
        CurveA: RuntimePrimeCurveDiffieHellman.ParseHex("FFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFC"),
        CurveB: RuntimePrimeCurveDiffieHellman.ParseHex("5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B"),
        GroupOrder: RuntimePrimeCurveDiffieHellman.ParseHex("FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551"),
        PrivateKeyLength,
        PublicKeyLength);

    public static RuntimeSecp256r1KeyPair CreateKeyPair()
    {
        using var keyPair = RuntimePrimeCurveDiffieHellman.CreateKeyPair(ECCurve.NamedCurves.nistP256, Definition);
        return new RuntimeSecp256r1KeyPair(keyPair.PrivateKey, keyPair.PublicKey);
    }

    public static byte[] DeriveSharedSecret(ReadOnlySpan<byte> privateKey, ReadOnlySpan<byte> peerPublicKey)
        => RuntimePrimeCurveDiffieHellman.DeriveSharedSecret(privateKey, peerPublicKey, Definition, "secp256r1");
}

internal sealed record RuntimeSecp256r1KeyPair(
    byte[] PrivateKey,
    byte[] PublicKey) : IDisposable
{
    public void Dispose()
    {
    }
}

internal static class RuntimeSecp384r1
{
    public const int PrivateKeyLength = 48;
    public const int PublicKeyLength = 97;

    private static readonly RuntimePrimeCurveDiffieHellman.RuntimePrimeCurveDefinition Definition = new(
        FieldPrime: RuntimePrimeCurveDiffieHellman.ParseHex("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFFFF0000000000000000FFFFFFFF"),
        CurveA: RuntimePrimeCurveDiffieHellman.ParseHex("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFFFF0000000000000000FFFFFFFC"),
        CurveB: RuntimePrimeCurveDiffieHellman.ParseHex("B3312FA7E23EE7E4988E056BE3F82D19181D9C6EFE8141120314088F5013875AC656398D8A2ED19D2A85C8EDD3EC2AEF"),
        GroupOrder: RuntimePrimeCurveDiffieHellman.ParseHex("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFC7634D81F4372DDF581A0DB248B0A77AECEC196ACCC52973"),
        PrivateKeyLength,
        PublicKeyLength);

    public static RuntimeSecp384r1KeyPair CreateKeyPair()
    {
        using var keyPair = RuntimePrimeCurveDiffieHellman.CreateKeyPair(ECCurve.NamedCurves.nistP384, Definition);
        return new RuntimeSecp384r1KeyPair(keyPair.PrivateKey, keyPair.PublicKey);
    }

    public static byte[] DeriveSharedSecret(ReadOnlySpan<byte> privateKey, ReadOnlySpan<byte> peerPublicKey)
        => RuntimePrimeCurveDiffieHellman.DeriveSharedSecret(privateKey, peerPublicKey, Definition, "secp384r1");
}

internal sealed record RuntimeSecp384r1KeyPair(
    byte[] PrivateKey,
    byte[] PublicKey) : IDisposable
{
    public void Dispose()
    {
    }
}

internal static class RuntimeSecp521r1
{
    public const int PrivateKeyLength = 66;
    public const int PublicKeyLength = 133;

    private static readonly RuntimePrimeCurveDiffieHellman.RuntimePrimeCurveDefinition Definition = new(
        FieldPrime: RuntimePrimeCurveDiffieHellman.ParseHex("01FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF"),
        CurveA: RuntimePrimeCurveDiffieHellman.ParseHex("01FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFC"),
        CurveB: RuntimePrimeCurveDiffieHellman.ParseHex("0051953EB9618E1C9A1F929A21A0B68540EEA2DA725B99B315F3B8B489918EF109E156193951EC7E937B1652C0BD3BB1BF073573DF883D2C34F1EF451FD46B503F00"),
        GroupOrder: RuntimePrimeCurveDiffieHellman.ParseHex("01FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFA51868783BF2F966B7FCC0148F709A5D03BB5C9B8899C47AEBB6FB71E91386409"),
        PrivateKeyLength,
        PublicKeyLength);

    public static RuntimeSecp521r1KeyPair CreateKeyPair()
    {
        using var keyPair = RuntimePrimeCurveDiffieHellman.CreateKeyPair(ECCurve.NamedCurves.nistP521, Definition);
        return new RuntimeSecp521r1KeyPair(keyPair.PrivateKey, keyPair.PublicKey);
    }

    public static byte[] DeriveSharedSecret(ReadOnlySpan<byte> privateKey, ReadOnlySpan<byte> peerPublicKey)
        => RuntimePrimeCurveDiffieHellman.DeriveSharedSecret(privateKey, peerPublicKey, Definition, "secp521r1");
}

internal sealed record RuntimeSecp521r1KeyPair(
    byte[] PrivateKey,
    byte[] PublicKey) : IDisposable
{
    public void Dispose()
    {
    }
}

internal static class RuntimeEd25519
{
    public const int PrivateKeyLength = 32;
    public const int PublicKeyLength = 32;
    public const int SignatureLength = 64;

    private static readonly BigInteger Prime = (BigInteger.One << 255) - 19;
    private static readonly BigInteger GroupOrder =
        (BigInteger.One << 252) +
        BigInteger.Parse("27742317777372353535851937790883648493");
    private static readonly BigInteger CurveD = Mod(-121665 * ModInverse(121666));
    private static readonly BigInteger SqrtMinusOne = BigInteger.ModPow(2, (Prime - 1) / 4, Prime);
    private static readonly RuntimeEd25519Point BasePoint = CreateBasePoint();

    public static byte[] DerivePublicKey(ReadOnlySpan<byte> privateKey)
    {
        var expandedKey = ExpandPrivateKey(privateKey);
        return EncodePoint(Multiply(BasePoint, expandedKey.Scalar));
    }

    public static byte[] Sign(
        ReadOnlySpan<byte> privateKey,
        ReadOnlySpan<byte> message)
    {
        var expandedKey = ExpandPrivateKey(privateKey);
        var publicKey = EncodePoint(Multiply(BasePoint, expandedKey.Scalar));

        var nonceInput = new byte[expandedKey.Prefix.Length + message.Length];
        expandedKey.Prefix.CopyTo(nonceInput, 0);
        message.CopyTo(nonceInput.AsSpan(expandedKey.Prefix.Length));
        var nonce = ReduceModGroupOrder(SHA512.HashData(nonceInput));

        var encodedR = EncodePoint(Multiply(BasePoint, nonce));
        var challengeInput = new byte[(2 * PublicKeyLength) + message.Length];
        encodedR.CopyTo(challengeInput);
        publicKey.CopyTo(challengeInput.AsSpan(PublicKeyLength));
        message.CopyTo(challengeInput.AsSpan(2 * PublicKeyLength));
        var challenge = ReduceModGroupOrder(SHA512.HashData(challengeInput));
        var scalarS = ModGroupOrder(nonce + (challenge * expandedKey.Scalar));

        var signature = new byte[SignatureLength];
        encodedR.CopyTo(signature);
        EncodeLittleEndian(scalarS, PublicKeyLength).CopyTo(signature.AsSpan(PublicKeyLength));
        return signature;
    }

    public static bool Verify(
        ReadOnlySpan<byte> signature,
        ReadOnlySpan<byte> message,
        ReadOnlySpan<byte> publicKey)
    {
        if (signature.Length != SignatureLength || publicKey.Length != PublicKeyLength)
        {
            return false;
        }

        if (!TryDecodePoint(publicKey, out var publicPoint))
        {
            return false;
        }

        var encodedR = signature[..PublicKeyLength];
        if (!TryDecodePoint(encodedR, out var rPoint))
        {
            return false;
        }

        var scalarS = DecodeLittleEndian(signature[PublicKeyLength..]);
        if (scalarS.Sign < 0 || scalarS >= GroupOrder)
        {
            return false;
        }

        var challengeInput = new byte[(2 * PublicKeyLength) + message.Length];
        encodedR.CopyTo(challengeInput);
        publicKey.CopyTo(challengeInput.AsSpan(PublicKeyLength));
        message.CopyTo(challengeInput.AsSpan(2 * PublicKeyLength));
        var challenge = ReduceModGroupOrder(SHA512.HashData(challengeInput));

        var left = Multiply(BasePoint, 8 * scalarS);
        var right = Add(
            Multiply(rPoint, 8),
            Multiply(publicPoint, 8 * challenge));
        return left.Equals(right);
    }

    private static RuntimeEd25519Point CreateBasePoint()
    {
        var y = Mod(4 * ModInverse(5));
        var ySquared = Mod(y * y);
        var u = Mod(ySquared - 1);
        var v = Mod((CurveD * ySquared) + 1);
        if (!TryRecoverX(u, v, xIsOdd: false, out var x))
        {
            throw new CryptographicException("Failed to derive the Ed25519 base point.");
        }

        return new RuntimeEd25519Point(x, y);
    }

    private static RuntimeEd25519ExpandedKey ExpandPrivateKey(ReadOnlySpan<byte> privateKey)
    {
        if (privateKey.Length != PrivateKeyLength)
        {
            throw new ArgumentOutOfRangeException(nameof(privateKey), "The Ed25519 private key must be 32 bytes.");
        }

        var hash = SHA512.HashData(privateKey);
        hash[0] &= 248;
        hash[31] &= 63;
        hash[31] |= 64;
        return new RuntimeEd25519ExpandedKey(
            DecodeLittleEndian(hash.AsSpan(0, PrivateKeyLength)),
            hash.AsSpan(PrivateKeyLength, PrivateKeyLength).ToArray());
    }

    private static bool TryDecodePoint(ReadOnlySpan<byte> encodedPoint, out RuntimeEd25519Point point)
    {
        point = RuntimeEd25519Point.Identity;
        var buffer = encodedPoint.ToArray();
        var xIsOdd = (buffer[^1] & 0x80) != 0;
        buffer[^1] &= 0x7F;

        var y = DecodeLittleEndian(buffer);
        if (y.Sign < 0 || y >= Prime)
        {
            return false;
        }

        var ySquared = Mod(y * y);
        var u = Mod(ySquared - 1);
        var v = Mod((CurveD * ySquared) + 1);
        if (!TryRecoverX(u, v, xIsOdd, out var x))
        {
            return false;
        }

        point = new RuntimeEd25519Point(x, y);
        return IsOnCurve(point);
    }

    private static bool TryRecoverX(
        BigInteger u,
        BigInteger v,
        bool xIsOdd,
        out BigInteger x)
    {
        var vSquared = Mod(v * v);
        var vFourth = Mod(vSquared * vSquared);
        var vSeventh = Mod(vFourth * vSquared * v);
        x = Mod(BigInteger.ModPow(Mod(u * vSeventh), (Prime - 5) / 8, Prime) * u * Mod(vSquared * v));
        var check = Mod(v * x * x);
        if (check != u)
        {
            if (check != Mod(-u))
            {
                return false;
            }

            x = Mod(x * SqrtMinusOne);
            if (Mod(v * x * x) != u)
            {
                return false;
            }
        }

        if (x.IsEven == xIsOdd)
        {
            x = Mod(Prime - x);
        }

        return !(x.IsZero && xIsOdd);
    }

    private static RuntimeEd25519Point Multiply(RuntimeEd25519Point point, BigInteger scalar)
    {
        var result = RuntimeEd25519Point.Identity;
        var addend = point;
        var current = scalar % GroupOrder;
        if (current.Sign < 0)
        {
            current += GroupOrder;
        }

        while (current > 0)
        {
            if (!current.IsEven)
            {
                result = Add(result, addend);
            }

            addend = Add(addend, addend);
            current >>= 1;
        }

        return result;
    }

    private static RuntimeEd25519Point Add(RuntimeEd25519Point left, RuntimeEd25519Point right)
    {
        var product = Mod(left.X * right.X * left.Y * right.Y);
        var denominatorX = Mod(1 + (CurveD * product));
        var denominatorY = Mod(1 - (CurveD * product));
        var x = Mod((left.X * right.Y + left.Y * right.X) * ModInverse(denominatorX));
        var y = Mod((left.Y * right.Y + left.X * right.X) * ModInverse(denominatorY));
        return new RuntimeEd25519Point(x, y);
    }

    private static bool IsOnCurve(RuntimeEd25519Point point)
        => Mod(point.Y * point.Y - point.X * point.X - 1 - (CurveD * point.X * point.X * point.Y * point.Y)) == 0;

    private static byte[] EncodePoint(RuntimeEd25519Point point)
    {
        var encoded = EncodeLittleEndian(point.Y, PublicKeyLength);
        if (!point.X.IsEven)
        {
            encoded[^1] |= 0x80;
        }

        return encoded;
    }

    private static byte[] EncodeLittleEndian(BigInteger value, int length)
    {
        var encoded = value.ToByteArray(isUnsigned: true, isBigEndian: false);
        if (encoded.Length == length)
        {
            return encoded;
        }

        var output = new byte[length];
        encoded.AsSpan(0, Math.Min(encoded.Length, output.Length)).CopyTo(output);
        return output;
    }

    private static BigInteger ReduceModGroupOrder(ReadOnlySpan<byte> value)
        => DecodeLittleEndian(value) % GroupOrder;

    private static BigInteger ModGroupOrder(BigInteger value)
    {
        var result = value % GroupOrder;
        return result.Sign < 0 ? result + GroupOrder : result;
    }

    private static BigInteger DecodeLittleEndian(ReadOnlySpan<byte> value)
        => new(value.ToArray(), isUnsigned: true, isBigEndian: false);

    private static BigInteger ModInverse(BigInteger value)
        => BigInteger.ModPow(Mod(value), Prime - 2, Prime);

    private static BigInteger Mod(BigInteger value)
    {
        var result = value % Prime;
        return result.Sign < 0 ? result + Prime : result;
    }

    private readonly record struct RuntimeEd25519Point(BigInteger X, BigInteger Y)
    {
        public static RuntimeEd25519Point Identity { get; } = new(BigInteger.Zero, BigInteger.One);
    }

    private sealed record RuntimeEd25519ExpandedKey(
        BigInteger Scalar,
        byte[] Prefix);
}

internal static class RuntimeX25519
{
    public const int KeyLength = 32;

    private static readonly BigInteger Prime = (BigInteger.One << 255) - 19;
    private static readonly BigInteger A24 = new(121665);

    public static RuntimeX25519KeyPair CreateKeyPair()
    {
        var privateKey = RandomNumberGenerator.GetBytes(KeyLength);
        ClampScalar(privateKey);
        return new RuntimeX25519KeyPair(privateKey, DerivePublicKey(privateKey));
    }

    public static byte[] DerivePublicKey(ReadOnlySpan<byte> privateKey)
        => X25519(privateKey, CreateBasePoint());

    public static byte[] DeriveSharedSecret(ReadOnlySpan<byte> privateKey, ReadOnlySpan<byte> peerPublicKey)
    {
        if (privateKey.Length != KeyLength)
        {
            throw new ArgumentOutOfRangeException(nameof(privateKey), "The X25519 private key must be 32 bytes.");
        }

        if (peerPublicKey.Length != KeyLength)
        {
            throw new ArgumentOutOfRangeException(nameof(peerPublicKey), "The X25519 public key must be 32 bytes.");
        }

        return X25519(privateKey, peerPublicKey);
    }

    private static byte[] X25519(ReadOnlySpan<byte> scalar, ReadOnlySpan<byte> uCoordinate)
    {
        var clampedScalar = scalar.ToArray();
        ClampScalar(clampedScalar);

        var x1 = DecodeLittleEndian(uCoordinate, maskHighBit: true);
        var x2 = BigInteger.One;
        var z2 = BigInteger.Zero;
        var x3 = x1;
        var z3 = BigInteger.One;
        var swap = 0;

        for (var bit = 254; bit >= 0; bit--)
        {
            var bitValue = (clampedScalar[bit >> 3] >> (bit & 7)) & 1;
            if (swap != bitValue)
            {
                (x2, x3) = (x3, x2);
                (z2, z3) = (z3, z2);
            }

            swap = bitValue;

            var a = Mod(x2 + z2);
            var aa = Mod(a * a);
            var b = Mod(x2 - z2);
            var bb = Mod(b * b);
            var e = Mod(aa - bb);
            var c = Mod(x3 + z3);
            var d = Mod(x3 - z3);
            var da = Mod(d * a);
            var cb = Mod(c * b);
            var x3Next = Mod((da + cb) * (da + cb));
            var z3Next = Mod(x1 * Mod((da - cb) * (da - cb)));
            var x2Next = Mod(aa * bb);
            var z2Next = Mod(e * Mod(aa + A24 * e));

            x3 = x3Next;
            z3 = z3Next;
            x2 = x2Next;
            z2 = z2Next;
        }

        if (swap != 0)
        {
            (x2, x3) = (x3, x2);
            (z2, z3) = (z3, z2);
        }

        return EncodeLittleEndian(Mod(x2 * BigInteger.ModPow(z2, Prime - 2, Prime)));
    }

    private static void ClampScalar(byte[] scalar)
    {
        if (scalar.Length != KeyLength)
        {
            throw new ArgumentOutOfRangeException(nameof(scalar), "The X25519 scalar must be 32 bytes.");
        }

        scalar[0] &= 248;
        scalar[31] &= 127;
        scalar[31] |= 64;
    }

    private static BigInteger DecodeLittleEndian(ReadOnlySpan<byte> value, bool maskHighBit)
    {
        var buffer = value.ToArray();
        if (maskHighBit && buffer.Length > 0)
        {
            buffer[^1] &= 0x7F;
        }

        return new BigInteger(buffer, isUnsigned: true, isBigEndian: false);
    }

    private static byte[] EncodeLittleEndian(BigInteger value)
    {
        var encoded = Mod(value).ToByteArray(isUnsigned: true, isBigEndian: false);
        if (encoded.Length == KeyLength)
        {
            return encoded;
        }

        var output = new byte[KeyLength];
        encoded.AsSpan(0, Math.Min(encoded.Length, output.Length)).CopyTo(output);
        return output;
    }

    private static BigInteger Mod(BigInteger value)
    {
        var result = value % Prime;
        return result.Sign < 0 ? result + Prime : result;
    }

    private static byte[] CreateBasePoint()
    {
        var basePoint = new byte[KeyLength];
        basePoint[0] = 9;
        return basePoint;
    }
}

internal sealed record RuntimeX25519KeyPair(
    byte[] PrivateKey,
    byte[] PublicKey) : IDisposable
{
    public void Dispose()
    {
    }
}

internal static class RuntimeHybridMlKemKeyShareSupport
{
    public static bool IsSupported => MLKem.IsSupported;

    public static RuntimeMlKemKeyPair CreateMlKemKeyPair(MLKemAlgorithm algorithm, string groupName)
    {
        EnsureSupported(groupName);

        var key = MLKem.GenerateKey(algorithm);
        return new RuntimeMlKemKeyPair(key, key.ExportEncapsulationKey());
    }

    public static byte[] BuildClientKeyShare(
        ReadOnlySpan<byte> ecdhPublicKey,
        int expectedEcdhPublicKeyLength,
        string ecdhName,
        ReadOnlySpan<byte> mlKemPublicKey,
        int expectedMlKemPublicKeyLength,
        string mlKemName)
    {
        ValidateEcdhPublicKey(ecdhPublicKey, expectedEcdhPublicKeyLength, ecdhName);
        ValidateMlKemPublicKey(mlKemPublicKey, expectedMlKemPublicKeyLength, mlKemName);
        return Combine(ecdhPublicKey, mlKemPublicKey);
    }

    public static byte[] BuildServerKeyShare(
        ReadOnlySpan<byte> ecdhPublicKey,
        int expectedEcdhPublicKeyLength,
        string ecdhName,
        ReadOnlySpan<byte> mlKemCiphertext,
        int expectedMlKemCiphertextLength,
        string mlKemName)
    {
        ValidateEcdhPublicKey(ecdhPublicKey, expectedEcdhPublicKeyLength, ecdhName);
        ValidateMlKemCiphertext(mlKemCiphertext, expectedMlKemCiphertextLength, mlKemName);
        return Combine(ecdhPublicKey, mlKemCiphertext);
    }

    public static bool TryExtractLeadingPublicKey(
        ReadOnlySpan<byte> clientKeyShare,
        int expectedClientKeyShareLength,
        int expectedEcdhPublicKeyLength,
        out byte[] ecdhPublicKey)
    {
        if (clientKeyShare.Length != expectedClientKeyShareLength)
        {
            ecdhPublicKey = Array.Empty<byte>();
            return false;
        }

        ecdhPublicKey = clientKeyShare[..expectedEcdhPublicKeyLength].ToArray();
        return true;
    }

    public static void ParseClientKeyShare(
        ReadOnlySpan<byte> clientKeyShare,
        int expectedEcdhPublicKeyLength,
        int expectedClientKeyShareLength,
        string groupName,
        out ReadOnlySpan<byte> ecdhPublicKey,
        out ReadOnlySpan<byte> mlKemPublicKey)
    {
        if (clientKeyShare.Length != expectedClientKeyShareLength)
        {
            throw new ArgumentOutOfRangeException(
                nameof(clientKeyShare),
                $"The {groupName} client key share must be {expectedClientKeyShareLength} bytes.");
        }

        ecdhPublicKey = clientKeyShare[..expectedEcdhPublicKeyLength];
        mlKemPublicKey = clientKeyShare[expectedEcdhPublicKeyLength..];
    }

    public static void ParseServerKeyShare(
        ReadOnlySpan<byte> serverKeyShare,
        int expectedEcdhPublicKeyLength,
        int expectedServerKeyShareLength,
        string groupName,
        out ReadOnlySpan<byte> ecdhPublicKey,
        out ReadOnlySpan<byte> mlKemCiphertext)
    {
        if (serverKeyShare.Length != expectedServerKeyShareLength)
        {
            throw new ArgumentOutOfRangeException(
                nameof(serverKeyShare),
                $"The {groupName} server key share must be {expectedServerKeyShareLength} bytes.");
        }

        ecdhPublicKey = serverKeyShare[..expectedEcdhPublicKeyLength];
        mlKemCiphertext = serverKeyShare[expectedEcdhPublicKeyLength..];
    }

    public static void EnsureSupported(string groupName)
    {
        if (!IsSupported)
        {
            throw new PlatformNotSupportedException(
                $"The current platform does not support {groupName} hybrid key exchange.");
        }
    }

    public static byte[] Combine(ReadOnlySpan<byte> first, ReadOnlySpan<byte> second)
    {
        var combined = new byte[first.Length + second.Length];
        first.CopyTo(combined);
        second.CopyTo(combined.AsSpan(first.Length));
        return combined;
    }

    private static void ValidateEcdhPublicKey(
        ReadOnlySpan<byte> ecdhPublicKey,
        int expectedLength,
        string ecdhName)
    {
        if (ecdhPublicKey.Length != expectedLength)
        {
            throw new ArgumentOutOfRangeException(
                nameof(ecdhPublicKey),
                $"The {ecdhName} public key must be {expectedLength} bytes.");
        }
    }

    private static void ValidateMlKemPublicKey(
        ReadOnlySpan<byte> mlKemPublicKey,
        int expectedLength,
        string mlKemName)
    {
        if (mlKemPublicKey.Length != expectedLength)
        {
            throw new ArgumentOutOfRangeException(
                nameof(mlKemPublicKey),
                $"The {mlKemName} public key must be {expectedLength} bytes.");
        }
    }

    private static void ValidateMlKemCiphertext(
        ReadOnlySpan<byte> mlKemCiphertext,
        int expectedLength,
        string mlKemName)
    {
        if (mlKemCiphertext.Length != expectedLength)
        {
            throw new ArgumentOutOfRangeException(
                nameof(mlKemCiphertext),
                $"The {mlKemName} ciphertext must be {expectedLength} bytes.");
        }
    }
}

internal static class RuntimeX25519MlKem768
{
    private const string GroupName = "X25519MLKEM768";

    public const ushort GroupId = 0x11EC;

    public static int MlKemPublicKeyLength => MLKemAlgorithm.MLKem768.EncapsulationKeySizeInBytes;

    public static int MlKemCiphertextLength => MLKemAlgorithm.MLKem768.CiphertextSizeInBytes;

    public static int SharedSecretLength => MLKemAlgorithm.MLKem768.SharedSecretSizeInBytes;

    public static int ClientKeyShareLength => RuntimeX25519.KeyLength + MlKemPublicKeyLength;

    public static int ServerKeyShareLength => RuntimeX25519.KeyLength + MlKemCiphertextLength;

    public static bool IsSupported => RuntimeHybridMlKemKeyShareSupport.IsSupported;

    public static RuntimeMlKemKeyPair CreateMlKemKeyPair()
        => RuntimeHybridMlKemKeyShareSupport.CreateMlKemKeyPair(MLKemAlgorithm.MLKem768, GroupName);

    public static byte[] BuildClientKeyShare(
        ReadOnlySpan<byte> x25519PublicKey,
        ReadOnlySpan<byte> mlKemPublicKey)
    {
        ValidateX25519PublicKey(x25519PublicKey);
        ValidateMlKemPublicKey(mlKemPublicKey);
        return RuntimeHybridMlKemKeyShareSupport.Combine(mlKemPublicKey, x25519PublicKey);
    }

    public static byte[] BuildServerKeyShare(
        ReadOnlySpan<byte> x25519PublicKey,
        ReadOnlySpan<byte> mlKemCiphertext)
    {
        ValidateX25519PublicKey(x25519PublicKey);
        ValidateMlKemCiphertext(mlKemCiphertext);
        return RuntimeHybridMlKemKeyShareSupport.Combine(mlKemCiphertext, x25519PublicKey);
    }

    public static bool TryExtractClientX25519PublicKey(
        ReadOnlySpan<byte> clientKeyShare,
        out byte[] x25519PublicKey)
    {
        if (clientKeyShare.Length != ClientKeyShareLength)
        {
            x25519PublicKey = Array.Empty<byte>();
            return false;
        }

        x25519PublicKey = clientKeyShare[^RuntimeX25519.KeyLength..].ToArray();
        return true;
    }

    public static byte[] DeriveSharedSecret(
        ReadOnlySpan<byte> x25519PrivateKey,
        MLKem mlKemKey,
        ReadOnlySpan<byte> serverKeyShare)
    {
        ArgumentNullException.ThrowIfNull(mlKemKey);

        ParseServerKeyShare(serverKeyShare, out var serverX25519PublicKey, out var mlKemCiphertext);
        var x25519SharedSecret = RuntimeX25519.DeriveSharedSecret(x25519PrivateKey, serverX25519PublicKey);
        var mlKemSharedSecret = mlKemKey.Decapsulate(mlKemCiphertext.ToArray());
        return RuntimeHybridMlKemKeyShareSupport.Combine(mlKemSharedSecret, x25519SharedSecret);
    }

    public static RuntimeHybridMlKemEncapsulation Encapsulate(ReadOnlySpan<byte> clientKeyShare)
    {
        RuntimeHybridMlKemKeyShareSupport.EnsureSupported(GroupName);

        ParseClientKeyShare(clientKeyShare, out var clientX25519PublicKey, out var clientMlKemPublicKey);

        using var x25519KeyPair = RuntimeX25519.CreateKeyPair();
        using var mlKemKey = MLKem.ImportEncapsulationKey(
            MLKemAlgorithm.MLKem768,
            clientMlKemPublicKey.ToArray());
        mlKemKey.Encapsulate(out var mlKemCiphertext, out var mlKemSharedSecret);

        var x25519SharedSecret = RuntimeX25519.DeriveSharedSecret(
            x25519KeyPair.PrivateKey,
            clientX25519PublicKey);
        return new RuntimeHybridMlKemEncapsulation(
            BuildServerKeyShare(x25519KeyPair.PublicKey, mlKemCiphertext),
            RuntimeHybridMlKemKeyShareSupport.Combine(mlKemSharedSecret, x25519SharedSecret));
    }

    private static void ParseClientKeyShare(
        ReadOnlySpan<byte> clientKeyShare,
        out ReadOnlySpan<byte> x25519PublicKey,
        out ReadOnlySpan<byte> mlKemPublicKey)
    {
        if (clientKeyShare.Length != ClientKeyShareLength)
        {
            throw new ArgumentOutOfRangeException(
                nameof(clientKeyShare),
                $"The {GroupName} client key share must be {ClientKeyShareLength} bytes.");
        }

        mlKemPublicKey = clientKeyShare[..MlKemPublicKeyLength];
        x25519PublicKey = clientKeyShare[MlKemPublicKeyLength..];
    }

    private static void ParseServerKeyShare(
        ReadOnlySpan<byte> serverKeyShare,
        out ReadOnlySpan<byte> x25519PublicKey,
        out ReadOnlySpan<byte> mlKemCiphertext)
    {
        if (serverKeyShare.Length != ServerKeyShareLength)
        {
            throw new ArgumentOutOfRangeException(
                nameof(serverKeyShare),
                $"The {GroupName} server key share must be {ServerKeyShareLength} bytes.");
        }

        mlKemCiphertext = serverKeyShare[..MlKemCiphertextLength];
        x25519PublicKey = serverKeyShare[MlKemCiphertextLength..];
    }

    private static void ValidateX25519PublicKey(ReadOnlySpan<byte> x25519PublicKey)
    {
        if (x25519PublicKey.Length != RuntimeX25519.KeyLength)
        {
            throw new ArgumentOutOfRangeException(
                nameof(x25519PublicKey),
                $"The X25519 public key must be {RuntimeX25519.KeyLength} bytes.");
        }
    }

    private static void ValidateMlKemPublicKey(ReadOnlySpan<byte> mlKemPublicKey)
    {
        if (mlKemPublicKey.Length != MlKemPublicKeyLength)
        {
            throw new ArgumentOutOfRangeException(
                nameof(mlKemPublicKey),
                $"The ML-KEM-768 public key must be {MlKemPublicKeyLength} bytes.");
        }
    }

    private static void ValidateMlKemCiphertext(ReadOnlySpan<byte> mlKemCiphertext)
    {
        if (mlKemCiphertext.Length != MlKemCiphertextLength)
        {
            throw new ArgumentOutOfRangeException(
                nameof(mlKemCiphertext),
                $"The ML-KEM-768 ciphertext must be {MlKemCiphertextLength} bytes.");
        }
    }
}

internal static class RuntimeX25519Kyber768Draft00
{
    private const string GroupName = "X25519Kyber768Draft00";

    public const ushort GroupId = 0x6399;

    public static int MlKemPublicKeyLength => MLKemAlgorithm.MLKem768.EncapsulationKeySizeInBytes;

    public static int MlKemCiphertextLength => MLKemAlgorithm.MLKem768.CiphertextSizeInBytes;

    public static int SharedSecretLength => MLKemAlgorithm.MLKem768.SharedSecretSizeInBytes;

    public static int ClientKeyShareLength => RuntimeX25519.KeyLength + MlKemPublicKeyLength;

    public static int ServerKeyShareLength => RuntimeX25519.KeyLength + MlKemCiphertextLength;

    public static bool IsSupported
        => RuntimeHybridMlKemKeyShareSupport.IsSupported &&
           SHA3_256.IsSupported &&
           Shake256.IsSupported;

    public static RuntimeMlKemKeyPair CreateMlKemKeyPair()
    {
        EnsureSupported();
        return RuntimeHybridMlKemKeyShareSupport.CreateMlKemKeyPair(MLKemAlgorithm.MLKem768, GroupName);
    }

    public static byte[] BuildClientKeyShare(
        ReadOnlySpan<byte> x25519PublicKey,
        ReadOnlySpan<byte> mlKemPublicKey)
    {
        ValidateX25519PublicKey(x25519PublicKey);
        ValidateMlKemPublicKey(mlKemPublicKey);
        return RuntimeHybridMlKemKeyShareSupport.Combine(x25519PublicKey, mlKemPublicKey);
    }

    public static byte[] BuildServerKeyShare(
        ReadOnlySpan<byte> x25519PublicKey,
        ReadOnlySpan<byte> mlKemCiphertext)
    {
        ValidateX25519PublicKey(x25519PublicKey);
        ValidateMlKemCiphertext(mlKemCiphertext);
        return RuntimeHybridMlKemKeyShareSupport.Combine(x25519PublicKey, mlKemCiphertext);
    }

    public static bool TryExtractClientX25519PublicKey(
        ReadOnlySpan<byte> clientKeyShare,
        out byte[] x25519PublicKey)
    {
        if (clientKeyShare.Length != ClientKeyShareLength)
        {
            x25519PublicKey = Array.Empty<byte>();
            return false;
        }

        x25519PublicKey = clientKeyShare[..RuntimeX25519.KeyLength].ToArray();
        return true;
    }

    public static byte[] DeriveSharedSecret(
        ReadOnlySpan<byte> x25519PrivateKey,
        MLKem mlKemKey,
        ReadOnlySpan<byte> serverKeyShare)
    {
        ArgumentNullException.ThrowIfNull(mlKemKey);

        ParseServerKeyShare(serverKeyShare, out var serverX25519PublicKey, out var mlKemCiphertext);
        var x25519SharedSecret = RuntimeX25519.DeriveSharedSecret(x25519PrivateKey, serverX25519PublicKey);
        var mlKemSharedSecret = mlKemKey.Decapsulate(mlKemCiphertext.ToArray());
        var kyberSharedSecret = TransformSharedSecret(mlKemCiphertext, mlKemSharedSecret);
        return RuntimeHybridMlKemKeyShareSupport.Combine(x25519SharedSecret, kyberSharedSecret);
    }

    public static RuntimeHybridMlKemEncapsulation Encapsulate(ReadOnlySpan<byte> clientKeyShare)
    {
        EnsureSupported();

        ParseClientKeyShare(clientKeyShare, out var clientX25519PublicKey, out var clientMlKemPublicKey);

        using var x25519KeyPair = RuntimeX25519.CreateKeyPair();
        using var mlKemKey = MLKem.ImportEncapsulationKey(
            MLKemAlgorithm.MLKem768,
            clientMlKemPublicKey.ToArray());
        mlKemKey.Encapsulate(out var mlKemCiphertext, out var mlKemSharedSecret);

        var x25519SharedSecret = RuntimeX25519.DeriveSharedSecret(
            x25519KeyPair.PrivateKey,
            clientX25519PublicKey);
        var kyberSharedSecret = TransformSharedSecret(mlKemCiphertext, mlKemSharedSecret);
        return new RuntimeHybridMlKemEncapsulation(
            BuildServerKeyShare(x25519KeyPair.PublicKey, mlKemCiphertext),
            RuntimeHybridMlKemKeyShareSupport.Combine(x25519SharedSecret, kyberSharedSecret));
    }

    private static void EnsureSupported()
    {
        RuntimeHybridMlKemKeyShareSupport.EnsureSupported(GroupName);
        if (!SHA3_256.IsSupported ||
            !Shake256.IsSupported)
        {
            throw new PlatformNotSupportedException(
                $"The current platform does not support {GroupName} shared secret derivation.");
        }
    }

    private static byte[] TransformSharedSecret(
        ReadOnlySpan<byte> ciphertext,
        ReadOnlySpan<byte> mlKemSharedSecret)
    {
        var ciphertextHash = SHA3_256.HashData(ciphertext);
        var shakeInput = new byte[mlKemSharedSecret.Length + ciphertextHash.Length];
        mlKemSharedSecret.CopyTo(shakeInput);
        ciphertextHash.CopyTo(shakeInput.AsSpan(mlKemSharedSecret.Length));
        return Shake256.HashData(shakeInput, SharedSecretLength);
    }

    private static void ParseClientKeyShare(
        ReadOnlySpan<byte> clientKeyShare,
        out ReadOnlySpan<byte> x25519PublicKey,
        out ReadOnlySpan<byte> mlKemPublicKey)
    {
        if (clientKeyShare.Length != ClientKeyShareLength)
        {
            throw new ArgumentOutOfRangeException(
                nameof(clientKeyShare),
                $"The {GroupName} client key share must be {ClientKeyShareLength} bytes.");
        }

        x25519PublicKey = clientKeyShare[..RuntimeX25519.KeyLength];
        mlKemPublicKey = clientKeyShare[RuntimeX25519.KeyLength..];
    }

    private static void ParseServerKeyShare(
        ReadOnlySpan<byte> serverKeyShare,
        out ReadOnlySpan<byte> x25519PublicKey,
        out ReadOnlySpan<byte> mlKemCiphertext)
    {
        if (serverKeyShare.Length != ServerKeyShareLength)
        {
            throw new ArgumentOutOfRangeException(
                nameof(serverKeyShare),
                $"The {GroupName} server key share must be {ServerKeyShareLength} bytes.");
        }

        x25519PublicKey = serverKeyShare[..RuntimeX25519.KeyLength];
        mlKemCiphertext = serverKeyShare[RuntimeX25519.KeyLength..];
    }

    private static void ValidateX25519PublicKey(ReadOnlySpan<byte> x25519PublicKey)
    {
        if (x25519PublicKey.Length != RuntimeX25519.KeyLength)
        {
            throw new ArgumentOutOfRangeException(
                nameof(x25519PublicKey),
                $"The X25519 public key must be {RuntimeX25519.KeyLength} bytes.");
        }
    }

    private static void ValidateMlKemPublicKey(ReadOnlySpan<byte> mlKemPublicKey)
    {
        if (mlKemPublicKey.Length != MlKemPublicKeyLength)
        {
            throw new ArgumentOutOfRangeException(
                nameof(mlKemPublicKey),
                $"The ML-KEM-768 public key must be {MlKemPublicKeyLength} bytes.");
        }
    }

    private static void ValidateMlKemCiphertext(ReadOnlySpan<byte> mlKemCiphertext)
    {
        if (mlKemCiphertext.Length != MlKemCiphertextLength)
        {
            throw new ArgumentOutOfRangeException(
                nameof(mlKemCiphertext),
                $"The ML-KEM-768 ciphertext must be {MlKemCiphertextLength} bytes.");
        }
    }
}

internal static class RuntimeSecp256r1MlKem768
{
    private const string GroupName = "SecP256r1MLKEM768";
    private const string EcdhName = "secp256r1";
    private const string MlKemName = "ML-KEM-768";

    public const ushort GroupId = 0x11EB;

    public static int MlKemPublicKeyLength => MLKemAlgorithm.MLKem768.EncapsulationKeySizeInBytes;

    public static int MlKemCiphertextLength => MLKemAlgorithm.MLKem768.CiphertextSizeInBytes;

    public static int ClientKeyShareLength => RuntimeSecp256r1.PublicKeyLength + MlKemPublicKeyLength;

    public static int ServerKeyShareLength => RuntimeSecp256r1.PublicKeyLength + MlKemCiphertextLength;

    public static bool IsSupported => RuntimeHybridMlKemKeyShareSupport.IsSupported;

    public static RuntimeMlKemKeyPair CreateMlKemKeyPair()
        => RuntimeHybridMlKemKeyShareSupport.CreateMlKemKeyPair(MLKemAlgorithm.MLKem768, GroupName);

    public static byte[] BuildClientKeyShare(
        ReadOnlySpan<byte> secp256r1PublicKey,
        ReadOnlySpan<byte> mlKemPublicKey)
        => RuntimeHybridMlKemKeyShareSupport.BuildClientKeyShare(
            secp256r1PublicKey,
            RuntimeSecp256r1.PublicKeyLength,
            EcdhName,
            mlKemPublicKey,
            MlKemPublicKeyLength,
            MlKemName);

    public static byte[] BuildServerKeyShare(
        ReadOnlySpan<byte> secp256r1PublicKey,
        ReadOnlySpan<byte> mlKemCiphertext)
        => RuntimeHybridMlKemKeyShareSupport.BuildServerKeyShare(
            secp256r1PublicKey,
            RuntimeSecp256r1.PublicKeyLength,
            EcdhName,
            mlKemCiphertext,
            MlKemCiphertextLength,
            MlKemName);

    public static byte[] DeriveSharedSecret(
        ReadOnlySpan<byte> secp256r1PrivateKey,
        MLKem mlKemKey,
        ReadOnlySpan<byte> serverKeyShare)
    {
        ArgumentNullException.ThrowIfNull(mlKemKey);

        RuntimeHybridMlKemKeyShareSupport.ParseServerKeyShare(
            serverKeyShare,
            RuntimeSecp256r1.PublicKeyLength,
            ServerKeyShareLength,
            GroupName,
            out var serverSecp256r1PublicKey,
            out var mlKemCiphertext);
        var secp256r1SharedSecret = RuntimeSecp256r1.DeriveSharedSecret(secp256r1PrivateKey, serverSecp256r1PublicKey);
        var mlKemSharedSecret = mlKemKey.Decapsulate(mlKemCiphertext.ToArray());
        return RuntimeHybridMlKemKeyShareSupport.Combine(secp256r1SharedSecret, mlKemSharedSecret);
    }

    public static RuntimeHybridMlKemEncapsulation Encapsulate(ReadOnlySpan<byte> clientKeyShare)
    {
        RuntimeHybridMlKemKeyShareSupport.EnsureSupported(GroupName);

        RuntimeHybridMlKemKeyShareSupport.ParseClientKeyShare(
            clientKeyShare,
            RuntimeSecp256r1.PublicKeyLength,
            ClientKeyShareLength,
            GroupName,
            out var clientSecp256r1PublicKey,
            out var clientMlKemPublicKey);

        using var secp256r1KeyPair = RuntimeSecp256r1.CreateKeyPair();
        using var mlKemKey = MLKem.ImportEncapsulationKey(
            MLKemAlgorithm.MLKem768,
            clientMlKemPublicKey.ToArray());
        mlKemKey.Encapsulate(out var mlKemCiphertext, out var mlKemSharedSecret);

        var secp256r1SharedSecret = RuntimeSecp256r1.DeriveSharedSecret(
            secp256r1KeyPair.PrivateKey,
            clientSecp256r1PublicKey);
        return new RuntimeHybridMlKemEncapsulation(
            BuildServerKeyShare(secp256r1KeyPair.PublicKey, mlKemCiphertext),
            RuntimeHybridMlKemKeyShareSupport.Combine(secp256r1SharedSecret, mlKemSharedSecret));
    }
}

internal static class RuntimeSecp384r1MlKem1024
{
    private const string GroupName = "SecP384r1MLKEM1024";
    private const string EcdhName = "secp384r1";
    private const string MlKemName = "ML-KEM-1024";

    public const ushort GroupId = 0x11ED;

    public static int MlKemPublicKeyLength => MLKemAlgorithm.MLKem1024.EncapsulationKeySizeInBytes;

    public static int MlKemCiphertextLength => MLKemAlgorithm.MLKem1024.CiphertextSizeInBytes;

    public static int ClientKeyShareLength => RuntimeSecp384r1.PublicKeyLength + MlKemPublicKeyLength;

    public static int ServerKeyShareLength => RuntimeSecp384r1.PublicKeyLength + MlKemCiphertextLength;

    public static bool IsSupported => RuntimeHybridMlKemKeyShareSupport.IsSupported;

    public static RuntimeMlKemKeyPair CreateMlKemKeyPair()
        => RuntimeHybridMlKemKeyShareSupport.CreateMlKemKeyPair(MLKemAlgorithm.MLKem1024, GroupName);

    public static byte[] BuildClientKeyShare(
        ReadOnlySpan<byte> secp384r1PublicKey,
        ReadOnlySpan<byte> mlKemPublicKey)
        => RuntimeHybridMlKemKeyShareSupport.BuildClientKeyShare(
            secp384r1PublicKey,
            RuntimeSecp384r1.PublicKeyLength,
            EcdhName,
            mlKemPublicKey,
            MlKemPublicKeyLength,
            MlKemName);

    public static byte[] BuildServerKeyShare(
        ReadOnlySpan<byte> secp384r1PublicKey,
        ReadOnlySpan<byte> mlKemCiphertext)
        => RuntimeHybridMlKemKeyShareSupport.BuildServerKeyShare(
            secp384r1PublicKey,
            RuntimeSecp384r1.PublicKeyLength,
            EcdhName,
            mlKemCiphertext,
            MlKemCiphertextLength,
            MlKemName);

    public static byte[] DeriveSharedSecret(
        ReadOnlySpan<byte> secp384r1PrivateKey,
        MLKem mlKemKey,
        ReadOnlySpan<byte> serverKeyShare)
    {
        ArgumentNullException.ThrowIfNull(mlKemKey);

        RuntimeHybridMlKemKeyShareSupport.ParseServerKeyShare(
            serverKeyShare,
            RuntimeSecp384r1.PublicKeyLength,
            ServerKeyShareLength,
            GroupName,
            out var serverSecp384r1PublicKey,
            out var mlKemCiphertext);
        var secp384r1SharedSecret = RuntimeSecp384r1.DeriveSharedSecret(secp384r1PrivateKey, serverSecp384r1PublicKey);
        var mlKemSharedSecret = mlKemKey.Decapsulate(mlKemCiphertext.ToArray());
        return RuntimeHybridMlKemKeyShareSupport.Combine(secp384r1SharedSecret, mlKemSharedSecret);
    }

    public static RuntimeHybridMlKemEncapsulation Encapsulate(ReadOnlySpan<byte> clientKeyShare)
    {
        RuntimeHybridMlKemKeyShareSupport.EnsureSupported(GroupName);

        RuntimeHybridMlKemKeyShareSupport.ParseClientKeyShare(
            clientKeyShare,
            RuntimeSecp384r1.PublicKeyLength,
            ClientKeyShareLength,
            GroupName,
            out var clientSecp384r1PublicKey,
            out var clientMlKemPublicKey);

        using var secp384r1KeyPair = RuntimeSecp384r1.CreateKeyPair();
        using var mlKemKey = MLKem.ImportEncapsulationKey(
            MLKemAlgorithm.MLKem1024,
            clientMlKemPublicKey.ToArray());
        mlKemKey.Encapsulate(out var mlKemCiphertext, out var mlKemSharedSecret);

        var secp384r1SharedSecret = RuntimeSecp384r1.DeriveSharedSecret(
            secp384r1KeyPair.PrivateKey,
            clientSecp384r1PublicKey);
        return new RuntimeHybridMlKemEncapsulation(
            BuildServerKeyShare(secp384r1KeyPair.PublicKey, mlKemCiphertext),
            RuntimeHybridMlKemKeyShareSupport.Combine(secp384r1SharedSecret, mlKemSharedSecret));
    }
}

internal sealed record RuntimeMlKemKeyPair(
    MLKem Key,
    byte[] PublicKey) : IDisposable
{
    public void Dispose()
        => Key.Dispose();
}

internal sealed record RuntimeHybridMlKemEncapsulation(
    byte[] ServerKeyShare,
    byte[] SharedSecret);

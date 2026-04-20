using System.Net;
using System.Net.Sockets;
using System.Numerics;
using System.Security.Cryptography;
using System.Text;
using Blake3;
using NodePanel.Core.Protocol;
using NodePanel.Core.Runtime;

namespace NodePanel.Core.Tests;

public sealed class VlessTransportEncryptionTests
{
    private static readonly byte[] MaxNonce = Enumerable.Repeat((byte)0xFF, 12).ToArray();
    private const string CtrDeriveKeyContext = "VLESS";
    private const int HeaderLength = 5;
    private const int TagLength = 16;
    private const int TicketLength = 16;
    private static readonly BigInteger X25519Prime = (BigInteger.One << 255) - 19;
    private static readonly BigInteger X25519A24 = new(121665);

    [Fact]
    public async Task ConnectAsync_routes_vless_over_mlkem_transport_encryption()
    {
        using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(15));
        using var listener = new TcpListener(IPAddress.Loopback, 0);
        using var nfsServerKey = MLKem.GenerateKey(MLKemAlgorithm.MLKem768);
        listener.Start();

        var serverPort = ((IPEndPoint)listener.LocalEndpoint).Port;
        var serverTask = CaptureEncryptedTcpSessionAsync(listener, nfsServerKey, cts.Token);
        var client = new VlessOutboundClient();

        await using var connection = await client.ConnectAsync(
            new VlessClientOptions
            {
                ServerHost = IPAddress.Loopback.ToString(),
                ServerPort = serverPort,
                Transport = VlessClientTransportType.Tcp,
                UserUuid = "11111111-1111-1111-1111-111111111111",
                Command = VlessCommand.Connect,
                TargetHost = "example.org",
                TargetPort = 443,
                Encryption = EncodeBase64Url(nfsServerKey.ExportEncapsulationKey())
            },
            cts.Token);

        await connection.Stream.WriteAsync(Encoding.ASCII.GetBytes("ping"), cts.Token);
        await connection.Stream.FlushAsync(cts.Token);

        var response = new byte[4];
        await connection.Stream.ReadExactlyAsync(response.AsMemory(0, response.Length), cts.Token);

        var capture = await serverTask;
        Assert.Equal(VlessCommand.Connect, capture.Request.Command);
        Assert.Equal("example.org", capture.Request.TargetHost);
        Assert.Equal(443, capture.Request.TargetPort);
        Assert.Equal("ping", capture.PayloadText);
        Assert.Equal("pong", Encoding.ASCII.GetString(response));
    }

    private static async Task<TcpCapture> CaptureEncryptedTcpSessionAsync(
        TcpListener listener,
        MLKem nfsServerKey,
        CancellationToken cancellationToken)
    {
        using var client = await listener.AcceptTcpClientAsync(cancellationToken);
        await using var stream = client.GetStream();

        var session = await AcceptEncryptedSessionAsync(stream, nfsServerKey, cancellationToken);

        var requestPayload = await ReadEncryptedRecordAsync(stream, session.ReadCipher, cancellationToken);
        await using var requestStream = new MemoryStream(requestPayload, writable: false);
        var request = await new VlessHandshakeReader().ReadAsync(requestStream, cancellationToken);

        await using var responseBuffer = new MemoryStream();
        await VlessHandshakeReader.WriteResponseAsync(responseBuffer, request.Version, cancellationToken);
        await WriteEncryptedRecordAsync(stream, session.WriteCipher, responseBuffer.ToArray(), cancellationToken);

        var payload = await ReadEncryptedRecordAsync(stream, session.ReadCipher, cancellationToken);
        await WriteEncryptedRecordAsync(stream, session.WriteCipher, Encoding.ASCII.GetBytes("pong"), cancellationToken);
        await stream.FlushAsync(cancellationToken);

        session.Dispose();
        return new TcpCapture(request, Encoding.ASCII.GetString(payload));
    }

    private static async Task<EncryptedSession> AcceptEncryptedSessionAsync(
        Stream stream,
        MLKem nfsServerKey,
        CancellationToken cancellationToken)
    {
        var useAes = PreferAesGcm();
        var relayLength = MLKemAlgorithm.MLKem768.CiphertextSizeInBytes;
        var clientMlkemPublicLength = MLKemAlgorithm.MLKem768.EncapsulationKeySizeInBytes;

        var iv = await ReadExactAsync(stream, TicketLength, cancellationToken);
        var relay = await ReadExactAsync(stream, relayLength, cancellationToken);
        var nfsKey = nfsServerKey.Decapsulate(relay);
        using var nfsCipher = TestAeadCipher.Create(iv, nfsKey, useAes);

        var encryptedLength = await ReadExactAsync(stream, 18, cancellationToken);
        var clientPfsPayloadLength = DecodeLength(
            nfsCipher.Decrypt(encryptedLength, ReadOnlySpan<byte>.Empty));

        var encryptedClientPfs = await ReadExactAsync(stream, clientPfsPayloadLength, cancellationToken);
        var clientPfsPublic = nfsCipher.Decrypt(encryptedClientPfs, ReadOnlySpan<byte>.Empty);

        using var clientMlkemKey = MLKem.ImportEncapsulationKey(
            MLKemAlgorithm.MLKem768,
            clientPfsPublic.AsSpan(0, clientMlkemPublicLength));
        clientMlkemKey.Encapsulate(out var serverMlkemCiphertext, out var serverMlkemSharedSecret);

        using var serverX25519 = CreateX25519KeyPair();
        var serverX25519SharedSecret = DeriveX25519SharedSecret(
            serverX25519.PrivateKey,
            clientPfsPublic.AsSpan(clientMlkemPublicLength, 32));

        var pfsKey = Combine(serverMlkemSharedSecret, serverX25519SharedSecret);
        var unitedKey = Combine(pfsKey, nfsKey);
        var serverPfsPublic = Combine(serverMlkemCiphertext, serverX25519.PublicKey);

        var serverWriteCipher = TestAeadCipher.Create(serverPfsPublic, unitedKey, useAes);
        var serverReadCipher = TestAeadCipher.Create(clientPfsPublic, unitedKey, useAes);

        var ticket = RandomNumberGenerator.GetBytes(TicketLength);
        await stream.WriteAsync(
            nfsCipher.Encrypt(serverPfsPublic, ReadOnlySpan<byte>.Empty, MaxNonce),
            cancellationToken);
        await stream.WriteAsync(
            serverWriteCipher.Encrypt(ticket, ReadOnlySpan<byte>.Empty),
            cancellationToken);
        await stream.WriteAsync(
            serverWriteCipher.Encrypt(EncodeLength(0), ReadOnlySpan<byte>.Empty),
            cancellationToken);
        await stream.FlushAsync(cancellationToken);

        var encryptedPaddingLength = await ReadExactAsync(stream, 18, cancellationToken);
        var clientPaddingLength = DecodeLength(
            nfsCipher.Decrypt(encryptedPaddingLength, ReadOnlySpan<byte>.Empty));
        if (clientPaddingLength > 0)
        {
            var encryptedPadding = await ReadExactAsync(stream, clientPaddingLength, cancellationToken);
            _ = nfsCipher.Decrypt(encryptedPadding, ReadOnlySpan<byte>.Empty);
        }

        return new EncryptedSession(serverReadCipher, serverWriteCipher);
    }

    private static async Task<byte[]> ReadEncryptedRecordAsync(
        Stream stream,
        TestAeadCipher cipher,
        CancellationToken cancellationToken)
    {
        var header = await ReadExactAsync(stream, HeaderLength, cancellationToken);
        var encryptedPayload = await ReadExactAsync(stream, DecodeHeader(header), cancellationToken);
        return cipher.Decrypt(encryptedPayload, header);
    }

    private static async Task WriteEncryptedRecordAsync(
        Stream stream,
        TestAeadCipher cipher,
        ReadOnlyMemory<byte> payload,
        CancellationToken cancellationToken)
    {
        var header = new byte[HeaderLength];
        EncodeHeader(header, payload.Length + TagLength);
        var encryptedPayload = cipher.Encrypt(payload.Span, header);
        await stream.WriteAsync(header, cancellationToken);
        await stream.WriteAsync(encryptedPayload, cancellationToken);
    }

    private static bool PreferAesGcm()
        => AesGcm.IsSupported &&
           ((System.Runtime.Intrinsics.X86.Aes.IsSupported &&
             System.Runtime.Intrinsics.X86.Pclmulqdq.IsSupported &&
             System.Runtime.Intrinsics.X86.Sse41.IsSupported &&
             System.Runtime.Intrinsics.X86.Ssse3.IsSupported) ||
            System.Runtime.Intrinsics.Arm.Aes.IsSupported);

    private static byte[] EncodeLength(int value)
        => [(byte)(value >> 8), (byte)value];

    private static int DecodeLength(ReadOnlySpan<byte> value)
        => (value[0] << 8) | value[1];

    private static void EncodeHeader(Span<byte> destination, int length)
    {
        destination[0] = 23;
        destination[1] = 3;
        destination[2] = 3;
        destination[3] = (byte)(length >> 8);
        destination[4] = (byte)length;
    }

    private static int DecodeHeader(ReadOnlySpan<byte> source)
    {
        var length = (source[3] << 8) | source[4];
        if (source[0] != 23 || source[1] != 3 || source[2] != 3)
        {
            throw new InvalidDataException("Invalid encrypted VLESS record header.");
        }

        return length;
    }

    private static byte[] Combine(ReadOnlySpan<byte> first, ReadOnlySpan<byte> second)
    {
        var buffer = new byte[first.Length + second.Length];
        first.CopyTo(buffer);
        second.CopyTo(buffer.AsSpan(first.Length));
        return buffer;
    }

    private static string EncodeBase64Url(ReadOnlySpan<byte> value)
        => Convert.ToBase64String(value)
            .TrimEnd('=')
            .Replace('+', '-')
            .Replace('/', '_');

    private static async Task<byte[]> ReadExactAsync(
        Stream stream,
        int length,
        CancellationToken cancellationToken)
    {
        var buffer = new byte[length];
        await stream.ReadExactlyAsync(buffer.AsMemory(0, length), cancellationToken);
        return buffer;
    }

    private static X25519KeyPair CreateX25519KeyPair()
    {
        var privateKey = RandomNumberGenerator.GetBytes(32);
        ClampX25519Scalar(privateKey);
        return new X25519KeyPair(
            privateKey,
            X25519(privateKey, CreateBasePoint()));
    }

    private static byte[] DeriveX25519SharedSecret(ReadOnlySpan<byte> privateKey, ReadOnlySpan<byte> peerPublicKey)
    {
        return X25519(privateKey, peerPublicKey);
    }

    private static byte[] X25519(ReadOnlySpan<byte> scalar, ReadOnlySpan<byte> uCoordinate)
    {
        var clampedScalar = scalar.ToArray();
        ClampX25519Scalar(clampedScalar);

        var x1 = DecodeLittleEndian25519(uCoordinate, maskHighBit: true);
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
            var z2Next = Mod(e * Mod(aa + X25519A24 * e));

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

        return EncodeLittleEndian25519(Mod(x2 * BigInteger.ModPow(z2, X25519Prime - 2, X25519Prime)));
    }

    private static void ClampX25519Scalar(byte[] scalar)
    {
        scalar[0] &= 248;
        scalar[31] &= 127;
        scalar[31] |= 64;
    }

    private static BigInteger DecodeLittleEndian25519(ReadOnlySpan<byte> value, bool maskHighBit)
    {
        var buffer = value.ToArray();
        if (maskHighBit)
        {
            buffer[^1] &= 0x7F;
        }

        return new BigInteger(buffer, isUnsigned: true, isBigEndian: false);
    }

    private static byte[] EncodeLittleEndian25519(BigInteger value)
    {
        var encoded = Mod(value).ToByteArray(isUnsigned: true, isBigEndian: false);
        if (encoded.Length == 32)
        {
            return encoded;
        }

        var output = new byte[32];
        encoded.AsSpan(0, Math.Min(encoded.Length, output.Length)).CopyTo(output);
        return output;
    }

    private static BigInteger Mod(BigInteger value)
    {
        var result = value % X25519Prime;
        return result.Sign < 0 ? result + X25519Prime : result;
    }

    private static byte[] CreateBasePoint()
    {
        var basePoint = new byte[32];
        basePoint[0] = 9;
        return basePoint;
    }

    private sealed class TestAeadCipher : IDisposable
    {
        private readonly AesGcm? _aesGcm;
        private readonly ChaCha20Poly1305? _chacha20Poly1305;
        private readonly byte[] _nonce = new byte[12];

        private TestAeadCipher(byte[] key, bool useAes)
        {
            if (useAes)
            {
                _aesGcm = new AesGcm(key, TagLength);
            }
            else
            {
                _chacha20Poly1305 = new ChaCha20Poly1305(key);
            }
        }

        public static TestAeadCipher Create(
            ReadOnlySpan<byte> context,
            ReadOnlySpan<byte> key,
            bool useAes)
        {
            var derivedKey = new byte[32];
            using var hasher = Hasher.NewDeriveKey(context);
            hasher.Update(key);
            hasher.Finalize(derivedKey);
            return new TestAeadCipher(derivedKey, useAes);
        }

        public byte[] Encrypt(
            ReadOnlySpan<byte> plaintext,
            ReadOnlySpan<byte> additionalData,
            byte[]? nonce = null)
        {
            var output = new byte[plaintext.Length + TagLength];
            var resolvedNonce = nonce ?? AdvanceNonce();
            if (_aesGcm is not null)
            {
                _aesGcm.Encrypt(
                    resolvedNonce,
                    plaintext,
                    output.AsSpan(0, plaintext.Length),
                    output.AsSpan(plaintext.Length, TagLength),
                    additionalData);
            }
            else
            {
                _chacha20Poly1305!.Encrypt(
                    resolvedNonce,
                    plaintext,
                    output.AsSpan(0, plaintext.Length),
                    output.AsSpan(plaintext.Length, TagLength),
                    additionalData);
            }

            return output;
        }

        public byte[] Decrypt(
            ReadOnlySpan<byte> ciphertext,
            ReadOnlySpan<byte> additionalData,
            byte[]? nonce = null)
        {
            var output = new byte[ciphertext.Length - TagLength];
            var resolvedNonce = nonce ?? AdvanceNonce();
            if (_aesGcm is not null)
            {
                _aesGcm.Decrypt(
                    resolvedNonce,
                    ciphertext[..^TagLength],
                    ciphertext[^TagLength..],
                    output,
                    additionalData);
            }
            else
            {
                _chacha20Poly1305!.Decrypt(
                    resolvedNonce,
                    ciphertext[..^TagLength],
                    ciphertext[^TagLength..],
                    output,
                    additionalData);
            }

            return output;
        }

        public void Dispose()
        {
            _aesGcm?.Dispose();
            _chacha20Poly1305?.Dispose();
        }

        private byte[] AdvanceNonce()
        {
            for (var index = _nonce.Length - 1; index >= 0; index--)
            {
                unchecked
                {
                    _nonce[index]++;
                }

                if (_nonce[index] != 0)
                {
                    break;
                }
            }

            return _nonce;
        }
    }

    private sealed record EncryptedSession(
        TestAeadCipher ReadCipher,
        TestAeadCipher WriteCipher) : IDisposable
    {
        public void Dispose()
        {
            ReadCipher.Dispose();
            WriteCipher.Dispose();
        }
    }

    private sealed record X25519KeyPair(
        byte[] PrivateKey,
        byte[] PublicKey) : IDisposable
    {
        public void Dispose()
        {
        }
    }

    private sealed record TcpCapture(VlessRequest Request, string PayloadText);
}

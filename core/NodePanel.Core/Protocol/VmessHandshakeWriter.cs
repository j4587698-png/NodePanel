using System.Buffers.Binary;
using System.Security.Cryptography;
using System.Text;
using NodePanel.Core.Runtime;

namespace NodePanel.Core.Protocol;

public sealed class VmessHandshakeWriter
{
    private const int AeadTagLength = 16;

    private static readonly byte[] SaltAuthIdEncryptionKey = Encoding.ASCII.GetBytes("AES Auth ID Encryption");
    private static readonly byte[] SaltAeadResponseHeaderLengthKey = Encoding.ASCII.GetBytes("AEAD Resp Header Len Key");
    private static readonly byte[] SaltAeadResponseHeaderLengthIv = Encoding.ASCII.GetBytes("AEAD Resp Header Len IV");
    private static readonly byte[] SaltAeadResponseHeaderPayloadKey = Encoding.ASCII.GetBytes("AEAD Resp Header Key");
    private static readonly byte[] SaltAeadResponseHeaderPayloadIv = Encoding.ASCII.GetBytes("AEAD Resp Header IV");
    private static readonly byte[] SaltVmessHeaderPayloadAeadKey = Encoding.ASCII.GetBytes("VMess Header AEAD Key");
    private static readonly byte[] SaltVmessHeaderPayloadAeadIv = Encoding.ASCII.GetBytes("VMess Header AEAD Nonce");
    private static readonly byte[] SaltVmessHeaderPayloadLengthAeadKey = Encoding.ASCII.GetBytes("VMess Header AEAD Key_Length");
    private static readonly byte[] SaltVmessHeaderPayloadLengthAeadIv = Encoding.ASCII.GetBytes("VMess Header AEAD Nonce_Length");

    public byte[] BuildRequestHeader(VmessRequest request)
    {
        ArgumentNullException.ThrowIfNull(request);
        ValidateRequest(request);

        var headerPayload = BuildRequestPayload(request);
        var authId = CreateAuthId(request.User.CmdKey);
        var connectionNonce = RandomNumberGenerator.GetBytes(8);

        Span<byte> headerLengthBytes = stackalloc byte[2];
        BinaryPrimitives.WriteUInt16BigEndian(headerLengthBytes, checked((ushort)headerPayload.Length));

        var encryptedHeaderLength = EncryptAead(
            VmessAeadKdf.Kdf16(request.User.CmdKey, SaltVmessHeaderPayloadLengthAeadKey, authId, connectionNonce),
            VmessAeadKdf.Kdf(request.User.CmdKey, SaltVmessHeaderPayloadLengthAeadIv, authId, connectionNonce).AsSpan(0, 12).ToArray(),
            headerLengthBytes,
            authId);
        var encryptedHeaderPayload = EncryptAead(
            VmessAeadKdf.Kdf16(request.User.CmdKey, SaltVmessHeaderPayloadAeadKey, authId, connectionNonce),
            VmessAeadKdf.Kdf(request.User.CmdKey, SaltVmessHeaderPayloadAeadIv, authId, connectionNonce).AsSpan(0, 12).ToArray(),
            headerPayload,
            authId);

        using var output = new MemoryStream(
            authId.Length +
            encryptedHeaderLength.Length +
            connectionNonce.Length +
            encryptedHeaderPayload.Length);
        output.Write(authId);
        output.Write(encryptedHeaderLength);
        output.Write(connectionNonce);
        output.Write(encryptedHeaderPayload);
        return output.ToArray();
    }

    public static async ValueTask ReadResponseAsync(
        Stream stream,
        VmessRequest request,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(stream);
        ArgumentNullException.ThrowIfNull(request);

        var responseBodyKey = VmessHandshakeReader.DeriveResponseBodyKey(request.RequestBodyKey);
        var responseBodyIv = VmessHandshakeReader.DeriveResponseBodyIv(request.RequestBodyIv);

        var encryptedLength = new byte[2 + AeadTagLength];
        await TrojanProtocolCodec.ReadExactAsync(stream, encryptedLength, cancellationToken).ConfigureAwait(false);

        var decryptedLength = DecryptAead(
            VmessAeadKdf.Kdf16(responseBodyKey, SaltAeadResponseHeaderLengthKey),
            VmessAeadKdf.Kdf(responseBodyIv, SaltAeadResponseHeaderLengthIv).AsSpan(0, 12).ToArray(),
            encryptedLength,
            ReadOnlySpan<byte>.Empty);
        if (decryptedLength.Length != 2)
        {
            throw new InvalidDataException("VMess response header length is invalid.");
        }

        var responseLength = BinaryPrimitives.ReadUInt16BigEndian(decryptedLength);
        var encryptedPayload = new byte[responseLength + AeadTagLength];
        await TrojanProtocolCodec.ReadExactAsync(stream, encryptedPayload, cancellationToken).ConfigureAwait(false);

        var decryptedPayload = DecryptAead(
            VmessAeadKdf.Kdf16(responseBodyKey, SaltAeadResponseHeaderPayloadKey),
            VmessAeadKdf.Kdf(responseBodyIv, SaltAeadResponseHeaderPayloadIv).AsSpan(0, 12).ToArray(),
            encryptedPayload,
            ReadOnlySpan<byte>.Empty);
        if (decryptedPayload.Length < 4)
        {
            throw new InvalidDataException("VMess response header is truncated.");
        }

        if (decryptedPayload[0] != request.ResponseHeader)
        {
            throw new InvalidDataException(
                $"VMess response header mismatch. Expected {request.ResponseHeader} but received {decryptedPayload[0]}.");
        }

        var commandId = decryptedPayload[2];
        var commandLength = decryptedPayload[3];
        if (commandId != 0 && decryptedPayload.Length < 4 + commandLength)
        {
            throw new InvalidDataException("VMess response command payload is truncated.");
        }
    }

    internal static byte[] CreateAuthId(ReadOnlySpan<byte> commandKey, long? timestamp = null)
    {
        var authIdPlaintext = new byte[16];
        BinaryPrimitives.WriteInt64BigEndian(
            authIdPlaintext.AsSpan(0, 8),
            timestamp ?? DateTimeOffset.UtcNow.ToUnixTimeSeconds());
        RandomNumberGenerator.Fill(authIdPlaintext.AsSpan(8, 4));
        BinaryPrimitives.WriteUInt32BigEndian(
            authIdPlaintext.AsSpan(12, 4),
            ComputeCrc32(authIdPlaintext.AsSpan(0, 12)));

        using var aes = Aes.Create();
        aes.Mode = CipherMode.ECB;
        aes.Padding = PaddingMode.None;
        aes.Key = VmessAeadKdf.Kdf16(commandKey, SaltAuthIdEncryptionKey);

        using var encryptor = aes.CreateEncryptor();
        var encrypted = new byte[authIdPlaintext.Length];
        var written = encryptor.TransformBlock(authIdPlaintext, 0, authIdPlaintext.Length, encrypted, 0);
        if (written != encrypted.Length)
        {
            throw new InvalidDataException("VMess auth id encryption failed.");
        }

        return encrypted;
    }

    private static byte[] BuildRequestPayload(VmessRequest request)
    {
        using var output = new MemoryStream();
        output.WriteByte(request.Version);
        output.Write(request.RequestBodyIv);
        output.Write(request.RequestBodyKey);
        output.WriteByte(request.ResponseHeader);
        output.WriteByte(request.Option);

        var paddingLength = RandomNumberGenerator.GetInt32(0, 16);
        var security = (byte)((paddingLength << 4) | (byte)request.Security);
        output.WriteByte(security);
        output.WriteByte(0);
        output.WriteByte((byte)request.Command);

        if (request.Command != VmessCommand.Mux)
        {
            WriteAddressPort(output, request.TargetHost, request.TargetPort);
        }

        if (paddingLength > 0)
        {
            output.Write(RandomNumberGenerator.GetBytes(paddingLength));
        }

        var header = output.ToArray();
        var payload = new byte[header.Length + 4];
        Buffer.BlockCopy(header, 0, payload, 0, header.Length);
        BinaryPrimitives.WriteUInt32BigEndian(payload.AsSpan(header.Length, 4), ComputeFnv1a(header));
        return payload;
    }

    private static void WriteAddressPort(Stream stream, string host, int port)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(host);
        if (port is <= 0 or > 65535)
        {
            throw new ArgumentOutOfRangeException(nameof(port), port, "VMess target port must be between 1 and 65535.");
        }

        Span<byte> portBytes = stackalloc byte[2];
        BinaryPrimitives.WriteUInt16BigEndian(portBytes, checked((ushort)port));
        stream.Write(portBytes);

        if (System.Net.IPAddress.TryParse(host, out var ipAddress))
        {
            stream.WriteByte(ipAddress.AddressFamily switch
            {
                System.Net.Sockets.AddressFamily.InterNetwork => (byte)0x01,
                System.Net.Sockets.AddressFamily.InterNetworkV6 => (byte)0x04,
                _ => throw new InvalidDataException($"Unsupported VMess IP address family: {host}.")
            });

            var addressBytes = ipAddress.GetAddressBytes();
            stream.Write(addressBytes);
            return;
        }

        var domainBytes = Encoding.ASCII.GetBytes(host);
        if (domainBytes.Length is 0 or > byte.MaxValue)
        {
            throw new InvalidDataException("VMess domain address must be between 1 and 255 ASCII bytes.");
        }

        stream.WriteByte(0x03);
        stream.WriteByte((byte)domainBytes.Length);
        stream.Write(domainBytes);
    }

    private static void ValidateRequest(VmessRequest request)
    {
        ArgumentNullException.ThrowIfNull(request.User);

        if (request.User.CmdKey.Length != 16)
        {
            throw new ArgumentException("VMess request command key must be 16 bytes.", nameof(request));
        }

        if (request.RequestBodyKey.Length != 16)
        {
            throw new ArgumentException("VMess request body key must be 16 bytes.", nameof(request));
        }

        if (request.RequestBodyIv.Length != 16)
        {
            throw new ArgumentException("VMess request body IV must be 16 bytes.", nameof(request));
        }

        if (request.Command is not VmessCommand.Mux)
        {
            ArgumentException.ThrowIfNullOrWhiteSpace(request.TargetHost);
            if (request.TargetPort is <= 0 or > 65535)
            {
                throw new ArgumentOutOfRangeException(nameof(request), request.TargetPort, "VMess target port must be between 1 and 65535.");
            }
        }
    }

    private static byte[] DecryptAead(
        ReadOnlySpan<byte> key,
        ReadOnlySpan<byte> nonce,
        ReadOnlySpan<byte> encrypted,
        ReadOnlySpan<byte> additionalData)
    {
        if (encrypted.Length < AeadTagLength)
        {
            throw new InvalidDataException("VMess AEAD payload is truncated.");
        }

        var ciphertextLength = encrypted.Length - AeadTagLength;
        var plaintext = new byte[ciphertextLength];
        using var aead = new AesGcm(key.ToArray(), AeadTagLength);
        aead.Decrypt(
            nonce,
            encrypted[..ciphertextLength],
            encrypted[ciphertextLength..],
            plaintext,
            additionalData);
        return plaintext;
    }

    private static byte[] EncryptAead(
        ReadOnlySpan<byte> key,
        ReadOnlySpan<byte> nonce,
        ReadOnlySpan<byte> plaintext,
        ReadOnlySpan<byte> additionalData)
    {
        var output = new byte[plaintext.Length + AeadTagLength];
        using var aead = new AesGcm(key.ToArray(), AeadTagLength);
        aead.Encrypt(
            nonce,
            plaintext,
            output.AsSpan(0, plaintext.Length),
            output.AsSpan(plaintext.Length, AeadTagLength),
            additionalData);
        return output;
    }

    private static uint ComputeFnv1a(ReadOnlySpan<byte> data)
    {
        const uint offsetBasis = 2166136261;
        const uint prime = 16777619;

        var hash = offsetBasis;
        foreach (var value in data)
        {
            hash ^= value;
            hash *= prime;
        }

        return hash;
    }

    private static uint ComputeCrc32(ReadOnlySpan<byte> data)
    {
        var crc = 0xFFFFFFFFu;
        foreach (var value in data)
        {
            crc ^= value;
            for (var bit = 0; bit < 8; bit++)
            {
                crc = (crc & 1) != 0
                    ? (crc >> 1) ^ 0xEDB88320u
                    : crc >> 1;
            }
        }

        return crc ^ 0xFFFFFFFFu;
    }
}

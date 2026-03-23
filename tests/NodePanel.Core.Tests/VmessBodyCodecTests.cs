using System.Text;
using NodePanel.Core.Protocol;
using NodePanel.Core.Runtime;

namespace NodePanel.Core.Tests;

public sealed class VmessBodyCodecTests
{
    [Fact]
    public async Task ReadAsync_decrypts_aes_gcm_stream_with_authenticated_length_and_padding()
    {
        var request = CreateRequest(
            VmessCommand.Connect,
            VmessSecurityType.Aes128Gcm,
            VmessRequestOptions.ChunkStream |
            VmessRequestOptions.ChunkMasking |
            VmessRequestOptions.GlobalPadding |
            VmessRequestOptions.AuthenticatedLength);
        var expected = CreatePayload(20000);
        var encoded = EncodeClientStream(request, expected, 4093);

        await using var transport = new MemoryStream(encoded, writable: false);
        var vmessStream = new VmessDataStream(transport, request);

        var actual = await ReadAllAsync(vmessStream, 317);
        Assert.Equal(expected, actual);
    }

    [Fact]
    public async Task WriteAsync_encrypts_chacha20_poly1305_stream_with_authenticated_length_and_padding()
    {
        var request = CreateRequest(
            VmessCommand.Connect,
            VmessSecurityType.ChaCha20Poly1305,
            VmessRequestOptions.ChunkStream |
            VmessRequestOptions.ChunkMasking |
            VmessRequestOptions.GlobalPadding |
            VmessRequestOptions.AuthenticatedLength);
        var expected = CreatePayload(24000);

        await using var transport = new MemoryStream();
        var vmessStream = new VmessDataStream(transport, request);

        await vmessStream.WriteAsync(expected, CancellationToken.None);
        await vmessStream.CompleteResponseAsync(CancellationToken.None);

        var actual = DecodeResponseStream(request, transport.ToArray());
        Assert.Equal(expected, actual);
    }

    [Fact]
    public async Task ReadPacketAsync_decrypts_aes_gcm_packets()
    {
        var request = CreateRequest(
            VmessCommand.Udp,
            VmessSecurityType.Aes128Gcm,
            VmessRequestOptions.ChunkStream |
            VmessRequestOptions.ChunkMasking |
            VmessRequestOptions.GlobalPadding |
            VmessRequestOptions.AuthenticatedLength);
        var expectedPackets = new[]
        {
            Encoding.ASCII.GetBytes("alpha"),
            CreatePayload(1024),
            Encoding.ASCII.GetBytes("omega")
        };
        var encoded = EncodeClientPackets(request, expectedPackets);

        await using var transport = new MemoryStream(encoded, writable: false);
        var vmessStream = new VmessDataStream(transport, request);

        foreach (var expected in expectedPackets)
        {
            var actual = await vmessStream.ReadPacketAsync(CancellationToken.None);
            Assert.NotNull(actual);
            Assert.Equal(expected, actual);
        }

        Assert.Null(await vmessStream.ReadPacketAsync(CancellationToken.None));
    }

    [Fact]
    public async Task WritePacketAsync_encrypts_chacha20_poly1305_packets()
    {
        var request = CreateRequest(
            VmessCommand.Udp,
            VmessSecurityType.ChaCha20Poly1305,
            VmessRequestOptions.ChunkStream |
            VmessRequestOptions.ChunkMasking |
            VmessRequestOptions.GlobalPadding |
            VmessRequestOptions.AuthenticatedLength);
        var expectedPackets = new[]
        {
            Encoding.ASCII.GetBytes("first"),
            CreatePayload(1536),
            Encoding.ASCII.GetBytes("last")
        };

        await using var transport = new MemoryStream();
        var vmessStream = new VmessDataStream(transport, request);

        foreach (var packet in expectedPackets)
        {
            await vmessStream.WritePacketAsync(packet, CancellationToken.None);
        }

        await vmessStream.CompleteResponseAsync(CancellationToken.None);

        var actualPackets = DecodeResponsePackets(request, transport.ToArray());
        Assert.Equal(expectedPackets.Length, actualPackets.Count);
        for (var index = 0; index < expectedPackets.Length; index++)
        {
            Assert.Equal(expectedPackets[index], actualPackets[index]);
        }
    }

    private static async Task<byte[]> ReadAllAsync(Stream stream, int bufferSize)
    {
        using var output = new MemoryStream();
        var buffer = new byte[bufferSize];
        while (true)
        {
            var read = await stream.ReadAsync(buffer.AsMemory(0, buffer.Length), CancellationToken.None);
            if (read == 0)
            {
                break;
            }

            await output.WriteAsync(buffer.AsMemory(0, read), CancellationToken.None);
        }

        return output.ToArray();
    }

    private static byte[] EncodeClientStream(VmessRequest request, ReadOnlySpan<byte> payload, int chunkSize)
    {
        var security = VmessBodyCodecFactory.NormalizeSecurity(request.Security);
        var frameOptions = VmessBodyCodecFactory.CreateRequestFrameOptions(request, security, framed: true);
        var cipher = VmessBodyCodecFactory.CreatePayloadCipher(security, request.RequestBodyKey, request.RequestBodyIv);

        using var output = new MemoryStream();
        var offset = 0;
        while (offset < payload.Length)
        {
            var currentLength = Math.Min(chunkSize, payload.Length - offset);
            WriteFrame(output, payload.Slice(offset, currentLength), cipher, frameOptions);
            offset += currentLength;
        }

        WriteFrame(output, ReadOnlySpan<byte>.Empty, cipher, frameOptions);
        return output.ToArray();
    }

    private static byte[] EncodeClientPackets(VmessRequest request, IReadOnlyList<byte[]> packets)
    {
        var security = VmessBodyCodecFactory.NormalizeSecurity(request.Security);
        var frameOptions = VmessBodyCodecFactory.CreateRequestFrameOptions(request, security, framed: true);
        var cipher = VmessBodyCodecFactory.CreatePayloadCipher(security, request.RequestBodyKey, request.RequestBodyIv);

        using var output = new MemoryStream();
        foreach (var packet in packets)
        {
            WriteFrame(output, packet, cipher, frameOptions);
        }

        WriteFrame(output, ReadOnlySpan<byte>.Empty, cipher, frameOptions);
        return output.ToArray();
    }

    private static byte[] DecodeResponseStream(VmessRequest request, byte[] encoded)
    {
        var packets = DecodeFrames(
            encoded,
            CreateResponseCipher(request),
            CreateResponseFrameOptions(request));
        using var output = new MemoryStream();
        foreach (var packet in packets)
        {
            output.Write(packet);
        }

        return output.ToArray();
    }

    private static IReadOnlyList<byte[]> DecodeResponsePackets(VmessRequest request, byte[] encoded)
        => DecodeFrames(
            encoded,
            CreateResponseCipher(request),
            CreateResponseFrameOptions(request));

    private static IVmessBodyCipher CreateResponseCipher(VmessRequest request)
    {
        var security = VmessBodyCodecFactory.NormalizeSecurity(request.Security);
        var responseBodyKey = VmessHandshakeReader.DeriveResponseBodyKey(request.RequestBodyKey);
        var responseBodyIv = VmessHandshakeReader.DeriveResponseBodyIv(request.RequestBodyIv);
        return VmessBodyCodecFactory.CreatePayloadCipher(security, responseBodyKey, responseBodyIv);
    }

    private static VmessBodyFrameOptions CreateResponseFrameOptions(VmessRequest request)
    {
        var security = VmessBodyCodecFactory.NormalizeSecurity(request.Security);
        var responseBodyIv = VmessHandshakeReader.DeriveResponseBodyIv(request.RequestBodyIv);
        return VmessBodyCodecFactory.CreateResponseFrameOptions(request, security, framed: true, responseBodyIv);
    }

    private static IReadOnlyList<byte[]> DecodeFrames(
        byte[] encoded,
        IVmessBodyCipher cipher,
        VmessBodyFrameOptions frameOptions)
    {
        var packets = new List<byte[]>();
        using var input = new MemoryStream(encoded, writable: false);

        while (true)
        {
            var packet = ReadFrame(input, cipher, frameOptions);
            if (packet is null)
            {
                break;
            }

            packets.Add(packet);
        }

        return packets;
    }

    private static void WriteFrame(
        Stream stream,
        ReadOnlySpan<byte> plaintext,
        IVmessBodyCipher cipher,
        VmessBodyFrameOptions frameOptions)
    {
        ArgumentNullException.ThrowIfNull(frameOptions.SizeCodec);

        var paddingLength = frameOptions.PaddingGenerator?.NextPaddingLength() ?? 0;
        var ciphertext = cipher.Encrypt(plaintext);
        var totalLength = ciphertext.Length + paddingLength;

        var sizeBuffer = new byte[frameOptions.SizeCodec.HeaderLength];
        frameOptions.SizeCodec.WriteSize(totalLength, sizeBuffer);
        stream.Write(sizeBuffer);

        if (ciphertext.Length > 0)
        {
            stream.Write(ciphertext);
        }

        if (paddingLength > 0)
        {
            stream.Write(new byte[paddingLength]);
        }
    }

    private static byte[]? ReadFrame(
        Stream stream,
        IVmessBodyCipher cipher,
        VmessBodyFrameOptions frameOptions)
    {
        ArgumentNullException.ThrowIfNull(frameOptions.SizeCodec);

        var sizeBuffer = new byte[frameOptions.SizeCodec.HeaderLength];
        FillExact(stream, sizeBuffer);

        var paddingLength = frameOptions.PaddingGenerator?.NextPaddingLength() ?? 0;
        var size = frameOptions.SizeCodec.ReadSize(sizeBuffer);
        if (size == cipher.Overhead + paddingLength)
        {
            return null;
        }

        var encrypted = new byte[size];
        FillExact(stream, encrypted);
        return cipher.Decrypt(encrypted.AsSpan(0, size - paddingLength));
    }

    private static void FillExact(Stream stream, byte[] buffer)
    {
        var offset = 0;
        while (offset < buffer.Length)
        {
            var read = stream.Read(buffer, offset, buffer.Length - offset);
            if (read == 0)
            {
                throw new EndOfStreamException("Unexpected end of stream while reading VMess test frame.");
            }

            offset += read;
        }
    }

    private static byte[] CreatePayload(int length)
    {
        var buffer = new byte[length];
        for (var index = 0; index < buffer.Length; index++)
        {
            buffer[index] = (byte)((index * 31 + 17) & 0xFF);
        }

        return buffer;
    }

    private static VmessRequest CreateRequest(VmessCommand command, VmessSecurityType security, byte option)
    {
        var requestBodyKey = new byte[16];
        var requestBodyIv = new byte[16];
        for (var index = 0; index < 16; index++)
        {
            requestBodyKey[index] = (byte)(index + 1);
            requestBodyIv[index] = (byte)(0xF0 - index);
        }

        return new VmessRequest
        {
            Version = 1,
            User = new VmessUser
            {
                UserId = "demo-user",
                Uuid = Guid.NewGuid().ToString("D"),
                CmdKey = CreatePayload(16),
                BytesPerSecond = 0
            },
            RequestBodyKey = requestBodyKey,
            RequestBodyIv = requestBodyIv,
            ResponseHeader = 0x23,
            Option = option,
            Security = security,
            Command = command,
            TargetHost = "example.com",
            TargetPort = command == VmessCommand.Udp ? 53 : 443
        };
    }
}

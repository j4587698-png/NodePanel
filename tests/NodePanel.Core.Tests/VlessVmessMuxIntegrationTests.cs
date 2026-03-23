using System.Buffers.Binary;
using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Text;
using NodePanel.Core.Protocol;
using NodePanel.Core.Runtime;

namespace NodePanel.Core.Tests;

public sealed class VlessVmessMuxIntegrationTests
{
    private static readonly byte[] SaltAeadResponseHeaderLengthKey = Encoding.ASCII.GetBytes("AEAD Resp Header Len Key");
    private static readonly byte[] SaltAeadResponseHeaderLengthIv = Encoding.ASCII.GetBytes("AEAD Resp Header Len IV");
    private static readonly byte[] SaltAeadResponseHeaderPayloadKey = Encoding.ASCII.GetBytes("AEAD Resp Header Key");
    private static readonly byte[] SaltAeadResponseHeaderPayloadIv = Encoding.ASCII.GetBytes("AEAD Resp Header IV");

    [Fact]
    public async Task Vless_mux_relays_tcp_session()
    {
        using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(15));
        var uuid = Guid.NewGuid().ToString("D");
        var user = new VlessUser
        {
            UserId = "vless-user",
            Uuid = uuid,
            BytesPerSecond = 0
        };

        using var echoListener = new TcpListener(IPAddress.Loopback, 0);
        echoListener.Start();
        var echoPort = ((IPEndPoint)echoListener.LocalEndpoint).Port;
        var echoTask = RunTcpEchoServerAsync(echoListener, cts.Token);

        using var frontListener = new TcpListener(IPAddress.Loopback, 0);
        frontListener.Start();
        var frontPort = ((IPEndPoint)frontListener.LocalEndpoint).Port;
        var handler = CreateVlessHandler(new FreedomOutboundHandler());
        var serverTask = Task.Run(async () =>
        {
            using var accepted = await frontListener.AcceptTcpClientAsync(cts.Token);
            await using var stream = accepted.GetStream();
            await handler.HandleAsync(
                stream,
                new VlessInboundSessionOptions
                {
                    InboundTag = "vless-edge",
                    UsersByUuid = new Dictionary<string, VlessUser>(StringComparer.OrdinalIgnoreCase)
                    {
                        [uuid] = user
                    }
                },
                cts.Token);
        }, cts.Token);

        using var client = new TcpClient { NoDelay = true };
        await client.ConnectAsync(IPAddress.Loopback, frontPort, cts.Token);
        await using var stream = client.GetStream();

        await stream.WriteAsync(BuildVlessMuxHandshake(uuid), cts.Token);
        await stream.FlushAsync(cts.Token);

        var responseHeader = new byte[2];
        await stream.ReadExactlyAsync(responseHeader, cts.Token);
        Assert.Equal(new byte[] { 0x00, 0x00 }, responseHeader);

        var outboundFrame = BuildMuxNewDataFrame(
            "127.0.0.1",
            echoPort,
            Encoding.ASCII.GetBytes("ping"));
        await stream.WriteAsync(outboundFrame, cts.Token);
        await stream.FlushAsync(cts.Token);

        var responseFrame = await TrojanMuxFrameCodec.ReadAsync(stream, cts.Token);
        Assert.NotNull(responseFrame);
        Assert.Equal(TrojanMuxSessionStatus.Keep, responseFrame!.Status);
        Assert.Equal("pong", Encoding.ASCII.GetString(responseFrame.Payload));

        var endFrame = await TrojanMuxFrameCodec.ReadAsync(stream, cts.Token);
        Assert.NotNull(endFrame);
        Assert.Equal(TrojanMuxSessionStatus.End, endFrame!.Status);

        client.Close();
        await serverTask;
        Assert.Equal("ping", await echoTask);
    }

    [Fact]
    public async Task Vmess_mux_relays_tcp_session_over_aes_gcm_body()
    {
        using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(15));
        var user = new VmessUser
        {
            UserId = "vmess-user",
            Uuid = Guid.NewGuid().ToString("D"),
            CmdKey = Enumerable.Range(1, 16).Select(static value => (byte)value).ToArray(),
            BytesPerSecond = 0
        };
        var request = CreateVmessMuxRequest(user);

        using var echoListener = new TcpListener(IPAddress.Loopback, 0);
        echoListener.Start();
        var echoPort = ((IPEndPoint)echoListener.LocalEndpoint).Port;
        var echoTask = RunTcpEchoServerAsync(echoListener, cts.Token);

        using var frontListener = new TcpListener(IPAddress.Loopback, 0);
        frontListener.Start();
        var frontPort = ((IPEndPoint)frontListener.LocalEndpoint).Port;
        var handler = CreateVmessHandler(new FreedomOutboundHandler());
        var serverTask = Task.Run(async () =>
        {
            using var accepted = await frontListener.AcceptTcpClientAsync(cts.Token);
            await using var stream = accepted.GetStream();
            await handler.HandleAsync(
                stream,
                new VmessInboundSessionOptions
                {
                    InboundTag = "vmess-edge",
                    Users = [user]
                },
                cts.Token);
        }, cts.Token);

        using var client = new TcpClient { NoDelay = true };
        await client.ConnectAsync(IPAddress.Loopback, frontPort, cts.Token);
        await using var stream = client.GetStream();

        await stream.WriteAsync(VmessTestRequestEncoder.BuildRequestHeader(user, request), cts.Token);
        await stream.FlushAsync(cts.Token);

        var responsePayload = await ReadVmessResponseHeaderAsync(stream, request, cts.Token);
        Assert.Equal(request.ResponseHeader, responsePayload[0]);

        var requestBodyWriter = new VmessRequestBodyWriter(request);
        var muxPayload = BuildMuxNewDataFrame(
            "127.0.0.1",
            echoPort,
            Encoding.ASCII.GetBytes("ping"));
        await stream.WriteAsync(requestBodyWriter.EncodeChunk(muxPayload), cts.Token);
        await stream.FlushAsync(cts.Token);

        await using var responseBodyStream = new VmessResponseBodyStream(stream, request);
        var responseFrame = await TrojanMuxFrameCodec.ReadAsync(responseBodyStream, cts.Token);
        Assert.NotNull(responseFrame);
        Assert.Equal(TrojanMuxSessionStatus.Keep, responseFrame!.Status);
        Assert.Equal("pong", Encoding.ASCII.GetString(responseFrame.Payload));

        var endFrame = await TrojanMuxFrameCodec.ReadAsync(responseBodyStream, cts.Token);
        Assert.NotNull(endFrame);
        Assert.Equal(TrojanMuxSessionStatus.End, endFrame!.Status);

        await stream.WriteAsync(requestBodyWriter.EncodeChunk(Array.Empty<byte>()), cts.Token);
        await stream.FlushAsync(cts.Token);

        await serverTask;
        Assert.Equal("ping", await echoTask);
    }

    private static VlessInboundConnectionHandler CreateVlessHandler(IOutboundHandler outboundHandler)
    {
        var dispatcher = CreateDispatcher(outboundHandler);
        var rateLimiterRegistry = new RateLimiterRegistry();
        var trafficRegistry = new TrafficRegistry();
        return new VlessInboundConnectionHandler(
            dispatcher,
            new VlessHandshakeReader(),
            new TrojanMuxInboundServer(
                dispatcher,
                rateLimiterRegistry,
                trafficRegistry),
            new VlessUdpRelay(
                dispatcher,
                rateLimiterRegistry,
                trafficRegistry,
                new VlessUdpPacketReader(),
                new VlessUdpPacketWriter()),
            new SessionRegistry(),
            new RelayService(),
            rateLimiterRegistry,
            trafficRegistry);
    }

    private static VmessInboundConnectionHandler CreateVmessHandler(IOutboundHandler outboundHandler)
    {
        var dispatcher = CreateDispatcher(outboundHandler);
        var rateLimiterRegistry = new RateLimiterRegistry();
        var trafficRegistry = new TrafficRegistry();
        return new VmessInboundConnectionHandler(
            dispatcher,
            new VmessHandshakeReader(),
            new TrojanMuxInboundServer(
                dispatcher,
                rateLimiterRegistry,
                trafficRegistry),
            new VmessUdpRelay(
                dispatcher,
                rateLimiterRegistry,
                trafficRegistry),
            new SessionRegistry(),
            new RelayService(),
            rateLimiterRegistry,
            trafficRegistry);
    }

    private static IDispatcher CreateDispatcher(IOutboundHandler outboundHandler)
        => new DefaultDispatcher(
            new DefaultOutboundRouter(
                [outboundHandler],
                new StaticOutboundRuntimePlanProvider(
                    new OutboundRuntimePlan
                    {
                        Outbounds =
                        [
                            new OutboundRuntime
                            {
                                Tag = "default",
                                Protocol = outboundHandler.Protocol
                            }
                        ],
                        DefaultOutboundTag = "default"
                    })));

    private static byte[] BuildVlessMuxHandshake(string uuid)
    {
        var buffer = new byte[19];
        buffer[0] = 0;
        Assert.True(ProtocolUuid.TryWriteBytes(uuid, buffer.AsSpan(1, 16)));
        buffer[17] = 0;
        buffer[18] = (byte)VlessCommand.Mux;
        return buffer;
    }

    private static byte[] BuildMuxNewDataFrame(string host, int port, byte[] payload)
    {
        using var stream = new MemoryStream();
        TrojanMuxFrameCodec.WriteAsync(
            stream,
            new TrojanMuxFrame
            {
                SessionId = 1,
                Status = TrojanMuxSessionStatus.New,
                Option = TrojanMuxFrameOption.Data,
                Target = new TrojanMuxFrameTarget(host, port, DispatchNetwork.Tcp),
                Payload = payload
            },
            CancellationToken.None).AsTask().GetAwaiter().GetResult();
        return stream.ToArray();
    }

    private static async Task<string> RunTcpEchoServerAsync(TcpListener listener, CancellationToken cancellationToken)
    {
        using var accepted = await listener.AcceptTcpClientAsync(cancellationToken);
        await using var stream = accepted.GetStream();
        var payload = new byte[4];
        await stream.ReadExactlyAsync(payload.AsMemory(0, payload.Length), cancellationToken);
        await stream.WriteAsync(Encoding.ASCII.GetBytes("pong"), cancellationToken);
        await stream.FlushAsync(cancellationToken);
        return Encoding.ASCII.GetString(payload);
    }

    private static VmessRequest CreateVmessMuxRequest(VmessUser user)
    {
        var requestBodyKey = Enumerable.Range(0x10, 16).Select(static value => (byte)value).ToArray();
        var requestBodyIv = Enumerable.Range(0x80, 16).Select(static value => (byte)value).ToArray();

        return new VmessRequest
        {
            Version = 1,
            User = user,
            RequestBodyKey = requestBodyKey,
            RequestBodyIv = requestBodyIv,
            ResponseHeader = 0x5A,
            Option = VmessRequestOptions.ChunkStream |
                     VmessRequestOptions.ChunkMasking |
                     VmessRequestOptions.GlobalPadding |
                     VmessRequestOptions.AuthenticatedLength,
            Security = VmessSecurityType.Aes128Gcm,
            Command = VmessCommand.Mux,
            TargetHost = TrojanMuxProtocol.Host,
            TargetPort = 0
        };
    }

    private static async Task<byte[]> ReadVmessResponseHeaderAsync(Stream stream, VmessRequest request, CancellationToken cancellationToken)
    {
        var responseBodyKey = VmessHandshakeReader.DeriveResponseBodyKey(request.RequestBodyKey);
        var responseBodyIv = VmessHandshakeReader.DeriveResponseBodyIv(request.RequestBodyIv);

        var encryptedLength = new byte[18];
        await stream.ReadExactlyAsync(encryptedLength, cancellationToken);
        var decryptedLength = DecryptAead(
            VmessAeadKdf.Kdf16(responseBodyKey, SaltAeadResponseHeaderLengthKey),
            VmessAeadKdf.Kdf(responseBodyIv, SaltAeadResponseHeaderLengthIv).AsSpan(0, 12).ToArray(),
            encryptedLength,
            ReadOnlySpan<byte>.Empty);
        var payloadLength = BinaryPrimitives.ReadUInt16BigEndian(decryptedLength);

        var encryptedPayload = new byte[payloadLength + 16];
        await stream.ReadExactlyAsync(encryptedPayload, cancellationToken);
        return DecryptAead(
            VmessAeadKdf.Kdf16(responseBodyKey, SaltAeadResponseHeaderPayloadKey),
            VmessAeadKdf.Kdf(responseBodyIv, SaltAeadResponseHeaderPayloadIv).AsSpan(0, 12).ToArray(),
            encryptedPayload,
            ReadOnlySpan<byte>.Empty);
    }

    private static void WriteVmessFrame(
        Stream stream,
        ReadOnlySpan<byte> payload,
        IVmessBodyCipher cipher,
        VmessBodyFrameOptions frameOptions)
    {
        Assert.NotNull(frameOptions.SizeCodec);

        var paddingLength = frameOptions.PaddingGenerator?.NextPaddingLength() ?? 0;
        var encryptedPayload = cipher.Encrypt(payload);
        var totalLength = encryptedPayload.Length + paddingLength;

        var sizeBuffer = new byte[frameOptions.SizeCodec!.HeaderLength];
        frameOptions.SizeCodec.WriteSize(totalLength, sizeBuffer);
        stream.Write(sizeBuffer);
        if (encryptedPayload.Length > 0)
        {
            stream.Write(encryptedPayload);
        }

        if (paddingLength > 0)
        {
            stream.Write(new byte[paddingLength]);
        }
    }

    private static byte[] EncryptAead(
        ReadOnlySpan<byte> key,
        ReadOnlySpan<byte> nonce,
        ReadOnlySpan<byte> plaintext,
        ReadOnlySpan<byte> additionalData)
    {
        var output = new byte[plaintext.Length + 16];
        using var aead = new AesGcm(key.ToArray(), 16);
        aead.Encrypt(
            nonce,
            plaintext,
            output.AsSpan(0, plaintext.Length),
            output.AsSpan(plaintext.Length, 16),
            additionalData);
        return output;
    }

    private static byte[] DecryptAead(
        ReadOnlySpan<byte> key,
        ReadOnlySpan<byte> nonce,
        ReadOnlySpan<byte> ciphertext,
        ReadOnlySpan<byte> additionalData)
    {
        var plaintext = new byte[ciphertext.Length - 16];
        using var aead = new AesGcm(key.ToArray(), 16);
        aead.Decrypt(
            nonce,
            ciphertext[..^16],
            ciphertext[^16..],
            plaintext,
            additionalData);
        return plaintext;
    }

    private sealed class StaticOutboundRuntimePlanProvider : IOutboundRuntimePlanProvider
    {
        private readonly OutboundRuntimePlan _plan;

        public StaticOutboundRuntimePlanProvider(OutboundRuntimePlan plan)
        {
            _plan = plan;
        }

        public OutboundRuntimePlan GetCurrentOutboundPlan() => _plan;
    }

    private sealed class VmessRequestBodyWriter
    {
        private readonly IVmessBodyCipher _cipher;
        private readonly VmessBodyFrameOptions _frameOptions;

        public VmessRequestBodyWriter(VmessRequest request)
        {
            var security = VmessBodyCodecFactory.NormalizeSecurity(request.Security);
            var framed = VmessBodyCodecFactory.RequiresFraming(security, request.Option);
            _frameOptions = VmessBodyCodecFactory.CreateRequestFrameOptions(request, security, framed);
            _cipher = VmessBodyCodecFactory.CreatePayloadCipher(security, request.RequestBodyKey, request.RequestBodyIv);
        }

        public byte[] EncodeChunk(ReadOnlySpan<byte> payload)
        {
            using var stream = new MemoryStream();
            WriteVmessFrame(stream, payload, _cipher, _frameOptions);
            return stream.ToArray();
        }
    }

    private sealed class VmessResponseBodyStream : Stream
    {
        private readonly Stream _inner;
        private readonly IVmessBodyCipher _cipher;
        private readonly IVmessChunkSizeCodec _sizeCodec;
        private readonly IVmessPaddingLengthGenerator? _paddingGenerator;

        private byte[]? _currentChunk;
        private int _currentChunkOffset;
        private bool _completed;

        public VmessResponseBodyStream(Stream inner, VmessRequest request)
        {
            _inner = inner;

            var security = VmessBodyCodecFactory.NormalizeSecurity(request.Security);
            var responseBodyKey = VmessHandshakeReader.DeriveResponseBodyKey(request.RequestBodyKey);
            var responseBodyIv = VmessHandshakeReader.DeriveResponseBodyIv(request.RequestBodyIv);
            var framed = VmessBodyCodecFactory.RequiresFraming(security, request.Option);
            var frameOptions = VmessBodyCodecFactory.CreateResponseFrameOptions(request, security, framed, responseBodyIv);

            _cipher = VmessBodyCodecFactory.CreatePayloadCipher(security, responseBodyKey, responseBodyIv);
            _sizeCodec = frameOptions.SizeCodec
                ?? throw new InvalidOperationException("VMess response body stream requires framed chunk sizes.");
            _paddingGenerator = frameOptions.PaddingGenerator;
        }

        public override bool CanRead => true;

        public override bool CanSeek => false;

        public override bool CanWrite => false;

        public override long Length => throw new NotSupportedException();

        public override long Position
        {
            get => throw new NotSupportedException();
            set => throw new NotSupportedException();
        }

        public override void Flush()
        {
        }

        public override Task FlushAsync(CancellationToken cancellationToken) => Task.CompletedTask;

        public override int Read(byte[] buffer, int offset, int count)
            => ReadAsync(buffer.AsMemory(offset, count), CancellationToken.None).AsTask().GetAwaiter().GetResult();

        public override async ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken cancellationToken = default)
        {
            if (_completed)
            {
                return 0;
            }

            if (_currentChunk is null || _currentChunkOffset >= _currentChunk.Length)
            {
                var nextChunk = await ReadNextChunkAsync(cancellationToken).ConfigureAwait(false);
                if (nextChunk is null)
                {
                    _completed = true;
                    return 0;
                }

                _currentChunk = nextChunk;
                _currentChunkOffset = 0;
            }

            var available = _currentChunk.Length - _currentChunkOffset;
            var count = Math.Min(buffer.Length, available);
            _currentChunk.AsMemory(_currentChunkOffset, count).CopyTo(buffer);
            _currentChunkOffset += count;
            if (_currentChunkOffset >= _currentChunk.Length)
            {
                _currentChunk = null;
                _currentChunkOffset = 0;
            }

            return count;
        }

        public override int Read(Span<byte> buffer)
        {
            var scratch = new byte[buffer.Length];
            var read = ReadAsync(scratch, CancellationToken.None).AsTask().GetAwaiter().GetResult();
            scratch.AsSpan(0, read).CopyTo(buffer);
            return read;
        }

        public override void Write(byte[] buffer, int offset, int count)
            => throw new NotSupportedException();

        public override ValueTask WriteAsync(ReadOnlyMemory<byte> buffer, CancellationToken cancellationToken = default)
            => throw new NotSupportedException();

        public override Task WriteAsync(byte[] buffer, int offset, int count, CancellationToken cancellationToken)
            => throw new NotSupportedException();

        public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();

        public override void SetLength(long value) => throw new NotSupportedException();

        private async ValueTask<byte[]?> ReadNextChunkAsync(CancellationToken cancellationToken)
        {
            var sizeBuffer = new byte[_sizeCodec.HeaderLength];
            await _inner.ReadExactlyAsync(sizeBuffer, cancellationToken);

            var paddingLength = _paddingGenerator?.NextPaddingLength() ?? 0;
            var encodedSize = _sizeCodec.ReadSize(sizeBuffer);
            var minimumTerminatorSize = _cipher.Overhead + paddingLength;
            if (encodedSize == minimumTerminatorSize)
            {
                return null;
            }

            Assert.True(encodedSize >= minimumTerminatorSize);

            var encryptedPayload = new byte[encodedSize];
            await _inner.ReadExactlyAsync(encryptedPayload, cancellationToken);
            return _cipher.Decrypt(encryptedPayload.AsSpan(0, encodedSize - paddingLength));
        }
    }
}

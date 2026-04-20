using System.Buffers.Binary;
using System.Security.Cryptography;
using System.Text;
using NodePanel.Core.Runtime;

namespace NodePanel.Core.Tests;

public sealed class RuntimeSniffingEvaluatorTests
{
    [Fact]
    public void Evaluate_detects_http_and_overrides_destination()
    {
        var sniffing = new RuntimeSniffingOptions
        {
            Enabled = true,
            DestinationOverride = [RoutingProtocols.Http]
        };

        var decision = RuntimeSniffingEvaluator.Evaluate(
            sniffing,
            Encoding.ASCII.GetBytes("GET / HTTP/1.1\r\nHost: edge.example.com\r\n\r\n"),
            DispatchNetwork.Tcp,
            new DispatchDestination
            {
                Host = "203.0.113.10",
                Port = 80,
                Network = DispatchNetwork.Tcp
            });

        Assert.Equal(RoutingProtocols.Http, decision.Protocol);
        Assert.Equal("edge.example.com", decision.Domain);
        Assert.NotNull(decision.OverrideDestination);
        Assert.Equal("edge.example.com", decision.OverrideDestination!.Host);
    }

    [Fact]
    public void Evaluate_populates_http_content_attributes()
    {
        var decision = RuntimeSniffingEvaluator.Evaluate(
            new RuntimeSniffingOptions
            {
                Enabled = true
            },
            Encoding.ASCII.GetBytes("GET /api?query=1 HTTP/1.1\r\nHost: edge.example.com\r\nX-Test: value\r\n\r\n"),
            DispatchNetwork.Tcp,
            new DispatchDestination
            {
                Host = "203.0.113.10",
                Port = 80,
                Network = DispatchNetwork.Tcp
            });

        Assert.Equal(RoutingProtocols.Http, decision.Protocol);
        Assert.Equal("edge.example.com", decision.Domain);
        Assert.Equal(RoutingProtocols.Http, decision.Content.Protocol);
        Assert.True(decision.Content.Attributes.TryGetValue(":method", out var method));
        Assert.Equal("GET", method);
        Assert.True(decision.Content.Attributes.TryGetValue(":path", out var path));
        Assert.Equal("/api?query=1", path);
        Assert.True(decision.Content.Attributes.TryGetValue("host", out var host));
        Assert.Equal("edge.example.com", host);
        Assert.True(decision.Content.Attributes.TryGetValue("x-test", out var testHeader));
        Assert.Equal("value", testHeader);
    }

    [Fact]
    public void Evaluate_respects_domain_exclusion_and_route_only()
    {
        var sniffing = new RuntimeSniffingOptions
        {
            Enabled = true,
            RouteOnly = true,
            DestinationOverride = [RoutingProtocols.Http],
            DomainsExcluded = ["blocked.example.com"]
        };

        var blocked = RuntimeSniffingEvaluator.Evaluate(
            sniffing,
            Encoding.ASCII.GetBytes("GET / HTTP/1.1\r\nHost: blocked.example.com\r\n\r\n"),
            DispatchNetwork.Tcp,
            new DispatchDestination
            {
                Host = "203.0.113.10",
                Port = 80,
                Network = DispatchNetwork.Tcp
            });
        var routeOnly = RuntimeSniffingEvaluator.Evaluate(
            sniffing with { DomainsExcluded = Array.Empty<string>() },
            Encoding.ASCII.GetBytes("GET / HTTP/1.1\r\nHost: route.example.com\r\n\r\n"),
            DispatchNetwork.Tcp,
            new DispatchDestination
            {
                Host = "203.0.113.11",
                Port = 80,
                Network = DispatchNetwork.Tcp
            });

        Assert.Equal(RoutingProtocols.Http, blocked.Protocol);
        Assert.Equal("blocked.example.com", blocked.Domain);
        Assert.False(blocked.OverrideMatched);
        Assert.Null(blocked.OverrideDestination);
        Assert.Null(blocked.RouteTarget);

        Assert.True(routeOnly.OverrideMatched);
        Assert.True(routeOnly.RouteOnly);
        Assert.Null(routeOnly.OverrideDestination);
        Assert.NotNull(routeOnly.RouteTarget);
        Assert.Equal("route.example.com", routeOnly.RouteTarget!.Host);
        Assert.Equal(80, routeOnly.RouteTarget.Port);
    }

    [Fact]
    public void Evaluate_detects_tls_sni_and_quic()
    {
        var sniffing = new RuntimeSniffingOptions
        {
            Enabled = true,
            DestinationOverride = [RoutingProtocols.Tls]
        };

        var tlsDecision = RuntimeSniffingEvaluator.Evaluate(
            sniffing,
            BuildTlsClientHello("tls.example.com"),
            DispatchNetwork.Tcp,
            new DispatchDestination
            {
                Host = "198.51.100.10",
                Port = 443,
                Network = DispatchNetwork.Tcp
            });
        var quicDecision = RuntimeSniffingEvaluator.Evaluate(
            new RuntimeSniffingOptions
            {
                Enabled = true,
                DestinationOverride = [RoutingProtocols.Quic]
            },
            BuildQuicInitialClientHello("quic.example.com"),
            DispatchNetwork.Udp,
            new DispatchDestination
            {
                Host = "198.51.100.11",
                Port = 443,
                Network = DispatchNetwork.Udp
            });

        Assert.Equal(RoutingProtocols.Tls, tlsDecision.Protocol);
        Assert.Equal("tls.example.com", tlsDecision.Domain);
        Assert.NotNull(tlsDecision.OverrideDestination);
        Assert.Equal("tls.example.com", tlsDecision.OverrideDestination!.Host);

        Assert.Equal(RoutingProtocols.Quic, quicDecision.Protocol);
        Assert.Equal("quic.example.com", quicDecision.Domain);
        Assert.NotNull(quicDecision.OverrideDestination);
        Assert.Equal("quic.example.com", quicDecision.OverrideDestination!.Host);
        Assert.Equal(RoutingProtocols.Tls, tlsDecision.Content.Protocol);
        Assert.Equal(RoutingProtocols.Quic, quicDecision.Content.Protocol);
    }

    [Fact]
    public void Evaluate_does_not_detect_http_without_host_header()
    {
        var decision = RuntimeSniffingEvaluator.Evaluate(
            new RuntimeSniffingOptions
            {
                Enabled = true,
                DestinationOverride = [RoutingProtocols.Http]
            },
            Encoding.ASCII.GetBytes("GET / HTTP/1.1\r\nUser-Agent: test\r\n\r\n"),
            DispatchNetwork.Tcp,
            new DispatchDestination
            {
                Host = "203.0.113.20",
                Port = 80,
                Network = DispatchNetwork.Tcp
            });

        Assert.Equal(string.Empty, decision.Protocol);
        Assert.Equal(string.Empty, decision.Domain);
        Assert.Equal(DispatchContent.Empty, decision.Content);
        Assert.False(decision.OverrideMatched);
        Assert.Null(decision.OverrideDestination);
    }

    [Fact]
    public void Evaluate_does_not_detect_tls_without_sni()
    {
        var decision = RuntimeSniffingEvaluator.Evaluate(
            new RuntimeSniffingOptions
            {
                Enabled = true,
                DestinationOverride = [RoutingProtocols.Tls]
            },
            BuildTlsClientHelloWithoutServerName(),
            DispatchNetwork.Tcp,
            new DispatchDestination
            {
                Host = "198.51.100.21",
                Port = 443,
                Network = DispatchNetwork.Tcp
            });

        Assert.Equal(string.Empty, decision.Protocol);
        Assert.Equal(string.Empty, decision.Domain);
        Assert.Equal(DispatchContent.Empty, decision.Content);
        Assert.False(decision.OverrideMatched);
        Assert.Null(decision.OverrideDestination);
    }

    [Fact]
    public void Evaluate_detects_quic_sni_across_coalesced_initial_packets()
    {
        var decision = RuntimeSniffingEvaluator.Evaluate(
            new RuntimeSniffingOptions
            {
                Enabled = true,
                DestinationOverride = [RoutingProtocols.Quic]
            },
            BuildCoalescedQuicInitialClientHello("coalesced.example.com"),
            DispatchNetwork.Udp,
            new DispatchDestination
            {
                Host = "198.51.100.22",
                Port = 443,
                Network = DispatchNetwork.Udp
            });

        Assert.Equal(RoutingProtocols.Quic, decision.Protocol);
        Assert.Equal("coalesced.example.com", decision.Domain);
        Assert.NotNull(decision.OverrideDestination);
        Assert.Equal("coalesced.example.com", decision.OverrideDestination!.Host);
        Assert.Equal(RoutingProtocols.Quic, decision.Content.Protocol);
    }

    [Fact]
    public void Evaluate_resolves_fake_dns_metadata_and_overrides_destination()
    {
        var fakeDnsEngine = CreateFakeDnsEngine();
        var fakeAddress = Assert.Single(fakeDnsEngine.GetFakeIPForDomain("mapped.example.com", ipv4: true, ipv6: false));

        var decision = RuntimeSniffingEvaluator.Evaluate(
            new RuntimeSniffingOptions
            {
                Enabled = true,
                DestinationOverride = [RoutingProtocols.FakeDns]
            },
            ReadOnlySpan<byte>.Empty,
            DispatchNetwork.Tcp,
            new DispatchDestination
            {
                Host = fakeAddress.ToString(),
                Port = 443,
                Network = DispatchNetwork.Tcp
            },
            fakeDnsEngine);

        Assert.Equal(RoutingProtocols.FakeDns, decision.Protocol);
        Assert.Equal("mapped.example.com", decision.Domain);
        Assert.True(decision.OverrideMatched);
        Assert.False(decision.RouteOnly);
        Assert.NotNull(decision.OverrideDestination);
        Assert.Equal("mapped.example.com", decision.OverrideDestination!.Host);
    }

    [Fact]
    public void Evaluate_prefers_exact_fake_dns_metadata_over_content_protocol_when_mapping_exists()
    {
        var fakeDnsEngine = CreateFakeDnsEngine();
        var fakeAddress = Assert.Single(fakeDnsEngine.GetFakeIPForDomain("mapped.example.com", ipv4: true, ipv6: false));

        var decision = RuntimeSniffingEvaluator.Evaluate(
            new RuntimeSniffingOptions
            {
                Enabled = true,
                RouteOnly = true,
                DestinationOverride = [RoutingProtocols.Http]
            },
            Encoding.ASCII.GetBytes("GET / HTTP/1.1\r\nHost: payload.example.com\r\n\r\n"),
            DispatchNetwork.Tcp,
            new DispatchDestination
            {
                Host = fakeAddress.ToString(),
                Port = 80,
                Network = DispatchNetwork.Tcp
            },
            fakeDnsEngine);

        Assert.Equal(RoutingProtocols.FakeDns, decision.Protocol);
        Assert.Equal("mapped.example.com", decision.Domain);
        Assert.Equal(RoutingProtocols.FakeDns, decision.Content.Protocol);
        Assert.False(decision.OverrideMatched);
        Assert.False(decision.RouteOnly);
        Assert.Null(decision.OverrideDestination);
        Assert.Null(decision.RouteTarget);
    }

    [Fact]
    public void Evaluate_uses_content_domain_when_fake_dns_mapping_is_missing_but_ip_is_in_pool()
    {
        var fakeDnsEngine = CreateFakeDnsEngine();

        var decision = RuntimeSniffingEvaluator.Evaluate(
            new RuntimeSniffingOptions
            {
                Enabled = true,
                RouteOnly = true,
                DestinationOverride = [RoutingProtocols.FakeDns]
            },
            Encoding.ASCII.GetBytes("GET / HTTP/1.1\r\nHost: missed.example.com\r\n\r\n"),
            DispatchNetwork.Tcp,
            new DispatchDestination
            {
                Host = "198.18.0.25",
                Port = 80,
                Network = DispatchNetwork.Tcp
            },
            fakeDnsEngine);

        Assert.Equal(RoutingProtocols.FakeDnsThenOthers, decision.Protocol);
        Assert.Equal("missed.example.com", decision.Domain);
        Assert.Equal(RoutingProtocols.FakeDnsThenOthers, decision.Content.Protocol);
        Assert.True(decision.OverrideMatched);
        Assert.False(decision.RouteOnly);
        Assert.NotNull(decision.OverrideDestination);
        Assert.Equal("missed.example.com", decision.OverrideDestination!.Host);
    }

    private static FakeDnsEngine CreateFakeDnsEngine()
        => new(
        [
            new FakeDnsPoolRuntime
            {
                IpPool = FakeDnsDefaults.IPv4Pool,
                LruSize = 256
            }
        ]);

    private static byte[] BuildQuicInitialClientHello(string host)
        => BuildQuicInitialPacket(BuildTlsClientHello(host).AsSpan(5));

    private static byte[] BuildCoalescedQuicInitialClientHello(string host)
    {
        var cryptoData = BuildTlsClientHello(host).AsSpan(5).ToArray();
        var firstLength = cryptoData.Length / 2;
        var firstPacket = BuildQuicInitialPacket(cryptoData.AsSpan(0, firstLength), 0, 1);
        var secondPacket = BuildQuicInitialPacket(cryptoData.AsSpan(firstLength), (ulong)firstLength, 2);
        var payload = new byte[firstPacket.Length + secondPacket.Length];
        firstPacket.CopyTo(payload, 0);
        secondPacket.CopyTo(payload, firstPacket.Length);
        return payload;
    }

    private static byte[] BuildQuicInitialPacket(
        ReadOnlySpan<byte> cryptoData,
        ulong cryptoOffset = 0,
        uint packetNumberValue = 1)
    {
        byte[] destinationConnectionId = [0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08];
        byte[] sourceConnectionId = [0x01, 0x02, 0x03, 0x04];
        var packetNumber = new byte[4];
        BinaryPrimitives.WriteUInt32BigEndian(packetNumber, packetNumberValue);

        using var plaintextStream = new MemoryStream();
        plaintextStream.WriteByte(0x06);
        WriteQuicVarInt(plaintextStream, cryptoOffset);
        WriteQuicVarInt(plaintextStream, (ulong)cryptoData.Length);
        plaintextStream.Write(cryptoData);
        var plaintext = plaintextStream.ToArray();

        using var headerStream = new MemoryStream();
        headerStream.WriteByte(0xc3);
        headerStream.Write([0x00, 0x00, 0x00, 0x01]);
        headerStream.WriteByte((byte)destinationConnectionId.Length);
        headerStream.Write(destinationConnectionId);
        headerStream.WriteByte((byte)sourceConnectionId.Length);
        headerStream.Write(sourceConnectionId);
        WriteQuicVarInt(headerStream, 0);
        WriteQuicVarInt(headerStream, (ulong)(packetNumber.Length + plaintext.Length + 16));
        var header = headerStream.ToArray();

        byte[] initialSalt =
        [
            0x38, 0x76, 0x2c, 0xf7, 0xf5, 0x59, 0x34, 0xb3, 0x4d, 0x17,
            0x9a, 0xe6, 0xa4, 0xc8, 0x0c, 0xad, 0xcc, 0xbb, 0x7f, 0x0a
        ];
        var initialSecret = HMACSHA256.HashData(initialSalt, destinationConnectionId);
        var secret = HkdfExpandLabel(initialSecret, "client in", 32);
        var headerProtectionKey = HkdfExpandLabel(secret, "quic hp", 16);
        var key = HkdfExpandLabel(secret, "quic key", 16);
        var iv = HkdfExpandLabel(secret, "quic iv", 12);

        var associatedData = new byte[header.Length + packetNumber.Length];
        header.CopyTo(associatedData, 0);
        packetNumber.CopyTo(associatedData, header.Length);

        var ciphertext = new byte[plaintext.Length];
        var tag = new byte[16];
        using (var aead = new AesGcm(key, 16))
        {
            aead.Encrypt(CreatePacketNonce(iv, packetNumber), plaintext, ciphertext, tag, associatedData);
        }

        var packet = new byte[associatedData.Length + ciphertext.Length + tag.Length];
        associatedData.CopyTo(packet, 0);
        ciphertext.CopyTo(packet, associatedData.Length);
        tag.CopyTo(packet, associatedData.Length + ciphertext.Length);

        Span<byte> mask = stackalloc byte[16];
        ApplyHeaderProtection(
            packet.AsSpan(header.Length + 4, 16),
            headerProtectionKey,
            mask);
        packet[0] ^= (byte)(mask[0] & 0x0f);
        for (var index = 0; index < packetNumber.Length; index++)
        {
            packet[header.Length + index] ^= mask[index + 1];
        }

        return packet;
    }

    private static void ApplyHeaderProtection(
        ReadOnlySpan<byte> sample,
        ReadOnlySpan<byte> key,
        Span<byte> mask)
    {
        using var aes = Aes.Create();
        aes.Mode = CipherMode.ECB;
        aes.Padding = PaddingMode.None;
        aes.Key = key.ToArray();
        using var encryptor = aes.CreateEncryptor();
        var protectedMask = encryptor.TransformFinalBlock(sample.ToArray(), 0, sample.Length);
        protectedMask.CopyTo(mask);
    }

    private static byte[] CreatePacketNonce(ReadOnlySpan<byte> iv, ReadOnlySpan<byte> packetNumber)
    {
        var nonce = iv.ToArray();
        for (var index = 0; index < packetNumber.Length; index++)
        {
            nonce[nonce.Length - packetNumber.Length + index] ^= packetNumber[index];
        }

        return nonce;
    }

    private static byte[] HkdfExpandLabel(ReadOnlySpan<byte> secret, string label, int length)
    {
        var labelBytes = Encoding.ASCII.GetBytes("tls13 " + label);
        var info = new byte[2 + 1 + labelBytes.Length + 1];
        BinaryPrimitives.WriteUInt16BigEndian(info.AsSpan(0, 2), (ushort)length);
        info[2] = (byte)labelBytes.Length;
        labelBytes.CopyTo(info.AsSpan(3));
        return HkdfExpand(secret, info, length);
    }

    private static byte[] HkdfExpand(ReadOnlySpan<byte> pseudorandomKey, ReadOnlySpan<byte> info, int length)
    {
        var output = new byte[length];
        Span<byte> previous = stackalloc byte[32];
        var previousLength = 0;
        var offset = 0;
        byte counter = 1;
        while (offset < output.Length)
        {
            var input = new byte[previousLength + info.Length + 1];
            if (previousLength > 0)
            {
                previous[..previousLength].CopyTo(input);
            }

            info.CopyTo(input.AsSpan(previousLength));
            input[^1] = counter++;

            var block = HMACSHA256.HashData(pseudorandomKey.ToArray(), input);
            block.CopyTo(previous);
            previousLength = block.Length;

            var copyLength = Math.Min(block.Length, output.Length - offset);
            block.AsSpan(0, copyLength).CopyTo(output.AsSpan(offset));
            offset += copyLength;
        }

        return output;
    }

    private static void WriteQuicVarInt(Stream stream, ulong value)
    {
        switch (value)
        {
            case <= 0x3f:
                stream.WriteByte((byte)value);
                return;
            case <= 0x3fff:
                Span<byte> shortBuffer = stackalloc byte[2];
                BinaryPrimitives.WriteUInt16BigEndian(shortBuffer, (ushort)(0x4000 | value));
                stream.Write(shortBuffer);
                return;
            case <= 0x3fffffff:
                Span<byte> intBuffer = stackalloc byte[4];
                BinaryPrimitives.WriteUInt32BigEndian(intBuffer, 0x80000000u | (uint)value);
                stream.Write(intBuffer);
                return;
            default:
                Span<byte> longBuffer = stackalloc byte[8];
                BinaryPrimitives.WriteUInt64BigEndian(longBuffer, 0xc000000000000000ul | value);
                stream.Write(longBuffer);
                return;
        }
    }

    private static byte[] BuildTlsClientHello(string host)
    {
        var hostBytes = Encoding.ASCII.GetBytes(host);
        using var handshakeBody = new MemoryStream();
        handshakeBody.WriteByte(0x03);
        handshakeBody.WriteByte(0x03);
        handshakeBody.Write(new byte[32]);
        handshakeBody.WriteByte(0x00);
        handshakeBody.WriteByte(0x00);
        handshakeBody.WriteByte(0x02);
        handshakeBody.WriteByte(0x13);
        handshakeBody.WriteByte(0x01);
        handshakeBody.WriteByte(0x01);
        handshakeBody.WriteByte(0x00);

        using var extensions = new MemoryStream();
        var serverNameListLength = (ushort)(1 + 2 + hostBytes.Length);
        var extensionLength = (ushort)(2 + serverNameListLength);
        extensions.WriteByte(0x00);
        extensions.WriteByte(0x00);
        extensions.WriteByte((byte)(extensionLength >> 8));
        extensions.WriteByte((byte)extensionLength);
        extensions.WriteByte((byte)(serverNameListLength >> 8));
        extensions.WriteByte((byte)serverNameListLength);
        extensions.WriteByte(0x00);
        extensions.WriteByte((byte)(hostBytes.Length >> 8));
        extensions.WriteByte((byte)hostBytes.Length);
        extensions.Write(hostBytes);

        var extensionsBytes = extensions.ToArray();
        handshakeBody.WriteByte((byte)(extensionsBytes.Length >> 8));
        handshakeBody.WriteByte((byte)extensionsBytes.Length);
        handshakeBody.Write(extensionsBytes);

        var handshakeBytes = handshakeBody.ToArray();
        using var record = new MemoryStream();
        record.WriteByte(0x16);
        record.WriteByte(0x03);
        record.WriteByte(0x01);
        var recordLength = (ushort)(handshakeBytes.Length + 4);
        record.WriteByte((byte)(recordLength >> 8));
        record.WriteByte((byte)recordLength);
        record.WriteByte(0x01);
        record.WriteByte((byte)((handshakeBytes.Length >> 16) & 0xff));
        record.WriteByte((byte)((handshakeBytes.Length >> 8) & 0xff));
        record.WriteByte((byte)(handshakeBytes.Length & 0xff));
        record.Write(handshakeBytes);
        return record.ToArray();
    }

    private static byte[] BuildTlsClientHelloWithoutServerName()
    {
        using var handshakeBody = new MemoryStream();
        handshakeBody.WriteByte(0x03);
        handshakeBody.WriteByte(0x03);
        handshakeBody.Write(new byte[32]);
        handshakeBody.WriteByte(0x00);
        handshakeBody.WriteByte(0x00);
        handshakeBody.WriteByte(0x02);
        handshakeBody.WriteByte(0x13);
        handshakeBody.WriteByte(0x01);
        handshakeBody.WriteByte(0x01);
        handshakeBody.WriteByte(0x00);
        handshakeBody.WriteByte(0x00);
        handshakeBody.WriteByte(0x00);

        var handshakeBytes = handshakeBody.ToArray();
        using var record = new MemoryStream();
        record.WriteByte(0x16);
        record.WriteByte(0x03);
        record.WriteByte(0x01);
        var recordLength = (ushort)(handshakeBytes.Length + 4);
        record.WriteByte((byte)(recordLength >> 8));
        record.WriteByte((byte)recordLength);
        record.WriteByte(0x01);
        record.WriteByte((byte)((handshakeBytes.Length >> 16) & 0xff));
        record.WriteByte((byte)((handshakeBytes.Length >> 8) & 0xff));
        record.WriteByte((byte)(handshakeBytes.Length & 0xff));
        record.Write(handshakeBytes);
        return record.ToArray();
    }
}

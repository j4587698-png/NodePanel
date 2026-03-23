using System.Security.Cryptography;
using System.Text;
using NodePanel.Core.Runtime;

namespace NodePanel.Core.Tests;

public sealed class TrojanClientHelloPolicyTests
{
    [Fact]
    public void TryParse_extracts_server_name_application_protocols_and_ja3()
    {
        var payload = BuildTlsClientHello("edge.example.com", ["h2", "http/1.1"]);

        var parsed = TrojanTlsClientHelloParser.TryParse(payload, out var metadata);

        Assert.True(parsed);
        Assert.Equal("edge.example.com", metadata.ServerName);
        Assert.Equal(["h2", "http/1.1"], metadata.ApplicationProtocols);
        Assert.Equal([0x1301, 0x1302], metadata.CipherSuites);
        Assert.Equal([0x0000, 0x0010, 0x000a, 0x000b], metadata.Extensions);
        Assert.Equal([23], metadata.SupportedGroups);
        Assert.Equal([0], metadata.EcPointFormats);

        const string expectedJa3 = "771,4865-4866,0-16-10-11,23,0";
        Assert.Equal(expectedJa3, metadata.Ja3Text);
        Assert.Equal(
            Convert.ToHexStringLower(MD5.HashData(Encoding.ASCII.GetBytes(expectedJa3))),
            metadata.Ja3Hash);
    }

    [Fact]
    public void ShouldReject_applies_allow_and_block_rules_from_parsed_client_hello()
    {
        var payload = BuildTlsClientHello("edge.example.com", ["h2", "http/1.1"]);
        Assert.True(TrojanTlsClientHelloParser.TryParse(payload, out var metadata));

        var allowedPolicy = new TrojanClientHelloPolicyRuntime
        {
            Enabled = true,
            AllowedServerNames = ["*.example.com"],
            AllowedApplicationProtocols = ["h2"],
            AllowedJa3 = [metadata.Ja3Hash]
        };

        var allowedRejected = TrojanClientHelloPolicyEvaluator.ShouldReject(
            allowedPolicy,
            metadata,
            out var allowedDecision);

        var blockedRejected = TrojanClientHelloPolicyEvaluator.ShouldReject(
            new TrojanClientHelloPolicyRuntime
            {
                Enabled = true,
                BlockedJa3 = [metadata.Ja3Hash]
            },
            metadata,
            out var blockedDecision);

        Assert.False(allowedRejected);
        Assert.False(allowedDecision.Rejected);
        Assert.True(blockedRejected);
        Assert.True(blockedDecision.Rejected);
        Assert.Equal("ja3-blocked", blockedDecision.Reason);
    }

    private static byte[] BuildTlsClientHello(string host, IReadOnlyList<string> applicationProtocols)
    {
        var hostBytes = Encoding.ASCII.GetBytes(host);
        var cipherSuites = new ushort[] { 0x1301, 0x1302 };
        var supportedGroups = new ushort[] { 23 };
        var ecPointFormats = new byte[] { 0x00 };

        using var handshakeBody = new MemoryStream();
        WriteUInt16(handshakeBody, 0x0303);
        handshakeBody.Write(new byte[32]);
        handshakeBody.WriteByte(0x00);

        WriteUInt16(handshakeBody, (ushort)(cipherSuites.Length * 2));
        foreach (var cipherSuite in cipherSuites)
        {
            WriteUInt16(handshakeBody, cipherSuite);
        }

        handshakeBody.WriteByte(0x01);
        handshakeBody.WriteByte(0x00);

        using var extensions = new MemoryStream();
        WriteExtension(extensions, 0x0000, extension =>
        {
            WriteUInt16(extension, (ushort)(hostBytes.Length + 3));
            extension.WriteByte(0x00);
            WriteUInt16(extension, (ushort)hostBytes.Length);
            extension.Write(hostBytes);
        });
        WriteExtension(extensions, 0x0010, extension =>
        {
            using var protocols = new MemoryStream();
            foreach (var applicationProtocol in applicationProtocols)
            {
                var currentProtocolBytes = Encoding.ASCII.GetBytes(applicationProtocol);
                protocols.WriteByte((byte)currentProtocolBytes.Length);
                protocols.Write(currentProtocolBytes);
            }

            var protocolListBytes = protocols.ToArray();
            WriteUInt16(extension, (ushort)protocolListBytes.Length);
            extension.Write(protocolListBytes);
        });
        WriteExtension(extensions, 0x000a, extension =>
        {
            WriteUInt16(extension, (ushort)(supportedGroups.Length * 2));
            foreach (var supportedGroup in supportedGroups)
            {
                WriteUInt16(extension, supportedGroup);
            }
        });
        WriteExtension(extensions, 0x000b, extension =>
        {
            extension.WriteByte((byte)ecPointFormats.Length);
            extension.Write(ecPointFormats);
        });

        var extensionBytes = extensions.ToArray();
        WriteUInt16(handshakeBody, (ushort)extensionBytes.Length);
        handshakeBody.Write(extensionBytes);

        var handshakeBytes = handshakeBody.ToArray();
        using var record = new MemoryStream();
        record.WriteByte(0x16);
        record.WriteByte(0x03);
        record.WriteByte(0x01);
        WriteUInt16(record, (ushort)(handshakeBytes.Length + 4));
        record.WriteByte(0x01);
        record.WriteByte((byte)((handshakeBytes.Length >> 16) & 0xff));
        record.WriteByte((byte)((handshakeBytes.Length >> 8) & 0xff));
        record.WriteByte((byte)(handshakeBytes.Length & 0xff));
        record.Write(handshakeBytes);
        return record.ToArray();
    }

    private static void WriteExtension(MemoryStream destination, ushort extensionType, Action<MemoryStream> writer)
    {
        using var payload = new MemoryStream();
        writer(payload);
        var payloadBytes = payload.ToArray();

        WriteUInt16(destination, extensionType);
        WriteUInt16(destination, (ushort)payloadBytes.Length);
        destination.Write(payloadBytes);
    }

    private static void WriteUInt16(Stream destination, ushort value)
    {
        destination.WriteByte((byte)(value >> 8));
        destination.WriteByte((byte)value);
    }
}

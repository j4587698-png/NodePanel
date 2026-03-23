using System.Text;
using NodePanel.Core.Cryptography;
using NodePanel.Core.Protocol;

namespace NodePanel.Core.Tests;

public sealed class TrojanHandshakeWriterTests
{
    [Fact]
    public async Task WriteAsync_writes_connect_header()
    {
        await using var stream = new MemoryStream();
        var writer = new TrojanHandshakeWriter();

        await writer.WriteAsync(stream, "demo-password", TrojanCommand.Connect, "example.com", 443, CancellationToken.None);

        var payload = stream.ToArray();
        var expectedHash = TrojanPassword.ComputeHash("demo-password");
        var actualHash = Encoding.ASCII.GetString(payload.AsSpan(0, TrojanProtocolCodec.UserHashLength));

        Assert.Equal(expectedHash, actualHash);
        Assert.Equal((byte)'\r', payload[TrojanProtocolCodec.UserHashLength]);
        Assert.Equal((byte)'\n', payload[TrojanProtocolCodec.UserHashLength + 1]);
        Assert.Equal((byte)TrojanCommand.Connect, payload[TrojanProtocolCodec.UserHashLength + 2]);

        var domainLengthOffset = TrojanProtocolCodec.UserHashLength + 3;
        Assert.Equal(0x03, payload[domainLengthOffset]);
        Assert.Equal((byte)"example.com".Length, payload[domainLengthOffset + 1]);
        Assert.Equal("example.com", Encoding.ASCII.GetString(payload.AsSpan(domainLengthOffset + 2, "example.com".Length)));
        Assert.Equal(0x01, payload[^4]);
        Assert.Equal(0xBB, payload[^3]);
        Assert.Equal((byte)'\r', payload[^2]);
        Assert.Equal((byte)'\n', payload[^1]);
    }

    [Fact]
    public async Task WriteAsync_writes_udp_associate_header()
    {
        await using var stream = new MemoryStream();
        var writer = new TrojanHandshakeWriter();

        await writer.WriteAsync(stream, "demo-password", TrojanCommand.Associate, "127.0.0.1", 53, CancellationToken.None);

        var payload = stream.ToArray();
        Assert.Equal((byte)TrojanCommand.Associate, payload[TrojanProtocolCodec.UserHashLength + 2]);

        var addressOffset = TrojanProtocolCodec.UserHashLength + 3;
        Assert.Equal(0x01, payload[addressOffset]);
        Assert.Equal(127, payload[addressOffset + 1]);
        Assert.Equal(0, payload[addressOffset + 2]);
        Assert.Equal(0, payload[addressOffset + 3]);
        Assert.Equal(1, payload[addressOffset + 4]);
        Assert.Equal(0x00, payload[addressOffset + 5]);
        Assert.Equal(0x35, payload[addressOffset + 6]);
        Assert.Equal((byte)'\r', payload[^2]);
        Assert.Equal((byte)'\n', payload[^1]);
    }
}

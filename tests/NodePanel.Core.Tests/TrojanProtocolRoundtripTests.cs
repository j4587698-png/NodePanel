using System.Text;
using NodePanel.Core.Cryptography;
using NodePanel.Core.Protocol;

namespace NodePanel.Core.Tests;

public sealed class TrojanProtocolRoundtripTests
{
    [Fact]
    public async Task HandshakeReader_reads_connect_header_written_by_writer()
    {
        await using var stream = new MemoryStream();
        var writer = new TrojanHandshakeWriter();
        var reader = new TrojanHandshakeReader();

        await writer.WriteAsync(
            stream,
            "demo-password",
            TrojanCommand.Connect,
            "2001:db8::1",
            8443,
            CancellationToken.None);

        stream.Position = 0;
        var request = await reader.ReadAsync(stream, CancellationToken.None);

        Assert.Equal(TrojanPassword.ComputeHash("demo-password"), request.UserHash);
        Assert.Equal(TrojanCommand.Connect, request.Command);
        Assert.Equal("2001:db8::1", request.TargetHost);
        Assert.Equal(8443, request.TargetPort);
    }

    [Fact]
    public async Task UdpPacketReader_reads_packet_written_by_writer_after_associate_header()
    {
        await using var stream = new MemoryStream();
        var handshakeWriter = new TrojanHandshakeWriter();
        var handshakeReader = new TrojanHandshakeReader();
        var packetWriter = new TrojanUdpPacketWriter();
        var packetReader = new TrojanUdpPacketReader();
        var payload = Encoding.ASCII.GetBytes("test string");

        await handshakeWriter.WriteAsync(
            stream,
            "demo-password",
            TrojanCommand.Associate,
            "127.0.0.1",
            53,
            CancellationToken.None);

        await packetWriter.WriteAsync(
            stream,
            new TrojanUdpPacket
            {
                DestinationHost = "8.8.8.8",
                DestinationPort = 53,
                Payload = payload
            },
            CancellationToken.None);

        stream.Position = 0;

        var request = await handshakeReader.ReadAsync(stream, CancellationToken.None);
        var packet = await packetReader.ReadAsync(stream, CancellationToken.None);

        Assert.Equal(TrojanPassword.ComputeHash("demo-password"), request.UserHash);
        Assert.Equal(TrojanCommand.Associate, request.Command);
        Assert.Equal("127.0.0.1", request.TargetHost);
        Assert.Equal(53, request.TargetPort);

        Assert.NotNull(packet);
        Assert.Equal("8.8.8.8", packet!.DestinationHost);
        Assert.Equal(53, packet.DestinationPort);
        Assert.Equal("test string", Encoding.ASCII.GetString(packet.Payload));
    }
}

using NodePanel.Core.Protocol;

namespace NodePanel.Core.Tests;

public sealed class VlessProtocolRoundtripTests
{
    [Fact]
    public async Task HandshakeReader_reads_connect_header_written_by_writer_in_xray_order()
    {
        var writer = new VlessHandshakeWriter();
        var reader = new VlessHandshakeReader();
        var payload = writer.Build(
            "11111111-1111-1111-1111-111111111111",
            VlessCommand.Connect,
            "example.org",
            443,
            version: 0);

        await using var stream = new MemoryStream(payload, writable: false);
        var request = await reader.ReadAsync(stream, CancellationToken.None);

        Assert.Equal((byte)0, request.Version);
        Assert.Equal("11111111-1111-1111-1111-111111111111", request.UserUuid);
        Assert.Equal(0x1111, request.VlessRoutePort);
        Assert.Equal(VlessCommand.Connect, request.Command);
        Assert.Equal("example.org", request.TargetHost);
        Assert.Equal(443, request.TargetPort);
        Assert.True(request.Addons.IsEmpty);
    }

    [Fact]
    public async Task HandshakeReader_reads_flow_and_seed_addons_written_by_writer()
    {
        var writer = new VlessHandshakeWriter();
        var reader = new VlessHandshakeReader();
        var payload = writer.Build(
            "11111111-1111-1111-1111-111111111111",
            VlessCommand.Connect,
            "example.org",
            443,
            version: 0,
            addons: new VlessHeaderAddons
            {
                Flow = "xtls-rprx-vision",
                Seed = [0x01, 0x02, 0x03]
            });

        await using var stream = new MemoryStream(payload, writable: false);
        var request = await reader.ReadAsync(stream, CancellationToken.None);

        Assert.Equal("xtls-rprx-vision", request.Addons.Flow);
        Assert.Equal([0x01, 0x02, 0x03], request.Addons.Seed);
    }

    [Fact]
    public void HandshakeWriter_writes_flow_addon_in_xray_protobuf_shape()
    {
        var payload = new VlessHandshakeWriter().Build(
            "11111111-1111-1111-1111-111111111111",
            VlessCommand.Connect,
            "example.org",
            443,
            version: 0,
            addons: new VlessHeaderAddons
            {
                Flow = "xtls-rprx-vision"
            });

        var expectedAddons = new byte[]
        {
            0x0A,
            0x10,
            (byte)'x',
            (byte)'t',
            (byte)'l',
            (byte)'s',
            (byte)'-',
            (byte)'r',
            (byte)'p',
            (byte)'r',
            (byte)'x',
            (byte)'-',
            (byte)'v',
            (byte)'i',
            (byte)'s',
            (byte)'i',
            (byte)'o',
            (byte)'n'
        };

        Assert.Equal(expectedAddons.Length, payload[17]);
        Assert.Equal(expectedAddons, payload.AsSpan(18, expectedAddons.Length).ToArray());
    }

    [Fact]
    public async Task ReadResponseAsync_reads_addons_written_by_response_writer()
    {
        await using var stream = new MemoryStream();
        await VlessHandshakeReader.WriteResponseAsync(
            stream,
            version: 0,
            new VlessHeaderAddons
            {
                Flow = "xtls-rprx-vision",
                Seed = [0x09, 0x08]
            },
            CancellationToken.None);
        stream.Position = 0;

        var addons = await VlessHandshakeReader.ReadResponseAsync(stream, expectedVersion: 0, CancellationToken.None);

        Assert.Equal("xtls-rprx-vision", addons.Flow);
        Assert.Equal([0x09, 0x08], addons.Seed);
    }

    [Fact]
    public async Task ReadResponseAsync_rejects_unexpected_version()
    {
        await using var stream = new MemoryStream([1, 0], writable: false);

        var exception = await Assert.ThrowsAsync<InvalidDataException>(() =>
            VlessHandshakeReader.ReadResponseAsync(stream, expectedVersion: 0, CancellationToken.None).AsTask());

        Assert.Contains("response version", exception.Message, StringComparison.OrdinalIgnoreCase);
    }
}

using System.Net;
using System.Text;
using NodePanel.Core.Runtime;
using NodePanel.Core.Transport;

namespace NodePanel.Core.Tests;

public sealed class ProxyProtocolReaderTests
{
    [Fact]
    public async Task ReadAsync_parses_proxy_protocol_v1_without_consuming_following_payload()
    {
        var payload = Encoding.ASCII.GetBytes("PROXY TCP4 203.0.113.10 198.51.100.20 54321 443\r\nX");
        await using var stream = new MemoryStream(payload, writable: false);

        var result = await ProxyProtocolReader.ReadAsync(stream, CancellationToken.None);
        var trailingByte = stream.ReadByte();

        var remote = Assert.IsType<IPEndPoint>(result.RemoteEndPoint);
        var local = Assert.IsType<IPEndPoint>(result.LocalEndPoint);
        Assert.Equal(IPAddress.Parse("203.0.113.10"), remote.Address);
        Assert.Equal(54321, remote.Port);
        Assert.Equal(IPAddress.Parse("198.51.100.20"), local.Address);
        Assert.Equal(443, local.Port);
        Assert.Equal((int)'X', trailingByte);
    }

    [Fact]
    public async Task ReadAsync_parses_proxy_protocol_v2_without_consuming_following_payload()
    {
        var header = new byte[]
        {
            0x0D, 0x0A, 0x0D, 0x0A, 0x00, 0x0D, 0x0A, 0x51, 0x55, 0x49, 0x54, 0x0A,
            0x21, 0x11, 0x00, 0x0C,
            203, 0, 113, 10,
            198, 51, 100, 20,
            0xD4, 0x31,
            0x01, 0xBB,
            (byte)'Y'
        };
        await using var stream = new MemoryStream(header, writable: false);

        var result = await ProxyProtocolReader.ReadAsync(stream, CancellationToken.None);
        var trailingByte = stream.ReadByte();

        var remote = Assert.IsType<IPEndPoint>(result.RemoteEndPoint);
        var local = Assert.IsType<IPEndPoint>(result.LocalEndPoint);
        Assert.Equal(IPAddress.Parse("203.0.113.10"), remote.Address);
        Assert.Equal(54321, remote.Port);
        Assert.Equal(IPAddress.Parse("198.51.100.20"), local.Address);
        Assert.Equal(443, local.Port);
        Assert.Equal((int)'Y', trailingByte);
    }

    [Fact]
    public async Task ReadAsync_rejects_missing_proxy_protocol_header()
    {
        await using var stream = new MemoryStream(Encoding.ASCII.GetBytes("GET /ws HTTP/1.1\r\n"), writable: false);

        await Assert.ThrowsAsync<InvalidDataException>(async () =>
        {
            await ProxyProtocolReader.ReadAsync(stream, CancellationToken.None);
        });
    }

    [Fact]
    public void ExtractRequestPath_returns_http_path_and_ignores_non_http_payload()
    {
        var httpPayload = Encoding.ASCII.GetBytes("GET /ws?ed=1 HTTP/1.1\r\nHost: example.com\r\n\r\n");
        var trojanPayload = Encoding.ASCII.GetBytes(new string('a', 56) + "\r\n");

        Assert.Equal("/ws", HttpRequestProbe.ExtractRequestPath(httpPayload));
        Assert.Equal(string.Empty, HttpRequestProbe.ExtractRequestPath(trojanPayload));
    }
}

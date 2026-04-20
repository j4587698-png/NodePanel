using System.Net;
using System.Net.Sockets;
using System.Text;
using NodePanel.Core.Protocol;
using NodePanel.Core.Runtime;

namespace NodePanel.Core.Tests;

public sealed class ShadowsocksProtocolCodecTests
{
    [Theory]
    [InlineData(ShadowsocksCipherTypes.Aes128Gcm, "tcp-password-1", "127.0.0.1", 1234)]
    [InlineData(ShadowsocksCipherTypes.Aes256Gcm, "tcp-password-2", "::1", 4321)]
    [InlineData(ShadowsocksCipherTypes.ChaCha20Poly1305, "tcp-password-3", "example.com", 443)]
    [InlineData(ShadowsocksCipherTypes.XChaCha20Poly1305, "tcp-password-4", "ss.example.org", 9443)]
    [InlineData(ShadowsocksCipherTypes.None, "", "example.net", 8443)]
    public async Task Tcp_client_and_server_streams_roundtrip_request_and_response(
        string cipher,
        string password,
        string host,
        int port)
    {
        using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(10));
        using var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();
        var serverPort = ((IPEndPoint)listener.LocalEndpoint).Port;
        var account = ShadowsocksAccount.Create(cipher, password);
        var requestPayload = Encoding.ASCII.GetBytes("hello-shadowsocks-request");
        var responsePayload = Encoding.ASCII.GetBytes("hello-shadowsocks-response");

        var serverTask = Task.Run(async () =>
        {
            using var accepted = await listener.AcceptTcpClientAsync(cts.Token);
            await using var serverStream = accepted.GetStream();
            var session = await ShadowsocksProtocolCodec.AcceptServerTcpStreamAsync(serverStream, account, cts.Token);

            Assert.Equal(host, session.Destination.Host);
            Assert.Equal(port, session.Destination.Port);

            await using var tunneled = session.Stream;
            var received = new byte[requestPayload.Length];
            await ReadExactAsync(tunneled, received, cts.Token);
            Assert.Equal(requestPayload, received);

            await tunneled.WriteAsync(responsePayload, cts.Token);
            await tunneled.FlushAsync(cts.Token);
        }, cts.Token);

        using var client = new TcpClient();
        await client.ConnectAsync(IPAddress.Loopback, serverPort, cts.Token);
        await using var rawClientStream = client.GetStream();
        await using var clientStream = await ShadowsocksProtocolCodec.OpenClientTcpStreamAsync(
            rawClientStream,
            account,
            host,
            port,
            cts.Token);

        await clientStream.WriteAsync(requestPayload, cts.Token);
        await clientStream.FlushAsync(cts.Token);

        var response = new byte[responsePayload.Length];
        await ReadExactAsync(clientStream, response, cts.Token);
        Assert.Equal(responsePayload, response);

        await serverTask;
    }

    [Theory]
    [InlineData(ShadowsocksCipherTypes.Aes128Gcm, "udp-password-1")]
    [InlineData(ShadowsocksCipherTypes.ChaCha20Poly1305, "udp-password-2")]
    [InlineData(ShadowsocksCipherTypes.XChaCha20Poly1305, "udp-password-3")]
    [InlineData(ShadowsocksCipherTypes.None, "")]
    public void Udp_packet_roundtrips_for_supported_ciphers(string cipher, string password)
    {
        var account = ShadowsocksAccount.Create(cipher, password);
        var payload = Encoding.ASCII.GetBytes("hello-shadowsocks-udp");

        var encoded = ShadowsocksProtocolCodec.EncodeUdpPacket(
            account,
            "udp.example.com",
            53,
            payload);
        var decoded = ShadowsocksProtocolCodec.DecodeUdpPacket(account, encoded);

        Assert.Equal("udp.example.com", decoded.Host);
        Assert.Equal(53, decoded.Port);
        Assert.Equal(payload, decoded.Payload);
    }

    private static async Task ReadExactAsync(Stream stream, byte[] buffer, CancellationToken cancellationToken)
    {
        var offset = 0;
        while (offset < buffer.Length)
        {
            var read = await stream.ReadAsync(buffer.AsMemory(offset, buffer.Length - offset), cancellationToken);
            if (read == 0)
            {
                throw new EndOfStreamException("Unexpected EOF while reading Shadowsocks test payload.");
            }

            offset += read;
        }
    }
}

using System.Text;
using NodePanel.Core.Protocol;
using NodePanel.Core.Runtime;

namespace NodePanel.Core.Tests;

public sealed class VmessProtocolRoundtripTests
{
    [Fact]
    public async Task HandshakeReader_reads_connect_header_written_by_writer()
    {
        var uuid = "11111111-1111-1111-1111-111111111111";
        var user = CreateUser(uuid);
        var request = CreateRequest(user, VmessCommand.Connect, "example.org", 443);
        var writer = new VmessHandshakeWriter();
        var reader = new VmessHandshakeReader();

        await using var stream = new MemoryStream(writer.BuildRequestHeader(request), writable: false);
        var decoded = await reader.ReadAsync(stream, [user], CancellationToken.None);

        Assert.Equal((byte)1, decoded.Version);
        Assert.Equal(uuid, decoded.User.Uuid);
        Assert.Equal(VmessCommand.Connect, decoded.Command);
        Assert.Equal("example.org", decoded.TargetHost);
        Assert.Equal(443, decoded.TargetPort);
        Assert.Equal(request.Security, decoded.Security);
        Assert.Equal(request.Option, decoded.Option);
    }

    [Fact]
    public async Task ReadResponseAsync_rejects_unexpected_response_header()
    {
        var uuid = "11111111-1111-1111-1111-111111111111";
        var user = CreateUser(uuid);
        var request = CreateRequest(user, VmessCommand.Connect, "example.org", 443);
        var mismatched = request with
        {
            ResponseHeader = (byte)(request.ResponseHeader + 1)
        };

        await using var stream = new MemoryStream();
        await VmessHandshakeReader.WriteResponseAsync(stream, mismatched, CancellationToken.None);
        stream.Position = 0;

        var exception = await Assert.ThrowsAsync<InvalidDataException>(() =>
            VmessHandshakeWriter.ReadResponseAsync(stream, request, CancellationToken.None).AsTask());

        Assert.Contains("response header mismatch", exception.Message, StringComparison.OrdinalIgnoreCase);
    }

    private static VmessUser CreateUser(string uuid)
        => new()
        {
            UserId = "vmess-user",
            Uuid = uuid,
            CmdKey = VmessAccountCodec.CreateCommandKey(uuid),
            BytesPerSecond = 0
        };

    private static VmessRequest CreateRequest(
        VmessUser user,
        VmessCommand command,
        string host,
        int port)
    {
        var requestBodyKey = Encoding.ASCII.GetBytes("0123456789ABCDEF");
        var requestBodyIv = Encoding.ASCII.GetBytes("FEDCBA9876543210");

        return new VmessRequest
        {
            Version = 1,
            User = user,
            RequestBodyKey = requestBodyKey,
            RequestBodyIv = requestBodyIv,
            ResponseHeader = 0x23,
            Option = VmessRequestOptions.ChunkStream |
                     VmessRequestOptions.ChunkMasking |
                     VmessRequestOptions.GlobalPadding |
                     VmessRequestOptions.AuthenticatedLength,
            Security = VmessSecurityType.Aes128Gcm,
            Command = command,
            TargetHost = host,
            TargetPort = port
        };
    }
}

using NodePanel.Core.Runtime;

namespace NodePanel.Core.Tests;

public sealed class BlackholeOutboundHandlerTests
{
    [Fact]
    public async Task OpenTcpAsync_returns_null_stream_that_discards_payloads()
    {
        var handler = new BlackholeOutboundHandler();

        await using var stream = await handler.OpenTcpAsync(
            new DispatchContext(),
            new DispatchDestination
            {
                Host = "example.com",
                Port = 443,
                Network = DispatchNetwork.Tcp
            },
            CancellationToken.None);

        await stream.WriteAsync("hello-blackhole"u8.ToArray(), CancellationToken.None);
        await stream.FlushAsync(CancellationToken.None);

        var buffer = new byte[1];
        var read = await stream.ReadAsync(buffer.AsMemory(0, 1), CancellationToken.None);
        Assert.Equal(0, read);
    }

    [Fact]
    public async Task OpenUdpAsync_discards_payloads_and_returns_no_response()
    {
        var handler = new BlackholeOutboundHandler();

        await using var transport = await handler.OpenUdpAsync(new DispatchContext(), CancellationToken.None);

        await transport.SendAsync(
            new DispatchDestination
            {
                Host = "example.com",
                Port = 53,
                Network = DispatchNetwork.Udp
            },
            "hello-blackhole-udp"u8.ToArray(),
            CancellationToken.None);

        var received = await transport.ReceiveAsync(CancellationToken.None);
        Assert.Null(received);
    }

    [Fact]
    public void RuntimeCapabilities_include_blackhole_protocol()
    {
        Assert.Contains(OutboundProtocols.Blackhole, RuntimeCapabilities.SupportedOutboundProtocols);
    }
}

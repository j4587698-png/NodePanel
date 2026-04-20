using System.Net;
using System.Net.Sockets;
using NodePanel.Core.Runtime;

namespace NodePanel.Core.Tests;

public sealed class FreedomOutboundHandlerTests
{
    [Fact]
    public async Task OpenTcpAsync_uses_system_dns_when_skip_dns_resolve_is_enabled()
    {
        using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(10));
        var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();

        try
        {
            var acceptTask = listener.AcceptTcpClientAsync(cts.Token);
            var handler = CreateHandler(new ThrowingDnsResolver());
            var destination = new DispatchDestination
            {
                Host = "localhost",
                Port = ((IPEndPoint)listener.LocalEndpoint).Port,
                Network = DispatchNetwork.Tcp
            };

            using var stream = await handler.OpenTcpAsync(CreateSkipDnsContext(), destination, cts.Token);
            using var server = await acceptTask;

            var payload = new byte[] { 0x01, 0x02, 0x03, 0x04 };
            await stream.WriteAsync(payload, cts.Token);

            var received = new byte[payload.Length];
            await ReadExactAsync(server.GetStream(), received, cts.Token);
            Assert.Equal(payload, received);
        }
        finally
        {
            listener.Stop();
        }
    }

    [Fact]
    public async Task OpenUdpAsync_uses_system_dns_when_skip_dns_resolve_is_enabled()
    {
        using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(10));
        using var server = new UdpClient(new IPEndPoint(IPAddress.Loopback, 0));
        var handler = CreateHandler(new ThrowingDnsResolver());
        var destination = new DispatchDestination
        {
            Host = "localhost",
            Port = ((IPEndPoint)server.Client.LocalEndPoint!).Port,
            Network = DispatchNetwork.Udp
        };
        var payload = new byte[] { 0x09, 0x08, 0x07, 0x06 };

        await using var transport = await handler.OpenUdpAsync(
            CreateSkipDnsContext() with
            {
                UseCone = false
            },
            cts.Token);

        await transport.SendAsync(destination, payload, cts.Token);

        var received = await server.ReceiveAsync(cts.Token);
        Assert.Equal(payload, received.Buffer);

        await server.SendAsync(received.Buffer, received.Buffer.Length, received.RemoteEndPoint);

        var echoed = await transport.ReceiveAsync(cts.Token);
        Assert.NotNull(echoed);
        Assert.Equal(payload, echoed!.Payload);
    }

    private static FreedomOutboundHandler CreateHandler(IDnsResolver dnsResolver)
        => new(
            new StaticSettingsProvider(
                new OutboundCommonSettings
                {
                    Tag = FreedomOutboundHandler.DefaultTag,
                    Protocol = OutboundProtocols.Freedom
                }),
            serviceProvider: null,
            dnsResolver);

    private static DispatchContext CreateSkipDnsContext()
        => new()
        {
            OutboundTag = FreedomOutboundHandler.DefaultTag,
            Content = new DispatchContent
            {
                SkipDnsResolve = true
            }
        };

    private static async Task ReadExactAsync(Stream stream, byte[] buffer, CancellationToken cancellationToken)
    {
        var offset = 0;
        while (offset < buffer.Length)
        {
            var read = await stream.ReadAsync(
                buffer.AsMemory(offset, buffer.Length - offset),
                cancellationToken);
            if (read == 0)
            {
                throw new EndOfStreamException("The stream ended before the expected number of bytes were read.");
            }

            offset += read;
        }
    }

    private sealed class StaticSettingsProvider : IOutboundCommonSettingsProvider
    {
        private readonly OutboundCommonSettings _settings;

        public StaticSettingsProvider(OutboundCommonSettings settings)
        {
            _settings = settings;
        }

        public bool TryResolve(DispatchContext context, out OutboundCommonSettings settings)
        {
            settings = _settings;
            return true;
        }
    }

    private sealed class ThrowingDnsResolver : IDnsResolver
    {
        public ValueTask<IReadOnlyList<IPAddress>> ResolveAsync(string host, CancellationToken cancellationToken = default)
            => throw new InvalidOperationException("The custom DNS resolver should not be used when SkipDnsResolve is enabled.");
    }
}

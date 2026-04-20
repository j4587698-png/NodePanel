using System.Text;
using NodePanel.Core.Runtime;

namespace NodePanel.Core.Tests;

public sealed class RuntimeSnifferTests
{
    [Fact]
    public async Task SniffTcpAsync_applies_http_sniffing_and_replays_initial_payload()
    {
        var sniffPayload = Encoding.ASCII.GetBytes("GET / HTTP/1.1\r\nHost: edge.example.com\r\n\r\n");
        var tailPayload = Encoding.ASCII.GetBytes("body");
        await using var stream = new MemoryStream(sniffPayload.Concat(tailPayload).ToArray(), writable: false);
        var destination = new DispatchDestination
        {
            Host = "198.51.100.10",
            Port = 80,
            Network = DispatchNetwork.Tcp
        };
        var context = DispatchContextTargeting.SetOriginalAndTarget(new DispatchContext(), destination);

        var result = await new DefaultRuntimeSniffer().SniffTcpAsync(
            new RuntimeSniffingOptions
            {
                Enabled = true,
                DestinationOverride = [RoutingProtocols.Http]
            },
            stream,
            context,
            destination,
            CancellationToken.None);

        Assert.Equal(RoutingProtocols.Http, result.Context.DetectedProtocol);
        Assert.Equal("edge.example.com", result.Context.DetectedDomain);
        Assert.True(result.Context.InitialPayload.AsSpan().StartsWith(sniffPayload));
        Assert.Equal("edge.example.com", result.Destination.Host);
        Assert.Equal(80, result.Destination.Port);

        await using var replay = new MemoryStream();
        await result.Stream.CopyToAsync(replay, CancellationToken.None);
        Assert.Equal(sniffPayload.Concat(tailPayload).ToArray(), replay.ToArray());
    }

    [Fact]
    public async Task SniffTcpAsync_keeps_original_target_when_destination_override_is_disabled()
    {
        var sniffPayload = Encoding.ASCII.GetBytes("GET / HTTP/1.1\r\nHost: edge.example.com\r\n\r\n");
        await using var stream = new MemoryStream(sniffPayload, writable: false);
        var destination = new DispatchDestination
        {
            Host = "198.51.100.10",
            Port = 80,
            Network = DispatchNetwork.Tcp
        };
        var context = DispatchContextTargeting.SetOriginalAndTarget(new DispatchContext(), destination);

        var result = await new DefaultRuntimeSniffer().SniffTcpAsync(
            new RuntimeSniffingOptions
            {
                Enabled = true,
                DestinationOverride = [RoutingProtocols.Http]
            },
            stream,
            context,
            destination,
            CancellationToken.None,
            allowDestinationOverride: false);

        Assert.Equal(RoutingProtocols.Http, result.Context.DetectedProtocol);
        Assert.Equal("edge.example.com", result.Context.DetectedDomain);
        Assert.Equal("198.51.100.10", result.Context.TargetHost);
        Assert.Equal(80, result.Context.TargetPort);
        Assert.Equal("198.51.100.10", result.Destination.Host);
        Assert.Equal(80, result.Destination.Port);
    }

    [Fact]
    public async Task SniffTcpAsync_uses_fake_dns_metadata_without_reading_stream_when_metadata_only()
    {
        var fakeDnsEngine = CreateFakeDnsEngine();
        var fakeAddress = Assert.Single(fakeDnsEngine.GetFakeIPForDomain("mapped.example.com", ipv4: true, ipv6: false));
        await using var stream = new ThrowingReadStream();
        var destination = new DispatchDestination
        {
            Host = fakeAddress.ToString(),
            Port = 443,
            Network = DispatchNetwork.Tcp
        };
        var context = DispatchContextTargeting.SetOriginalAndTarget(new DispatchContext(), destination);

        var result = await new DefaultRuntimeSniffer(fakeDnsEngine).SniffTcpAsync(
            new RuntimeSniffingOptions
            {
                Enabled = true,
                MetadataOnly = true,
                DestinationOverride = [RoutingProtocols.FakeDns]
            },
            stream,
            context,
            destination,
            CancellationToken.None);

        Assert.Same(stream, result.Stream);
        Assert.Equal(RoutingProtocols.FakeDns, result.Context.DetectedProtocol);
        Assert.Equal("mapped.example.com", result.Context.DetectedDomain);
        Assert.Empty(result.Context.InitialPayload);
        Assert.Equal("mapped.example.com", result.Destination.Host);
        Assert.Equal(443, result.Destination.Port);
    }

    [Fact]
    public async Task SniffTcpAsync_keeps_fake_dns_metadata_when_content_probe_times_out()
    {
        var fakeDnsEngine = CreateFakeDnsEngine();
        var fakeAddress = Assert.Single(fakeDnsEngine.GetFakeIPForDomain("mapped-timeout.example.com", ipv4: true, ipv6: false));
        var payload = Encoding.ASCII.GetBytes("garbage");
        await using var stream = new PayloadThenPendingStream(payload);
        var destination = new DispatchDestination
        {
            Host = fakeAddress.ToString(),
            Port = 443,
            Network = DispatchNetwork.Tcp
        };
        var context = DispatchContextTargeting.SetOriginalAndTarget(new DispatchContext(), destination);

        var result = await new DefaultRuntimeSniffer(fakeDnsEngine).SniffTcpAsync(
            new RuntimeSniffingOptions
            {
                Enabled = true,
                DestinationOverride = [RoutingProtocols.FakeDns]
            },
            stream,
            context,
            destination,
            CancellationToken.None);

        Assert.Equal(RoutingProtocols.FakeDns, result.Context.DetectedProtocol);
        Assert.Equal("mapped-timeout.example.com", result.Context.DetectedDomain);
        Assert.Equal(payload, result.Context.InitialPayload);
        Assert.Equal("mapped-timeout.example.com", result.Destination.Host);
        Assert.Equal(443, result.Destination.Port);

        var replay = new byte[payload.Length];
        await result.Stream.ReadExactlyAsync(replay.AsMemory(0, replay.Length), CancellationToken.None);
        Assert.Equal(payload, replay);
    }

    [Fact]
    public async Task SniffTcpAsync_prefers_exact_fake_dns_metadata_over_http_override_protocol()
    {
        var fakeDnsEngine = CreateFakeDnsEngine();
        var fakeAddress = Assert.Single(fakeDnsEngine.GetFakeIPForDomain("mapped-priority.example.com", ipv4: true, ipv6: false));
        var payload = Encoding.ASCII.GetBytes("GET / HTTP/1.1\r\nHost: payload.example.com\r\n\r\n");
        await using var stream = new MemoryStream(payload, writable: false);
        var destination = new DispatchDestination
        {
            Host = fakeAddress.ToString(),
            Port = 80,
            Network = DispatchNetwork.Tcp
        };
        var context = DispatchContextTargeting.SetOriginalAndTarget(new DispatchContext(), destination);

        var result = await new DefaultRuntimeSniffer(fakeDnsEngine).SniffTcpAsync(
            new RuntimeSniffingOptions
            {
                Enabled = true,
                DestinationOverride = [RoutingProtocols.Http]
            },
            stream,
            context,
            destination,
            CancellationToken.None);

        Assert.Equal(RoutingProtocols.FakeDns, result.Context.DetectedProtocol);
        Assert.Equal("mapped-priority.example.com", result.Context.DetectedDomain);
        Assert.Equal(RoutingProtocols.FakeDns, result.Context.Content.Protocol);
        Assert.Equal(fakeAddress.ToString(), result.Context.TargetHost);
        Assert.Equal(fakeAddress.ToString(), result.Destination.Host);
    }

    [Fact]
    public async Task SniffTcpAsync_preserves_existing_dispatch_content_when_no_protocol_is_detected()
    {
        var payload = Encoding.ASCII.GetBytes("not-a-known-protocol");
        await using var stream = new MemoryStream(payload, writable: false);
        var destination = new DispatchDestination
        {
            Host = "198.51.100.30",
            Port = 443,
            Network = DispatchNetwork.Tcp
        };
        var context = DispatchContextTargeting.SetOriginalAndTarget(
            new DispatchContext
            {
                Content = new DispatchContent
                {
                    Protocol = "preset",
                    Attributes = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
                    {
                        ["x-existing"] = "value"
                    },
                    SkipDnsResolve = true
                }
            },
            destination);

        var result = await new DefaultRuntimeSniffer().SniffTcpAsync(
            new RuntimeSniffingOptions
            {
                Enabled = true,
                DestinationOverride = [RoutingProtocols.Http]
            },
            stream,
            context,
            destination,
            CancellationToken.None);

        Assert.Equal(string.Empty, result.Context.DetectedProtocol);
        Assert.Equal(string.Empty, result.Context.DetectedDomain);
        Assert.Equal("preset", result.Context.Content.Protocol);
        Assert.True(result.Context.Content.SkipDnsResolve);
        Assert.True(result.Context.Content.Attributes.TryGetValue("x-existing", out var value));
        Assert.Equal("value", value);
        Assert.Equal(payload, result.Context.InitialPayload);
        Assert.Equal(destination.Host, result.Destination.Host);
    }

    [Fact]
    public async Task SniffTcpAsync_detects_fragmented_tls_when_probe_session_needs_more_data()
    {
        var tlsPayload = BuildTlsClientHello("tls.example.com");
        var firstSegment = tlsPayload.AsSpan(0, 9).ToArray();
        var secondSegment = tlsPayload.AsSpan(9).ToArray();
        await using var stream = new SegmentedPayloadThenPendingStream(firstSegment, secondSegment);
        var destination = new DispatchDestination
        {
            Host = "198.51.100.20",
            Port = 443,
            Network = DispatchNetwork.Tcp
        };
        var context = DispatchContextTargeting.SetOriginalAndTarget(new DispatchContext(), destination);

        var result = await new DefaultRuntimeSniffer().SniffTcpAsync(
            new RuntimeSniffingOptions
            {
                Enabled = true,
                DestinationOverride = [RoutingProtocols.Tls]
            },
            stream,
            context,
            destination,
            CancellationToken.None);

        Assert.Equal(RoutingProtocols.Tls, result.Context.DetectedProtocol);
        Assert.Equal("tls.example.com", result.Context.DetectedDomain);
        Assert.Equal("tls.example.com", result.Destination.Host);
        Assert.Equal(tlsPayload, result.Context.InitialPayload);
    }

    [Fact]
    public void SniffUdp_applies_fake_dns_metadata_and_updates_context()
    {
        var fakeDnsEngine = CreateFakeDnsEngine();
        var fakeAddress = Assert.Single(fakeDnsEngine.GetFakeIPForDomain("mapped.udp.example", ipv4: true, ipv6: false));
        var destination = new DispatchDestination
        {
            Host = fakeAddress.ToString(),
            Port = 53,
            Network = DispatchNetwork.Udp
        };
        var context = DispatchContextTargeting.SetOriginalAndTarget(new DispatchContext(), destination);

        var result = new DefaultRuntimeSniffer(fakeDnsEngine).SniffUdp(
            new RuntimeSniffingOptions
            {
                Enabled = true,
                MetadataOnly = true,
                DestinationOverride = [RoutingProtocols.FakeDns]
            },
            ReadOnlySpan<byte>.Empty,
            destination,
            context);

        Assert.Equal(RoutingProtocols.FakeDns, result.Decision.Protocol);
        Assert.Equal("mapped.udp.example", result.Decision.Domain);
        Assert.Equal("mapped.udp.example", result.Destination.Host);
        Assert.NotNull(result.Context);
        Assert.Equal(RoutingProtocols.FakeDns, result.Context!.DetectedProtocol);
        Assert.Equal("mapped.udp.example", result.Context.DetectedDomain);
        Assert.Equal("mapped.udp.example", result.Context.TargetHost);
        Assert.Equal(53, result.Context.TargetPort);
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

    private sealed class ThrowingReadStream : MemoryStream
    {
        public override int Read(byte[] buffer, int offset, int count)
            => throw new InvalidOperationException("Read should not be called.");

        public override Task<int> ReadAsync(byte[] buffer, int offset, int count, CancellationToken cancellationToken)
            => Task.FromException<int>(new InvalidOperationException("ReadAsync should not be called."));

        public override ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken cancellationToken = default)
            => ValueTask.FromException<int>(new InvalidOperationException("ReadAsync should not be called."));
    }
}

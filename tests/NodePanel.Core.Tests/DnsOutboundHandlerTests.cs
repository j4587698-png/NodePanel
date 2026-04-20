using System.Buffers.Binary;
using System.Collections.Concurrent;
using System.Net;
using System.Net.Sockets;
using System.Text;
using NodePanel.Core.Runtime;

namespace NodePanel.Core.Tests;

public sealed class DnsOutboundHandlerTests
{
    private const ushort TypeMx = 15;

    [Fact]
    public async Task OpenUdpAsync_resolves_a_query_locally()
    {
        using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(10));
        var resolver = new RecordingDnsResolver(
            IPAddress.Parse("1.1.1.1"),
            IPAddress.Parse("2001:db8::1"));
        var handler = CreateHandler(
            new RuntimeDnsOutboundOptions
            {
                Tag = "dns-udp-local"
            },
            resolver);

        await using var transport = await handler.OpenUdpAsync(
            new DispatchContext
            {
                OutboundTag = "dns-udp-local"
            },
            cts.Token);

        var query = BuildQuery("example.com", DnsOutboundProtocolCodec.TypeA);
        await transport.SendAsync(
            new DispatchDestination
            {
                Host = "8.8.8.8",
                Port = 53,
                Network = DispatchNetwork.Udp
            },
            query,
            cts.Token);

        var datagram = await transport.ReceiveAsync(cts.Token);
        Assert.NotNull(datagram);
        Assert.Equal("8.8.8.8", datagram!.SourceHost);
        Assert.Equal(53, datagram.SourcePort);
        Assert.True(DnsOutboundProtocolCodec.TryParseResponse(datagram.Payload, out var response));
        Assert.Equal(DnsResponseCodes.Success, response.ResponseCode);
        Assert.Equal("example.com", response.Domain);
        Assert.Equal(DnsOutboundProtocolCodec.TypeA, response.Type);

        var address = Assert.Single(response.Addresses);
        Assert.Equal(IPAddress.Parse("1.1.1.1"), address);
        Assert.Equal(["example.com"], resolver.Calls.ToArray());
    }

    [Fact]
    public async Task OpenTcpAsync_resolves_aaaa_query_locally()
    {
        using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(10));
        var resolver = new RecordingDnsResolver(
            IPAddress.Parse("1.1.1.1"),
            IPAddress.Parse("2001:db8::8"));
        var handler = CreateHandler(
            new RuntimeDnsOutboundOptions
            {
                Tag = "dns-tcp-local"
            },
            resolver);

        await using var stream = await handler.OpenTcpAsync(
            new DispatchContext
            {
                OutboundTag = "dns-tcp-local"
            },
            new DispatchDestination
            {
                Host = "1.1.1.1",
                Port = 53,
                Network = DispatchNetwork.Tcp
            },
            cts.Token);

        var query = BuildQuery("ipv6.example", DnsOutboundProtocolCodec.TypeAAAA, id: 0x2233);
        await stream.WriteAsync(
            DnsOutboundProtocolCodec.FrameTcpMessage(query).AsMemory(),
            cts.Token);
        await stream.FlushAsync(cts.Token);

        var responsePayload = await ReadFramedMessageAsync(stream, cts.Token);
        Assert.True(DnsOutboundProtocolCodec.TryParseResponse(responsePayload, out var response));
        Assert.Equal(DnsResponseCodes.Success, response.ResponseCode);
        Assert.Equal("ipv6.example", response.Domain);
        Assert.Equal(DnsOutboundProtocolCodec.TypeAAAA, response.Type);

        var address = Assert.Single(response.Addresses);
        Assert.Equal(IPAddress.Parse("2001:db8::8"), address);
        Assert.Equal(["ipv6.example"], resolver.Calls.ToArray());
    }

    [Fact]
    public async Task OpenUdpAsync_returns_fake_ip_for_local_a_query_when_fake_dns_is_configured()
    {
        using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(10));
        var settingsProvider = new FixedDnsRuntimeSettingsProvider(
            new DnsRuntimeSettings
            {
                FakeDnsPools =
                [
                    new FakeDnsPoolRuntime
                    {
                        IpPool = FakeDnsDefaults.IPv4Pool,
                        LruSize = 256
                    }
                ]
            });
        var fakeDnsEngine = new RuntimeFakeDnsEngine(settingsProvider);
        var handler = CreateHandler(
            new RuntimeDnsOutboundOptions
            {
                Tag = "dns-fake-local"
            },
            new RuntimeDnsResolver(
                settingsProvider,
                fakeDnsEngine: fakeDnsEngine));

        await using var transport = await handler.OpenUdpAsync(
            new DispatchContext
            {
                OutboundTag = "dns-fake-local"
            },
            cts.Token);

        await transport.SendAsync(
            new DispatchDestination
            {
                Host = "8.8.8.8",
                Port = 53,
                Network = DispatchNetwork.Udp
            },
            BuildQuery("fake.example", DnsOutboundProtocolCodec.TypeA),
            cts.Token);

        var datagram = await transport.ReceiveAsync(cts.Token);
        Assert.NotNull(datagram);
        Assert.True(DnsOutboundProtocolCodec.TryParseResponse(datagram!.Payload, out var response));
        var address = Assert.Single(response.Addresses);
        Assert.Equal(AddressFamily.InterNetwork, address.AddressFamily);
        Assert.True(fakeDnsEngine.IsIPInPool(address));
        Assert.Equal("fake.example", fakeDnsEngine.GetDomainFromFakeDns(address));
        Assert.Equal([FakeDnsDefaults.DefaultTtlSeconds], response.AnswerTtls.ToArray());
    }

    [Fact]
    public async Task OpenUdpAsync_uses_lookup_ttl_for_local_ip_response()
    {
        using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(10));
        var handler = CreateHandler(
            new RuntimeDnsOutboundOptions
            {
                Tag = "dns-ttl"
            },
            new StubLookupDnsResolver(static (_, _) => new DnsLookupResult
            {
                Addresses =
                [
                    IPAddress.Parse("203.0.113.7")
                ],
                TtlSeconds = 321
            }));

        await using var transport = await handler.OpenUdpAsync(
            new DispatchContext
            {
                OutboundTag = "dns-ttl"
            },
            cts.Token);

        await transport.SendAsync(
            new DispatchDestination
            {
                Host = "8.8.8.8",
                Port = 53,
                Network = DispatchNetwork.Udp
            },
            BuildQuery("ttl.example", DnsOutboundProtocolCodec.TypeA),
            cts.Token);

        var datagram = await transport.ReceiveAsync(cts.Token);
        Assert.NotNull(datagram);
        Assert.True(DnsOutboundProtocolCodec.TryParseResponse(datagram!.Payload, out var response));
        Assert.Equal([321u], response.AnswerTtls.ToArray());
    }

    [Fact]
    public async Task OpenUdpAsync_returns_empty_success_response_when_lookup_result_is_empty()
    {
        using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(10));
        var handler = CreateHandler(
            new RuntimeDnsOutboundOptions
            {
                Tag = "dns-empty"
            },
            new StubLookupDnsResolver(static (_, _) => new DnsLookupResult
            {
                IsEmptyResponse = true,
                TtlSeconds = 123
            }));

        await using var transport = await handler.OpenUdpAsync(
            new DispatchContext
            {
                OutboundTag = "dns-empty"
            },
            cts.Token);

        await transport.SendAsync(
            new DispatchDestination
            {
                Host = "8.8.4.4",
                Port = 53,
                Network = DispatchNetwork.Udp
            },
            BuildQuery("empty.example", DnsOutboundProtocolCodec.TypeA),
            cts.Token);

        var datagram = await transport.ReceiveAsync(cts.Token);
        Assert.NotNull(datagram);
        Assert.True(DnsOutboundProtocolCodec.TryParseResponse(datagram!.Payload, out var response));
        Assert.Equal(DnsResponseCodes.Success, response.ResponseCode);
        Assert.Equal("empty.example", response.Domain);
        Assert.Empty(response.Addresses);
        Assert.Empty(response.AnswerTtls);
    }

    [Fact]
    public async Task OpenUdpAsync_propagates_lookup_response_code_for_ip_queries()
    {
        using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(10));
        var handler = CreateHandler(
            new RuntimeDnsOutboundOptions
            {
                Tag = "dns-name-error"
            },
            new StubLookupDnsResolver(static (_, _) => new DnsLookupResult
            {
                ResponseCode = DnsResponseCodes.NameError
            }));

        await using var transport = await handler.OpenUdpAsync(
            new DispatchContext
            {
                OutboundTag = "dns-name-error"
            },
            cts.Token);

        await transport.SendAsync(
            new DispatchDestination
            {
                Host = "1.1.1.1",
                Port = 53,
                Network = DispatchNetwork.Udp
            },
            BuildQuery("missing.example", DnsOutboundProtocolCodec.TypeA),
            cts.Token);

        var datagram = await transport.ReceiveAsync(cts.Token);
        Assert.NotNull(datagram);
        Assert.True(DnsOutboundProtocolCodec.TryParseResponse(datagram!.Payload, out var response));
        Assert.Equal(DnsResponseCodes.NameError, response.ResponseCode);
        Assert.Equal("missing.example", response.Domain);
        Assert.Empty(response.Addresses);
    }

    [Fact]
    public async Task OpenUdpAsync_drops_ip_query_when_lookup_throws_unmapped_exception()
    {
        using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(10));
        var handler = CreateHandler(
            new RuntimeDnsOutboundOptions
            {
                Tag = "dns-drop-error"
            },
            new ThrowingLookupDnsResolver(new InvalidOperationException("boom")));

        await using var transport = await handler.OpenUdpAsync(
            new DispatchContext
            {
                OutboundTag = "dns-drop-error"
            },
            cts.Token);

        await transport.SendAsync(
            new DispatchDestination
            {
                Host = "8.8.8.8",
                Port = 53,
                Network = DispatchNetwork.Udp
            },
            BuildQuery("error.example", DnsOutboundProtocolCodec.TypeA),
            cts.Token);

        using var receiveCts = new CancellationTokenSource(TimeSpan.FromMilliseconds(300));
        await Assert.ThrowsAsync<OperationCanceledException>(() => transport.ReceiveAsync(receiveCts.Token).AsTask());
    }

    [Fact]
    public async Task OpenUdpAsync_rejects_non_ip_query_when_configured()
    {
        using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(10));
        var handler = CreateHandler(
            new RuntimeDnsOutboundOptions
            {
                Tag = "dns-reject",
                NonIpQuery = DnsOutboundNonIpQueryModes.Reject
            });

        await using var transport = await handler.OpenUdpAsync(
            new DispatchContext
            {
                OutboundTag = "dns-reject"
            },
            cts.Token);

        var query = BuildQuery("mail.example", TypeMx, id: 0x3344);
        await transport.SendAsync(
            new DispatchDestination
            {
                Host = "9.9.9.9",
                Port = 53,
                Network = DispatchNetwork.Udp
            },
            query,
            cts.Token);

        var datagram = await transport.ReceiveAsync(cts.Token);
        Assert.NotNull(datagram);
        Assert.True(DnsOutboundProtocolCodec.TryParseResponse(datagram!.Payload, out var response));
        Assert.Equal(DnsResponseCodes.Refused, response.ResponseCode);
        Assert.Equal("mail.example", response.Domain);
        Assert.Equal(TypeMx, response.Type);
        Assert.Empty(response.Addresses);
    }

    [Fact]
    public async Task OpenUdpAsync_drops_non_ip_query_when_configured()
    {
        using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(10));
        var handler = CreateHandler(
            new RuntimeDnsOutboundOptions
            {
                Tag = "dns-drop",
                NonIpQuery = DnsOutboundNonIpQueryModes.Drop
            });

        await using var transport = await handler.OpenUdpAsync(
            new DispatchContext
            {
                OutboundTag = "dns-drop"
            },
            cts.Token);

        await transport.SendAsync(
            new DispatchDestination
            {
                Host = "9.9.9.9",
                Port = 53,
                Network = DispatchNetwork.Udp
            },
            BuildQuery("mail.example", TypeMx),
            cts.Token);

        using var receiveCts = new CancellationTokenSource(TimeSpan.FromMilliseconds(300));
        await Assert.ThrowsAsync<OperationCanceledException>(() => transport.ReceiveAsync(receiveCts.Token).AsTask());
    }

    [Fact]
    public async Task OpenUdpAsync_can_forward_non_ip_query_to_tcp_server_when_server_network_is_overridden()
    {
        using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(10));
        using var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();
        var serverPort = ((IPEndPoint)listener.LocalEndpoint).Port;

        var serverTask = RunTcpDnsServerAsync(
            listener,
            cts.Token,
            static payload =>
            {
                Assert.True(DnsOutboundProtocolCodec.TryParseQuery(payload, out var query));
                Assert.Equal(TypeMx, query.Type);
                return DnsOutboundProtocolCodec.BuildRefusedResponse(query);
            });

        var handler = CreateHandler(
            new RuntimeDnsOutboundOptions
            {
                Tag = "dns-udp-to-tcp",
                NonIpQuery = DnsOutboundNonIpQueryModes.Forward,
                ServerHost = IPAddress.Loopback.ToString(),
                ServerPort = serverPort,
                ServerNetwork = RoutingNetworks.Tcp
            });

        await using var transport = await handler.OpenUdpAsync(
            new DispatchContext
            {
                OutboundTag = "dns-udp-to-tcp"
            },
            cts.Token);

        var query = BuildQuery("mail.example", TypeMx, id: 0x4455);
        await transport.SendAsync(
            new DispatchDestination
            {
                Host = "ignored.example",
                Port = 5353,
                Network = DispatchNetwork.Udp
            },
            query,
            cts.Token);

        var datagram = await transport.ReceiveAsync(cts.Token);
        var forwardedQuery = await serverTask;

        Assert.NotNull(datagram);
        Assert.Equal(query, forwardedQuery);
        Assert.Equal(IPAddress.Loopback.ToString(), datagram!.SourceHost);
        Assert.Equal(serverPort, datagram.SourcePort);
        Assert.True(DnsOutboundProtocolCodec.TryParseResponse(datagram.Payload, out var response));
        Assert.Equal(DnsResponseCodes.Refused, response.ResponseCode);
        Assert.Equal("mail.example", response.Domain);
        Assert.Equal(TypeMx, response.Type);
    }

    [Fact]
    public async Task OpenTcpAsync_can_forward_non_ip_query_to_udp_server_when_server_network_is_overridden()
    {
        using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(10));
        using var server = new Socket(AddressFamily.InterNetwork, SocketType.Dgram, ProtocolType.Udp);
        server.Bind(new IPEndPoint(IPAddress.Loopback, 0));
        var serverPort = ((IPEndPoint)server.LocalEndPoint!).Port;

        var serverTask = RunUdpDnsServerAsync(
            server,
            cts.Token,
            static payload =>
            {
                Assert.True(DnsOutboundProtocolCodec.TryParseQuery(payload, out var query));
                Assert.Equal(TypeMx, query.Type);
                return DnsOutboundProtocolCodec.BuildRefusedResponse(query);
            });

        var handler = CreateHandler(
            new RuntimeDnsOutboundOptions
            {
                Tag = "dns-tcp-to-udp",
                NonIpQuery = DnsOutboundNonIpQueryModes.Forward,
                ServerHost = IPAddress.Loopback.ToString(),
                ServerPort = serverPort,
                ServerNetwork = RoutingNetworks.Udp
            });

        await using var stream = await handler.OpenTcpAsync(
            new DispatchContext
            {
                OutboundTag = "dns-tcp-to-udp"
            },
            new DispatchDestination
            {
                Host = "ignored.example",
                Port = 5300,
                Network = DispatchNetwork.Tcp
            },
            cts.Token);

        var query = BuildQuery("mail.example", TypeMx, id: 0x5566);
        await stream.WriteAsync(
            DnsOutboundProtocolCodec.FrameTcpMessage(query).AsMemory(),
            cts.Token);
        await stream.FlushAsync(cts.Token);

        var responsePayload = await ReadFramedMessageAsync(stream, cts.Token);
        var forwardedQuery = await serverTask;

        Assert.Equal(query, forwardedQuery);
        Assert.True(DnsOutboundProtocolCodec.TryParseResponse(responsePayload, out var response));
        Assert.Equal(DnsResponseCodes.Refused, response.ResponseCode);
        Assert.Equal("mail.example", response.Domain);
        Assert.Equal(TypeMx, response.Type);
    }

    [Fact]
    public async Task OpenTcpAsync_reuses_tcp_forward_connection_for_multiple_queries()
    {
        using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(10));
        using var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();
        var serverPort = ((IPEndPoint)listener.LocalEndpoint).Port;

        var serverTask = RunPersistentTcpDnsServerAsync(
            listener,
            expectedQueries: 2,
            cts.Token,
            static payload =>
            {
                Assert.True(DnsOutboundProtocolCodec.TryParseQuery(payload, out var query));
                return DnsOutboundProtocolCodec.BuildRefusedResponse(query);
            });

        var handler = CreateHandler(
            new RuntimeDnsOutboundOptions
            {
                Tag = "dns-tcp-reuse",
                NonIpQuery = DnsOutboundNonIpQueryModes.Forward,
                ServerHost = IPAddress.Loopback.ToString(),
                ServerPort = serverPort,
                ServerNetwork = RoutingNetworks.Tcp
            });

        await using var stream = await handler.OpenTcpAsync(
            new DispatchContext
            {
                OutboundTag = "dns-tcp-reuse"
            },
            new DispatchDestination
            {
                Host = "ignored.example",
                Port = 53,
                Network = DispatchNetwork.Tcp
            },
            cts.Token);

        var query1 = BuildQuery("mail-1.example", TypeMx, id: 0x6677);
        var query2 = BuildQuery("mail-2.example", TypeMx, id: 0x6678);

        await stream.WriteAsync(
            DnsOutboundProtocolCodec.FrameTcpMessage(query1).AsMemory(),
            cts.Token);
        await stream.FlushAsync(cts.Token);
        var response1 = await ReadFramedMessageAsync(stream, cts.Token);

        await stream.WriteAsync(
            DnsOutboundProtocolCodec.FrameTcpMessage(query2).AsMemory(),
            cts.Token);
        await stream.FlushAsync(cts.Token);
        var response2 = await ReadFramedMessageAsync(stream, cts.Token);

        var receivedQueries = await serverTask;

        Assert.Equal(2, receivedQueries.Count);
        Assert.Equal(query1, receivedQueries[0]);
        Assert.Equal(query2, receivedQueries[1]);

        Assert.True(DnsOutboundProtocolCodec.TryParseResponse(response1, out var parsed1));
        Assert.True(DnsOutboundProtocolCodec.TryParseResponse(response2, out var parsed2));
        Assert.Equal("mail-1.example", parsed1.Domain);
        Assert.Equal("mail-2.example", parsed2.Domain);
        Assert.Equal(DnsResponseCodes.Refused, parsed1.ResponseCode);
        Assert.Equal(DnsResponseCodes.Refused, parsed2.ResponseCode);
    }

    [Fact]
    public async Task OpenUdpAsync_does_not_forward_blocked_query_types_even_when_non_ip_query_is_forward()
    {
        using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(10));
        using var server = new Socket(AddressFamily.InterNetwork, SocketType.Dgram, ProtocolType.Udp);
        server.Bind(new IPEndPoint(IPAddress.Loopback, 0));
        var serverPort = ((IPEndPoint)server.LocalEndPoint!).Port;
        var placeholder = new IPEndPoint(IPAddress.Any, 0);
        var probeBuffer = new byte[512];

        using var serverReceiveCts = new CancellationTokenSource(TimeSpan.FromMilliseconds(300));
        var serverReceiveTask = server.ReceiveFromAsync(
            probeBuffer.AsMemory(0, probeBuffer.Length),
            SocketFlags.None,
            placeholder,
            serverReceiveCts.Token).AsTask();

        var resolver = new RecordingDnsResolver(IPAddress.Parse("1.1.1.1"));
        var handler = CreateHandler(
            new RuntimeDnsOutboundOptions
            {
                Tag = "dns-block-type",
                NonIpQuery = DnsOutboundNonIpQueryModes.Forward,
                ServerHost = IPAddress.Loopback.ToString(),
                ServerPort = serverPort,
                ServerNetwork = RoutingNetworks.Udp,
                BlockTypes = [(int)DnsOutboundProtocolCodec.TypeA]
            },
            resolver);

        await using var transport = await handler.OpenUdpAsync(
            new DispatchContext
            {
                OutboundTag = "dns-block-type"
            },
            cts.Token);

        await transport.SendAsync(
            new DispatchDestination
            {
                Host = "8.8.8.8",
                Port = 53,
                Network = DispatchNetwork.Udp
            },
            BuildQuery("blocked.example", DnsOutboundProtocolCodec.TypeA),
            cts.Token);

        using var receiveCts = new CancellationTokenSource(TimeSpan.FromMilliseconds(300));
        await Assert.ThrowsAsync<OperationCanceledException>(() => transport.ReceiveAsync(receiveCts.Token).AsTask());
        await Assert.ThrowsAsync<OperationCanceledException>(async () => await serverReceiveTask);
        Assert.Empty(resolver.Calls);
    }

    [Fact]
    public void RuntimeOutboundSettingsCatalog_normalizes_dns_settings()
    {
        var catalog = RuntimeOutboundSettingsCatalog.Create(
        [
            new RuntimeDnsOutboundOptions
            {
                Tag = " dns-tag ",
                ServerNetwork = "UDP",
                ServerHost = " 127.0.0.1 ",
                ServerPort = 70000,
                NonIpQuery = "DROP",
                BlockTypes =
                [
                    0,
                    DnsOutboundProtocolCodec.TypeA,
                    DnsOutboundProtocolCodec.TypeA,
                    TypeMx
                ]
            }
        ]);

        Assert.True(catalog.TryGetDns("dns-tag", out var settings));
        Assert.Equal("dns-tag", settings.Tag);
        Assert.Equal(RoutingNetworks.Udp, settings.ServerNetwork);
        Assert.Equal("127.0.0.1", settings.ServerHost);
        Assert.Equal(0, settings.ServerPort);
        Assert.Equal(DnsOutboundNonIpQueryModes.Drop, settings.NonIpQuery);
        Assert.Equal(
            new[] { (int)DnsOutboundProtocolCodec.TypeA, TypeMx },
            settings.BlockTypes.ToArray());
    }

    [Fact]
    public void RuntimeCapabilities_include_dns_protocol()
    {
        Assert.Contains(OutboundProtocols.Dns, RuntimeCapabilities.SupportedOutboundProtocols);
    }

    private static DnsOutboundHandler CreateHandler(
        RuntimeDnsOutboundOptions settings,
        IDnsResolver? dnsResolver = null,
        IServiceProvider? serviceProvider = null)
        => new(
            new StaticCommonSettingsProvider(
                new OutboundCommonSettings
                {
                    Tag = settings.Tag,
                    Protocol = OutboundProtocols.Dns
                }),
            new StaticRuntimeSettingsProvider(settings),
            serviceProvider,
            dnsResolver);

    private static byte[] BuildQuery(string domain, ushort type, ushort id = 0x1234)
    {
        using var buffer = new MemoryStream(256);

        Span<byte> header = stackalloc byte[12];
        BinaryPrimitives.WriteUInt16BigEndian(header.Slice(0, 2), id);
        BinaryPrimitives.WriteUInt16BigEndian(header.Slice(2, 2), 0x0100);
        BinaryPrimitives.WriteUInt16BigEndian(header.Slice(4, 2), 1);
        BinaryPrimitives.WriteUInt16BigEndian(header.Slice(6, 2), 0);
        BinaryPrimitives.WriteUInt16BigEndian(header.Slice(8, 2), 0);
        BinaryPrimitives.WriteUInt16BigEndian(header.Slice(10, 2), 0);
        buffer.Write(header);

        foreach (var label in domain.Split('.', StringSplitOptions.RemoveEmptyEntries))
        {
            var labelBytes = Encoding.ASCII.GetBytes(label);
            buffer.WriteByte((byte)labelBytes.Length);
            buffer.Write(labelBytes);
        }

        buffer.WriteByte(0);

        Span<byte> question = stackalloc byte[4];
        BinaryPrimitives.WriteUInt16BigEndian(question.Slice(0, 2), type);
        BinaryPrimitives.WriteUInt16BigEndian(question.Slice(2, 2), DnsOutboundProtocolCodec.ClassInternet);
        buffer.Write(question);
        return buffer.ToArray();
    }

    private static async Task<byte[]> ReadFramedMessageAsync(Stream stream, CancellationToken cancellationToken)
    {
        var lengthBytes = new byte[2];
        await ReadExactAsync(stream, lengthBytes, cancellationToken);
        var length = BinaryPrimitives.ReadUInt16BigEndian(lengthBytes);
        var payload = new byte[length];
        await ReadExactAsync(stream, payload, cancellationToken);
        return payload;
    }

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

    private static async Task<byte[]> RunTcpDnsServerAsync(
        TcpListener listener,
        CancellationToken cancellationToken,
        Func<byte[], byte[]> responder)
    {
        using var client = await listener.AcceptTcpClientAsync(cancellationToken);
        await using var stream = client.GetStream();

        var payload = await ReadFramedMessageAsync(stream, cancellationToken);
        var response = responder(payload);
        if (response.Length > 0)
        {
            await stream.WriteAsync(
                DnsOutboundProtocolCodec.FrameTcpMessage(response).AsMemory(),
                cancellationToken);
            await stream.FlushAsync(cancellationToken);
        }

        return payload;
    }

    private static async Task<IReadOnlyList<byte[]>> RunPersistentTcpDnsServerAsync(
        TcpListener listener,
        int expectedQueries,
        CancellationToken cancellationToken,
        Func<byte[], byte[]> responder)
    {
        using var client = await listener.AcceptTcpClientAsync(cancellationToken);
        await using var stream = client.GetStream();

        var payloads = new List<byte[]>(expectedQueries);
        for (var index = 0; index < expectedQueries; index++)
        {
            var payload = await ReadFramedMessageAsync(stream, cancellationToken);
            payloads.Add(payload);

            var response = responder(payload);
            if (response.Length == 0)
            {
                continue;
            }

            await stream.WriteAsync(
                DnsOutboundProtocolCodec.FrameTcpMessage(response).AsMemory(),
                cancellationToken);
            await stream.FlushAsync(cancellationToken);
        }

        return payloads;
    }

    private static async Task<byte[]> RunUdpDnsServerAsync(
        Socket server,
        CancellationToken cancellationToken,
        Func<byte[], byte[]> responder)
    {
        var buffer = new byte[2048];
        var placeholder = new IPEndPoint(IPAddress.Any, 0);
        var received = await server.ReceiveFromAsync(
            buffer.AsMemory(0, buffer.Length),
            SocketFlags.None,
            placeholder,
            cancellationToken);
        var payload = buffer.AsSpan(0, received.ReceivedBytes).ToArray();
        var response = responder(payload);
        if (response.Length > 0)
        {
            await server.SendToAsync(
                response.AsMemory(0, response.Length),
                SocketFlags.None,
                received.RemoteEndPoint,
                cancellationToken);
        }

        return payload;
    }

    private sealed class StaticCommonSettingsProvider : IOutboundCommonSettingsProvider
    {
        private readonly OutboundCommonSettings _settings;

        public StaticCommonSettingsProvider(OutboundCommonSettings settings)
        {
            _settings = settings;
        }

        public bool TryResolve(DispatchContext context, out OutboundCommonSettings settings)
        {
            settings = _settings;
            return true;
        }
    }

    private sealed class StaticRuntimeSettingsProvider : IRuntimeOutboundSettingsProvider
    {
        private readonly IRuntimeOutboundOptions _settings;

        public StaticRuntimeSettingsProvider(IRuntimeOutboundOptions settings)
        {
            _settings = settings;
        }

        public bool TryResolve(DispatchContext context, out IRuntimeOutboundOptions settings)
        {
            settings = _settings;
            return true;
        }

        public bool TryResolve<TOptions>(DispatchContext context, out TOptions settings)
            where TOptions : class, IRuntimeOutboundOptions
        {
            if (_settings is TOptions typed)
            {
                settings = typed;
                return true;
            }

            settings = default!;
            return false;
        }
    }

    private sealed class FixedDnsRuntimeSettingsProvider : IDnsRuntimeSettingsProvider
    {
        private readonly DnsRuntimeSettings _settings;

        public FixedDnsRuntimeSettingsProvider(DnsRuntimeSettings settings)
        {
            _settings = settings;
        }

        public DnsRuntimeSettings GetCurrentDnsSettings() => _settings;
    }

    private sealed class RecordingDnsResolver : IDnsLookupResolver
    {
        private readonly IReadOnlyList<IPAddress> _addresses;

        public RecordingDnsResolver(params IPAddress[] addresses)
        {
            _addresses = addresses.ToArray();
        }

        public ConcurrentQueue<string> Calls { get; } = new();

        public ValueTask<IReadOnlyList<IPAddress>> ResolveAsync(string host, CancellationToken cancellationToken = default)
        {
            Calls.Enqueue(host);
            return ValueTask.FromResult<IReadOnlyList<IPAddress>>(_addresses);
        }

        public ValueTask<DnsLookupResult> LookupAsync(
            string host,
            DnsLookupOptions options,
            CancellationToken cancellationToken)
        {
            Calls.Enqueue(host);
            var filtered = DnsResolverExtensions.FilterAddresses(_addresses, options);
            return ValueTask.FromResult(new DnsLookupResult
            {
                Addresses = filtered,
                TtlSeconds = DnsResolutionDefaults.DefaultTtl,
                IsEmptyResponse = filtered.Count == 0
            });
        }
    }

    private sealed class StubLookupDnsResolver : IDnsLookupResolver
    {
        private readonly Func<string, DnsLookupOptions, DnsLookupResult> _factory;

        public StubLookupDnsResolver(Func<string, DnsLookupOptions, DnsLookupResult> factory)
        {
            _factory = factory;
        }

        public ValueTask<IReadOnlyList<IPAddress>> ResolveAsync(string host, CancellationToken cancellationToken = default)
            => ValueTask.FromResult<IReadOnlyList<IPAddress>>(
                _factory(host, DnsLookupOptions.Default).Addresses);

        public ValueTask<DnsLookupResult> LookupAsync(
            string host,
            DnsLookupOptions options,
            CancellationToken cancellationToken)
            => ValueTask.FromResult(_factory(host, options));
    }

    private sealed class ThrowingLookupDnsResolver : IDnsLookupResolver
    {
        private readonly Exception _exception;

        public ThrowingLookupDnsResolver(Exception exception)
        {
            _exception = exception;
        }

        public ValueTask<IReadOnlyList<IPAddress>> ResolveAsync(string host, CancellationToken cancellationToken = default)
            => ValueTask.FromException<IReadOnlyList<IPAddress>>(_exception);

        public ValueTask<DnsLookupResult> LookupAsync(
            string host,
            DnsLookupOptions options,
            CancellationToken cancellationToken)
            => ValueTask.FromException<DnsLookupResult>(_exception);
    }
}

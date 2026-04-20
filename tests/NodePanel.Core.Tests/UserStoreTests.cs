using NodePanel.Core.Cryptography;
using NodePanel.Core.Protocol;
using NodePanel.Core.Runtime;
using System.Text;

namespace NodePanel.Core.Tests;

public sealed class UserStoreTests
{
    [Fact]
    public void UserStore_scopes_runtime_users_by_protocol_and_inbound_tag()
    {
        var store = CreateSeededStore();

        store.AddUser(
            InboundProtocols.Trojan,
            "trojan-in",
            new TestTrojanUserDefinition
            {
                UserId = "trojan-user",
                Password = "demo-password",
                BytesPerSecond = 128,
                DeviceLimit = 2
            });
        store.AddUser(
            InboundProtocols.Vless,
            "vless-in",
            new TestVlessUserDefinition
            {
                UserId = "vless-user",
                Uuid = "11111111-1111-1111-1111-111111111111",
                Flow = " XTLS-RPRX-VISION-UDP443 ",
                TestSeed = [1u, 2u, 3u, 4u, 5u],
                BytesPerSecond = 256,
                DeviceLimit = 3
            });
        store.AddUser(
            InboundProtocols.Vmess,
            "vmess-in",
            new TestVmessUserDefinition
            {
                UserId = "vmess-user",
                Uuid = "22222222-2222-2222-2222-222222222222",
                BytesPerSecond = 512,
                DeviceLimit = 4
            });

        Assert.Equal(3, store.KnownUsers);
        Assert.Equal(1, store.GetUsersCount(InboundProtocols.Trojan, "trojan-in"));
        Assert.Equal(1, store.GetUsersCount(InboundProtocols.Vless, "vless-in"));
        Assert.Equal(1, store.GetUsersCount(InboundProtocols.Vmess, "vmess-in"));

        Assert.True(store.TryGetUser(InboundProtocols.Trojan, "trojan-in", "trojan-user", out var trojanRawUser));
        var trojanUser = Assert.IsType<TrojanUser>(trojanRawUser);
        Assert.Equal(TrojanPassword.ComputeHash("demo-password"), trojanUser.PasswordHash);
        Assert.Equal(128, trojanUser.BytesPerSecond);
        Assert.Equal(2, trojanUser.DeviceLimit);

        Assert.True(store.TryGetUser(InboundProtocols.Vless, "vless-in", "vless-user", out var vlessRawUser));
        var vlessUser = Assert.IsType<VlessUser>(vlessRawUser);
        Assert.Equal("11111111-1111-1111-1111-111111111111", vlessUser.Uuid);
        Assert.Equal(VlessFlowTypes.Vision, vlessUser.Flow);
        Assert.Equal([1u, 2u, 3u, 4u], vlessUser.TestSeed);

        Assert.True(store.TryGetUser(InboundProtocols.Vmess, "vmess-in", "vmess-user", out var vmessRawUser));
        var vmessUser = Assert.IsType<VmessUser>(vmessRawUser);
        Assert.Equal("22222222-2222-2222-2222-222222222222", vmessUser.Uuid);
        Assert.Equal(VmessAccountCodec.CreateCommandKey(vmessUser.Uuid), vmessUser.CmdKey);

        Assert.True(store.RemoveUser(InboundProtocols.Vless, "vless-in", "vless-user"));
        Assert.Equal(2, store.KnownUsers);
        Assert.Equal(0, store.GetUsersCount(InboundProtocols.Vless, "vless-in"));
        Assert.False(store.TryGetUser(InboundProtocols.Vless, "vless-in", "vless-user", out _));
        Assert.False(store.RemoveUser(InboundProtocols.Vless, "vless-in", "vless-user"));
    }

    [Fact]
    public void UserStore_global_snapshot_preserves_scoped_users_with_the_same_user_id()
    {
        var store = CreateSeededStore();

        store.AddUser(
            InboundProtocols.Trojan,
            "trojan-in",
            new TestTrojanUserDefinition
            {
                UserId = "shared-user",
                Password = "trojan-password",
                BytesPerSecond = 128,
                DeviceLimit = 1
            });
        store.AddUser(
            InboundProtocols.Vless,
            "vless-in",
            new TestVlessUserDefinition
            {
                UserId = "shared-user",
                Uuid = "66666666-6666-6666-6666-666666666666",
                BytesPerSecond = 256,
                DeviceLimit = 2
            });

        var users = store.GetUsers();

        Assert.Equal(2, store.KnownUsers);
        Assert.Equal(2, users.Count);
        Assert.Contains(users, static user => user is TrojanUser { UserId: "shared-user" });
        Assert.Contains(users, static user => user is VlessUser { UserId: "shared-user" });
    }

    [Fact]
    public void Trojan_and_vless_session_options_follow_live_runtime_states()
    {
        var store = CreateSeededStore(out var trojanRuntimeState, out var vlessRuntimeState, out _);
        var trojanOptions = new TrojanInboundSessionOptions
        {
            InboundTag = "trojan-in",
            RuntimeState = trojanRuntimeState
        };

        var passwordHash = TrojanPassword.ComputeHash("live-password");
        Assert.False(trojanOptions.TryAuthenticate(passwordHash, out _));

        store.AddUser(
            InboundProtocols.Trojan,
            "trojan-in",
            new TestTrojanUserDefinition
            {
                UserId = "trojan-live",
                Password = "live-password",
                BytesPerSecond = 64,
                DeviceLimit = 1
            });

        Assert.True(trojanOptions.TryAuthenticate(passwordHash, out var trojanUser));
        Assert.Equal("trojan-live", trojanUser!.UserId);

        Assert.True(store.RemoveUser(InboundProtocols.Trojan, "trojan-in", "trojan-live"));
        Assert.False(trojanOptions.TryAuthenticate(passwordHash, out _));

        var vlessOptions = new VlessInboundSessionOptions
        {
            InboundTag = "vless-in",
            RuntimeState = vlessRuntimeState
        };

        const string uuid = "33333333-3333-3333-3333-333333333333";
        Assert.False(vlessOptions.TryResolveUser(uuid, out _));

        store.AddUser(
            InboundProtocols.Vless,
            "vless-in",
            new TestVlessUserDefinition
            {
                UserId = "vless-live",
                Uuid = uuid,
                BytesPerSecond = 96,
                DeviceLimit = 2
            });

        Assert.True(vlessOptions.TryResolveUser(uuid, out var vlessUser));
        Assert.Equal("vless-live", vlessUser!.UserId);

        Assert.True(store.RemoveUser(InboundProtocols.Vless, "vless-in", "vless-live"));
        Assert.False(vlessOptions.TryResolveUser(uuid, out _));
    }

    [Fact]
    public async Task Vmess_handshake_reader_uses_live_user_registry_snapshot()
    {
        using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(10));

        var store = CreateSeededStore(out _, out _, out var vmessRuntimeState);
        var options = new VmessInboundSessionOptions
        {
            InboundTag = "vmess-in",
            RuntimeState = vmessRuntimeState
        };

        const string uuid = "44444444-4444-4444-4444-444444444444";
        store.AddUser(
            InboundProtocols.Vmess,
            "vmess-in",
            new TestVmessUserDefinition
            {
                UserId = "vmess-live",
                Uuid = uuid,
                BytesPerSecond = 128,
                DeviceLimit = 2
            });

        Assert.True(store.TryGetUser(InboundProtocols.Vmess, "vmess-in", "vmess-live", out var runtimeUser));
        var user = Assert.IsType<VmessUser>(runtimeUser);
        var request = CreateMuxRequest(user);
        var headerBytes = VmessTestRequestEncoder.BuildRequestHeader(user, request);

        var decodedRequest = await new VmessHandshakeReader(new VmessSessionHistory()).ReadAsync(
            new MemoryStream(headerBytes, writable: false),
            options.ResolveUsers(),
            drainOnFailure: false,
            vmessRuntimeState,
            cts.Token);

        Assert.Equal("vmess-live", decodedRequest.User.UserId);
        Assert.Equal(uuid, decodedRequest.User.Uuid);

        Assert.True(store.RemoveUser(InboundProtocols.Vmess, "vmess-in", "vmess-live"));
        Assert.Empty(options.ResolveUsers());

        var exception = await Assert.ThrowsAsync<UnauthorizedAccessException>(() => new VmessHandshakeReader(new VmessSessionHistory()).ReadAsync(
            new MemoryStream(headerBytes, writable: false),
            options.ResolveUsers(),
            drainOnFailure: false,
            vmessRuntimeState,
            cts.Token).AsTask());
        Assert.Contains("invalid user", exception.Message, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task Vmess_runtime_state_prefers_live_registry_matcher_over_stale_user_snapshot()
    {
        using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(10));

        var store = CreateSeededStore(out _, out _, out var runtimeState);
        var staleUsers = Array.Empty<VmessUser>();
        Assert.Empty(staleUsers);

        const string uuid = "55555555-5555-5555-5555-555555555555";
        store.AddUser(
            InboundProtocols.Vmess,
            "vmess-in",
            new TestVmessUserDefinition
            {
                UserId = "vmess-live",
                Uuid = uuid,
                BytesPerSecond = 128,
                DeviceLimit = 2
            });

        Assert.True(store.TryGetUser(InboundProtocols.Vmess, "vmess-in", "vmess-live", out var runtimeUser));
        var liveUser = Assert.IsType<VmessUser>(runtimeUser);
        var request = CreateMuxRequest(liveUser);
        var headerBytes = VmessTestRequestEncoder.BuildRequestHeader(liveUser, request);

        var decodedRequest = await new VmessHandshakeReader(new VmessSessionHistory()).ReadAsync(
            new MemoryStream(headerBytes, writable: false),
            staleUsers,
            drainOnFailure: false,
            runtimeState,
            cts.Token);

        Assert.Equal("vmess-live", decodedRequest.User.UserId);
        Assert.Equal(uuid, decodedRequest.User.Uuid);
    }

    [Fact]
    public async Task Shadowsocks_runtime_state_uses_live_user_registry_snapshot()
    {
        var store = CreateShadowsocksSeededStore(out var shadowsocksRuntimeState, out _);
        var payload = await CreateShadowsocksClientPayloadAsync(
            ShadowsocksCipherTypes.ChaCha20Poly1305,
            "live-password",
            "target.example.com",
            443,
            Encoding.ASCII.GetBytes("hello-live-ss"));

        Assert.False(shadowsocksRuntimeState.TryMatchTcpUser(payload, out _, out _));

        store.AddUser(
            InboundProtocols.Shadowsocks,
            "ss-in",
            new TestShadowsocksUserDefinition
            {
                UserId = "ss-live",
                Cipher = ShadowsocksCipherTypes.ChaCha20Poly1305,
                Password = "live-password",
                BytesPerSecond = 128,
                DeviceLimit = 2
            });

        Assert.True(shadowsocksRuntimeState.TryMatchTcpUser(payload, out var user, out var account));
        Assert.Equal("ss-live", user!.UserId);
        Assert.Equal(ShadowsocksCipherTypes.ChaCha20Poly1305, account!.Cipher);

        Assert.True(store.RemoveUser(InboundProtocols.Shadowsocks, "ss-in", "ss-live"));
        Assert.False(shadowsocksRuntimeState.TryMatchTcpUser(payload, out _, out _));
    }

    [Fact]
    public async Task Shadowsocks2022_runtime_state_uses_live_user_registry_snapshot_for_multi_identity_users()
    {
        const string method = ShadowsocksCipherTypes.Blake3Aes128Gcm;
        var serverKey = CreateShadowsocks2022Key(method);
        var sharedIdentityKey = CreateShadowsocks2022Key(method, 32);
        var userKeyA = CreateShadowsocks2022Key(method, 48);
        var userIdentityKeyB = CreateShadowsocks2022Key(method, 64);
        var userKeyB = CreateShadowsocks2022Key(method, 80);
        var userPasswordA = $"{sharedIdentityKey}:{userKeyA}";
        var userPasswordB = $"{sharedIdentityKey}:{userIdentityKeyB}:{userKeyB}";
        var store = CreateShadowsocksSeededStore(serverKey, method, out _, out var shadowsocks2022RuntimeState);

        var tcpPayloadA = await CreateShadowsocks2022ClientPayloadAsync(
            method,
            $"{serverKey}:{userPasswordA}",
            "target-a.example.com",
            443,
            Encoding.ASCII.GetBytes("hello-live-ss2022-a"));
        var tcpPayloadB = await CreateShadowsocks2022ClientPayloadAsync(
            method,
            $"{serverKey}:{userPasswordB}",
            "target-b.example.com",
            8443,
            Encoding.ASCII.GetBytes("hello-live-ss2022-b"));

        Assert.False(shadowsocks2022RuntimeState.TryMatchTcpUser(tcpPayloadA, out _, out _));
        Assert.False(shadowsocks2022RuntimeState.TryMatchTcpUser(tcpPayloadB, out _, out _));

        store.AddUser(
            InboundProtocols.Shadowsocks,
            "ss-2022-in",
            new TestShadowsocksUserDefinition
            {
                UserId = "user-a",
                Cipher = string.Empty,
                Password = userPasswordA,
                BytesPerSecond = 64,
                DeviceLimit = 1
            });
        store.AddUser(
            InboundProtocols.Shadowsocks,
            "ss-2022-in",
            new TestShadowsocksUserDefinition
            {
                UserId = "user-b",
                Cipher = string.Empty,
                Password = userPasswordB,
                BytesPerSecond = 96,
                DeviceLimit = 2
            });

        Assert.True(shadowsocks2022RuntimeState.TryMatchTcpUser(tcpPayloadB, out var matchedUserB, out var matchedAccountB));
        Assert.Equal("user-b", matchedUserB!.UserId);
        Assert.Equal(method, matchedAccountB!.Method);

        Assert.True(store.RemoveUser(InboundProtocols.Shadowsocks, "ss-2022-in", "user-b"));
        Assert.False(shadowsocks2022RuntimeState.TryMatchTcpUser(tcpPayloadB, out _, out _));

        Assert.True(shadowsocks2022RuntimeState.TryMatchTcpUser(tcpPayloadA, out var matchedUserA, out var matchedAccountA));
        Assert.Equal("user-a", matchedUserA!.UserId);
        Assert.Equal(method, matchedAccountA!.Method);

        var udpPacketA = Shadowsocks2022ProtocolCodec.EncodeUdpPacket(
            Shadowsocks2022Account.Create(method, $"{serverKey}:{userPasswordA}"),
            "dns.example.com",
            53,
            Encoding.ASCII.GetBytes("hello-live-ss2022-udp"));

        Assert.True(shadowsocks2022RuntimeState.TryDecodeUdpPacket(udpPacketA, out var udpUser, out _, out var udpPacket));
        Assert.Equal("user-a", udpUser!.UserId);
        Assert.Equal("dns.example.com", udpPacket!.Host);
    }

    [Fact]
    public void UserStore_rejects_non_empty_per_user_cipher_for_shadowsocks2022_multi_user_registry()
    {
        var store = CreateShadowsocksSeededStore(out _, out _);
        var exception = Assert.Throws<InvalidOperationException>(() => store.AddUser(
            InboundProtocols.Shadowsocks,
            "ss-2022-in",
            new TestShadowsocksUserDefinition
            {
                UserId = "bad-user",
                Cipher = ShadowsocksCipherTypes.Blake3Aes128Gcm,
                Password = CreateShadowsocks2022Key(ShadowsocksCipherTypes.Blake3Aes128Gcm, 96),
                BytesPerSecond = 64,
                DeviceLimit = 1
            }));

        Assert.Equal("Shadowsocks 2022 inbound requires empty per-user cipher in multi-user mode.", exception.Message);
    }

    [Fact]
    public void UserStore_rejects_duplicate_shadowsocks2022_per_user_key_for_multi_user_registry()
    {
        const string method = ShadowsocksCipherTypes.Blake3Aes128Gcm;
        var userKey = CreateShadowsocks2022Key(method, 96);
        var store = CreateShadowsocksSeededStore(CreateShadowsocks2022Key(method), method, out _, out _);

        store.AddUser(
            InboundProtocols.Shadowsocks,
            "ss-2022-in",
            new TestShadowsocksUserDefinition
            {
                UserId = "user-a",
                Cipher = string.Empty,
                Password = userKey,
                BytesPerSecond = 64,
                DeviceLimit = 1
            });

        var exception = Assert.Throws<InvalidOperationException>(() => store.AddUser(
            InboundProtocols.Shadowsocks,
            "ss-2022-in",
            new TestShadowsocksUserDefinition
            {
                UserId = "user-b",
                Cipher = string.Empty,
                Password = userKey,
                BytesPerSecond = 96,
                DeviceLimit = 2
            }));

        Assert.Equal("Shadowsocks 2022 inbound contains duplicate per-user keys.", exception.Message);
    }

    [Fact]
    public void UserStore_ignores_relay_destination_for_shadowsocks2022_multi_user_registry()
    {
        const string method = ShadowsocksCipherTypes.Blake3Aes128Gcm;
        var store = CreateShadowsocksSeededStore(CreateShadowsocks2022Key(method), method, out _, out _);

        store.AddUser(
            InboundProtocols.Shadowsocks,
            "ss-2022-in",
            new TestShadowsocks2022UserDefinition
            {
                UserId = "user-a",
                Password = CreateShadowsocks2022Key(method, 96),
                Address = " relay.example.com ",
                Port = 53,
                BytesPerSecond = 64,
                DeviceLimit = 1
            });

        Assert.True(store.TryGetUser(InboundProtocols.Shadowsocks, "ss-2022-in", "user-a", out var rawUser));
        var user = Assert.IsType<Shadowsocks2022User>(rawUser);
        Assert.Equal(string.Empty, user.Address);
        Assert.Equal(0, user.Port);
    }

    private static UserStore CreateSeededStore()
        => CreateSeededStore(out _, out _, out _);

    private static UserStore CreateSeededStore(
        out TrojanInboundRuntimeState trojanRuntimeState,
        out VlessInboundRuntimeState vlessRuntimeState,
        out VmessInboundRuntimeState vmessRuntimeState)
    {
        trojanRuntimeState = new TrojanInboundRuntimeState(Array.Empty<TrojanUser>());
        vlessRuntimeState = new VlessInboundRuntimeState(Array.Empty<VlessUser>());
        vmessRuntimeState = new VmessInboundRuntimeState(Array.Empty<VmessUser>());
        var store = new UserStore();
        ((IRuntimeUserStoreController)store).Reset(
            new RuntimePlan
            {
                Plan = NodeRuntimePlanner.Create(
                [
                    new TrojanInboundRuntimePlan
                    {
                        TlsListeners =
                        [
                            new TrojanTlsListenerRuntime
                            {
                                Binding = new ListenerBinding("127.0.0.1", 443),
                                RawTlsInbound = new TrojanTlsInboundRuntime
                                {
                                    Tag = "trojan-in",
                                    Transport = InboundTransports.Tls,
                                    Binding = new ListenerBinding("127.0.0.1", 443),
                                    RuntimeState = trojanRuntimeState
                                }
                            }
                        ]
                    },
                    new VlessInboundRuntimePlan
                    {
                        TlsListeners =
                        [
                            new VlessTlsListenerRuntime
                            {
                                Binding = new ListenerBinding("127.0.0.1", 1443),
                                RawTlsInbound = new VlessTlsInboundRuntime
                                {
                                    Tag = "vless-in",
                                    Transport = InboundTransports.Tls,
                                    Binding = new ListenerBinding("127.0.0.1", 1443),
                                    RuntimeState = vlessRuntimeState
                                }
                            }
                        ]
                    },
                    new VmessInboundRuntimePlan
                    {
                        TlsListeners =
                        [
                            new VmessTlsListenerRuntime
                            {
                                Binding = new ListenerBinding("127.0.0.1", 2443),
                                RawTlsInbound = new VmessTlsInboundRuntime
                                {
                                    Tag = "vmess-in",
                                    Transport = InboundTransports.Tls,
                                    Binding = new ListenerBinding("127.0.0.1", 2443),
                                    RuntimeState = vmessRuntimeState
                                }
                            }
                        ]
                    }
                ],
                    OutboundRuntimePlan.Empty)
            });
        return store;
    }

    private static UserStore CreateShadowsocksSeededStore(
        out ShadowsocksInboundRuntimeState shadowsocksRuntimeState,
        out Shadowsocks2022InboundRuntimeState shadowsocks2022RuntimeState)
        => CreateShadowsocksSeededStore(
            CreateShadowsocks2022Key(ShadowsocksCipherTypes.Blake3Aes128Gcm),
            ShadowsocksCipherTypes.Blake3Aes128Gcm,
            out shadowsocksRuntimeState,
            out shadowsocks2022RuntimeState);

    private static UserStore CreateShadowsocksSeededStore(
        string serverKey,
        string method,
        out ShadowsocksInboundRuntimeState shadowsocksRuntimeState,
        out Shadowsocks2022InboundRuntimeState shadowsocks2022RuntimeState)
    {
        shadowsocksRuntimeState = new ShadowsocksInboundRuntimeState(Array.Empty<ShadowsocksUser>());
        shadowsocks2022RuntimeState = new Shadowsocks2022InboundRuntimeState(
            method,
            serverKey,
            Shadowsocks2022InboundModes.MultiUser,
            Array.Empty<Shadowsocks2022User>());

        var store = new UserStore();
        ((IRuntimeUserStoreController)store).Reset(
            new RuntimePlan
            {
                Plan = NodeRuntimePlanner.Create(
                [
                    new ShadowsocksInboundRuntimePlan
                    {
                        Inbounds =
                        [
                            new ShadowsocksInboundRuntime
                            {
                                Tag = "ss-in",
                                Binding = new ListenerBinding("127.0.0.1", 8388),
                                RuntimeState = shadowsocksRuntimeState,
                                Networks = [RoutingNetworks.Tcp],
                                Users = Array.Empty<ShadowsocksUser>()
                            }
                        ],
                        Inbounds2022 =
                        [
                            new Shadowsocks2022InboundRuntime
                            {
                                Tag = "ss-2022-in",
                                Binding = new ListenerBinding("127.0.0.1", 9388),
                                RuntimeState = shadowsocks2022RuntimeState,
                                Networks = [RoutingNetworks.Tcp, RoutingNetworks.Udp],
                                Method = method,
                                Key = serverKey,
                                Mode = Shadowsocks2022InboundModes.MultiUser,
                                Users = Array.Empty<Shadowsocks2022User>()
                            }
                        ]
                    }
                ],
                    OutboundRuntimePlan.Empty)
            });
        return store;
    }

    private static async Task<byte[]> CreateShadowsocksClientPayloadAsync(
        string cipher,
        string password,
        string host,
        int port,
        byte[] payload)
    {
        var account = ShadowsocksAccount.Create(cipher, password);
        await using var transport = new MemoryStream();
        await using var stream = await ShadowsocksProtocolCodec.OpenClientTcpStreamAsync(
            transport,
            account,
            host,
            port,
            CancellationToken.None);

        await stream.WriteAsync(payload, CancellationToken.None);
        await stream.FlushAsync(CancellationToken.None);
        return transport.ToArray();
    }

    private static async Task<byte[]> CreateShadowsocks2022ClientPayloadAsync(
        string method,
        string key,
        string host,
        int port,
        byte[] payload)
    {
        var account = Shadowsocks2022Account.Create(method, key);
        await using var transport = new MemoryStream();
        await using var stream = await Shadowsocks2022ProtocolCodec.OpenClientTcpStreamAsync(
            transport,
            account,
            host,
            port,
            CancellationToken.None);

        await stream.WriteAsync(payload, CancellationToken.None);
        await stream.FlushAsync(CancellationToken.None);
        return transport.ToArray();
    }

    private static string CreateShadowsocks2022Key(string method, int seed = 0)
    {
        var keySize = method switch
        {
            ShadowsocksCipherTypes.Blake3Aes128Gcm => 16,
            ShadowsocksCipherTypes.Blake3Aes256Gcm => 32,
            ShadowsocksCipherTypes.Blake3ChaCha20Poly1305 => 32,
            _ => throw new NotSupportedException($"Unsupported Shadowsocks 2022 method: {method}.")
        };

        return Convert.ToBase64String(
            Enumerable.Range(seed, keySize)
                .Select(static value => (byte)(value & 0xFF))
                .ToArray());
    }

    private static VmessRequest CreateMuxRequest(VmessUser user)
        => new()
        {
            Version = 1,
            User = user,
            RequestBodyKey = Enumerable.Range(0x10, 16).Select(static value => (byte)value).ToArray(),
            RequestBodyIv = Enumerable.Range(0x80, 16).Select(static value => (byte)value).ToArray(),
            ResponseHeader = 0x5A,
            Option = VmessRequestOptions.ChunkStream |
                     VmessRequestOptions.ChunkMasking |
                     VmessRequestOptions.GlobalPadding |
                     VmessRequestOptions.AuthenticatedLength,
            Security = VmessSecurityType.Aes128Gcm,
            Command = VmessCommand.Mux,
            TargetHost = "v1.mux.cool",
            TargetPort = 0
        };

    private sealed record TestTrojanUserDefinition : ITrojanUserDefinition
    {
        public string UserId { get; init; } = string.Empty;

        public int Level { get; init; }

        public string Password { get; init; } = string.Empty;

        public long BytesPerSecond { get; init; }

        public int DeviceLimit { get; init; }
    }

    private sealed record TestShadowsocksUserDefinition : IShadowsocksUserDefinition
    {
        public string UserId { get; init; } = string.Empty;

        public int Level { get; init; }

        public string Cipher { get; init; } = string.Empty;

        public string Password { get; init; } = string.Empty;

        public long BytesPerSecond { get; init; }

        public int DeviceLimit { get; init; }
    }

    private sealed record TestShadowsocks2022UserDefinition : IShadowsocks2022UserDefinition
    {
        public string UserId { get; init; } = string.Empty;

        public int Level { get; init; }

        public string Cipher { get; init; } = string.Empty;

        public string Password { get; init; } = string.Empty;

        public string Address { get; init; } = string.Empty;

        public int Port { get; init; }

        public long BytesPerSecond { get; init; }

        public int DeviceLimit { get; init; }
    }

    private sealed record TestVlessUserDefinition : IVlessUserDefinition
    {
        public string UserId { get; init; } = string.Empty;

        public int Level { get; init; }

        public string Uuid { get; init; } = string.Empty;

        public string Flow { get; init; } = string.Empty;

        public string ReverseTag { get; init; } = string.Empty;

        public IReadOnlyList<uint> TestSeed { get; init; } = Array.Empty<uint>();

        public long BytesPerSecond { get; init; }

        public int DeviceLimit { get; init; }
    }

    private sealed record TestVmessUserDefinition : IVmessUserDefinition
    {
        public string UserId { get; init; } = string.Empty;

        public int Level { get; init; }

        public string Uuid { get; init; } = string.Empty;

        public long BytesPerSecond { get; init; }

        public int DeviceLimit { get; init; }
    }
}

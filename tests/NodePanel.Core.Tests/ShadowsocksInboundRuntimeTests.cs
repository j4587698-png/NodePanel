using System.Text;
using NodePanel.Core.Protocol;
using NodePanel.Core.Runtime;

namespace NodePanel.Core.Tests;

public sealed class ShadowsocksInboundRuntimeTests
{
    [Theory]
    [InlineData(ShadowsocksCipherTypes.ChaCha20Poly1305)]
    [InlineData(ShadowsocksCipherTypes.XChaCha20Poly1305)]
    public void TryBuild_supports_tcp_and_udp_networks(string cipher)
    {
        var result = ShadowsocksInboundRuntimePlanner.TryBuild(
            [
                new TestInboundDefinition
                {
                    Tag = "ss-entry",
                    Enabled = true,
                    Protocol = "ss",
                    ListenAddress = "0.0.0.0",
                    Port = 8388,
                    Security = cipher,
                    Password = "inbound-secret",
                    Networks = [" tcp ", "udp"],
                    Users =
                    [
                        new TestShadowsocksUser
                        {
                            UserId = "demo-user",
                            Cipher = cipher,
                            Password = "demo-secret"
                        }
                    ]
                }
            ],
            out var plan,
            out var error);

        Assert.True(result, error);
        var inbound = Assert.Single(plan.Inbounds);
        Assert.True(inbound.HasTcp);
        Assert.True(inbound.HasUdp);
        Assert.Equal(["tcp", "udp"], inbound.Networks);
        var user = Assert.Single(inbound.Users);
        Assert.Equal("demo-user", user.UserId);
        Assert.Equal(cipher, user.Cipher);
    }

    [Fact]
    public void TryBuild_rejects_regular_shadowsocks_user_without_explicit_cipher()
    {
        var result = ShadowsocksInboundRuntimePlanner.TryBuild(
            [
                new TestInboundDefinition
                {
                    Tag = "ss-user-missing-cipher",
                    Enabled = true,
                    Protocol = "shadowsocks",
                    ListenAddress = "127.0.0.1",
                    Port = 8388,
                    Security = ShadowsocksCipherTypes.Aes128Gcm,
                    Password = "inbound-secret",
                    Users =
                    [
                        new TestShadowsocksUser
                        {
                            UserId = "demo-user",
                            Cipher = string.Empty,
                            Password = "demo-secret"
                        }
                    ]
                }
            ],
            out _,
            out var error);

        Assert.False(result);
        Assert.Equal(
            "Shadowsocks user 'demo-user' on inbound 'ss-user-missing-cipher' is invalid: Shadowsocks cipher is not specified.",
            error);
    }

    [Fact]
    public void TryBuild_rejects_none_cipher_on_regular_shadowsocks_user_path()
    {
        var result = ShadowsocksInboundRuntimePlanner.TryBuild(
            [
                new TestInboundDefinition
                {
                    Tag = "ss-user-none",
                    Enabled = true,
                    Protocol = "shadowsocks",
                    ListenAddress = "127.0.0.1",
                    Port = 8388,
                    Security = ShadowsocksCipherTypes.Aes128Gcm,
                    Password = "inbound-secret",
                    Users =
                    [
                        new TestShadowsocksUser
                        {
                            UserId = "demo-user",
                            Cipher = "plain",
                            Password = "demo-secret"
                        }
                    ]
                }
            ],
            out _,
            out var error);

        Assert.False(result);
        Assert.Equal(
            "Shadowsocks user 'demo-user' on inbound 'ss-user-none' is invalid: Shadowsocks cipher 'none' is only supported by the implicit single-user path.",
            error);
    }

    [Fact]
    public void TryBuild_rejects_regular_shadowsocks_user_without_password()
    {
        var result = ShadowsocksInboundRuntimePlanner.TryBuild(
            [
                new TestInboundDefinition
                {
                    Tag = "ss-user-missing-password",
                    Enabled = true,
                    Protocol = "shadowsocks",
                    ListenAddress = "127.0.0.1",
                    Port = 8388,
                    Security = ShadowsocksCipherTypes.Aes128Gcm,
                    Password = "inbound-secret",
                    Users =
                    [
                        new TestShadowsocksUser
                        {
                            UserId = "demo-user",
                            Cipher = ShadowsocksCipherTypes.Aes128Gcm,
                            Password = string.Empty
                        }
                    ]
                }
            ],
            out _,
            out var error);

        Assert.False(result);
        Assert.Equal(
            "Shadowsocks user 'demo-user' on inbound 'ss-user-missing-password' requires a password.",
            error);
    }

    [Theory]
    [InlineData(ShadowsocksCipherTypes.Aes128Gcm, "inbound-secret", ShadowsocksCipherTypes.Aes128Gcm)]
    [InlineData("aead_xchacha20_poly1305", "inbound-secret-x", ShadowsocksCipherTypes.XChaCha20Poly1305)]
    [InlineData("plain", "inbound-plain", ShadowsocksCipherTypes.None)]
    public void TryBuild_supports_implicit_single_user_from_inbound_password(
        string cipher,
        string password,
        string expectedCipher)
    {
        var result = ShadowsocksInboundRuntimePlanner.TryBuild(
            [
                new TestInboundDefinition
                {
                    Tag = "ss-implicit",
                    Enabled = true,
                    Protocol = "shadowsocks",
                    ListenAddress = "127.0.0.1",
                    Port = 8388,
                    Security = cipher,
                    Password = password,
                    Networks = ["tcp"]
                }
            ],
            out var plan,
            out var error);

        Assert.True(result, error);
        var inbound = Assert.Single(plan.Inbounds);
        var user = Assert.Single(inbound.Users);
        Assert.Equal("default", user.UserId);
        Assert.Equal(expectedCipher, user.Cipher);
        Assert.Equal(password, user.Password);
        Assert.Equal(RuntimeUserKeys.Create(InboundProtocols.Shadowsocks, "ss-implicit", "default"), user.RuntimeKey);
    }

    [Fact]
    public void TryBuild_rejects_plain_without_password_for_implicit_single_user()
    {
        var result = ShadowsocksInboundRuntimePlanner.TryBuild(
            [
                new TestInboundDefinition
                {
                    Tag = "ss-implicit-none",
                    Enabled = true,
                    Protocol = "shadowsocks",
                    ListenAddress = "127.0.0.1",
                    Port = 8388,
                    Security = "plain",
                    Password = string.Empty,
                    Networks = ["tcp"]
                }
            ],
            out _,
            out var error);

        Assert.False(result);
        Assert.Equal(
            "Shadowsocks inbound 'ss-implicit-none' requires a password when no users are configured.",
            error);
    }

    [Fact]
    public void TryBuild_defaults_regular_shadowsocks_to_tcp_only_when_networks_unspecified()
    {
        var result = ShadowsocksInboundRuntimePlanner.TryBuild(
            [
                new TestInboundDefinition
                {
                    Tag = "ss-default-network",
                    Enabled = true,
                    Protocol = "shadowsocks",
                    ListenAddress = "127.0.0.1",
                    Port = 8388,
                    Security = ShadowsocksCipherTypes.Aes128Gcm,
                    Password = "inbound-secret"
                }
            ],
            out var plan,
            out var error);

        Assert.True(result, error);
        var inbound = Assert.Single(plan.Inbounds);
        Assert.Equal([RoutingNetworks.Tcp], inbound.Networks);
        Assert.True(inbound.HasTcp);
        Assert.False(inbound.HasUdp);
    }

    [Fact]
    public void TryBuild_builds_shadowsocks_2022_single_user_definition()
    {
        var result = ShadowsocksInboundRuntimePlanner.TryBuild(
            [
                new TestInboundDefinition
                {
                    Tag = "ss-2022",
                    Enabled = true,
                    Protocol = "shadowsocks",
                    ListenAddress = "127.0.0.1",
                    Port = 8388,
                    Security = ShadowsocksCipherTypes.Blake3Aes128Gcm,
                    Password = CreateShadowsocks2022Key(ShadowsocksCipherTypes.Blake3Aes128Gcm),
                    Networks = ["tcp"]
                }
            ],
            out var plan,
            out var error);

        Assert.True(result, error);
        Assert.Empty(plan.Inbounds);
        var inbound = Assert.Single(plan.Inbounds2022);
        Assert.Equal(Shadowsocks2022InboundModes.SingleUser, inbound.Mode);
        Assert.Equal(ShadowsocksCipherTypes.Blake3Aes128Gcm, inbound.Method);
        var user = Assert.Single(inbound.Users);
        Assert.Equal("default", user.UserId);
        Assert.Equal(inbound.Key, user.Password);
    }

    [Fact]
    public void TryBuild_defaults_shadowsocks_2022_to_tcp_and_udp_when_networks_unspecified()
    {
        var result = ShadowsocksInboundRuntimePlanner.TryBuild(
            [
                new TestInboundDefinition
                {
                    Tag = "ss-2022-default-network",
                    Enabled = true,
                    Protocol = "shadowsocks",
                    ListenAddress = "127.0.0.1",
                    Port = 8388,
                    Security = ShadowsocksCipherTypes.Blake3Aes128Gcm,
                    Password = CreateShadowsocks2022Key(ShadowsocksCipherTypes.Blake3Aes128Gcm)
                }
            ],
            out var plan,
            out var error);

        Assert.True(result, error);
        var inbound = Assert.Single(plan.Inbounds2022);
        Assert.Equal([RoutingNetworks.Tcp, RoutingNetworks.Udp], inbound.Networks);
        Assert.True(inbound.HasTcp);
        Assert.True(inbound.HasUdp);
    }

    [Fact]
    public void TryBuild_builds_shadowsocks_2022_multi_user_definition()
    {
        var result = ShadowsocksInboundRuntimePlanner.TryBuild(
            [
                new TestInboundDefinition
                {
                    Tag = "ss-2022-multi",
                    Enabled = true,
                    Protocol = "shadowsocks",
                    ListenAddress = "127.0.0.1",
                    Port = 8388,
                    Security = ShadowsocksCipherTypes.Blake3Aes256Gcm,
                    Password = CreateShadowsocks2022Key(ShadowsocksCipherTypes.Blake3Aes256Gcm),
                    Networks = ["tcp", "udp"],
                    Users2022 =
                    [
                        new TestShadowsocks2022User
                        {
                            UserId = "user-a",
                            Password = CreateShadowsocks2022Key(ShadowsocksCipherTypes.Blake3Aes256Gcm, 32)
                        },
                        new TestShadowsocks2022User
                        {
                            UserId = "user-b",
                            Password = CreateShadowsocks2022Key(ShadowsocksCipherTypes.Blake3Aes256Gcm, 64)
                        }
                    ]
                }
            ],
            out var plan,
            out var error);

        Assert.True(result, error);
        var inbound = Assert.Single(plan.Inbounds2022);
        Assert.Equal(Shadowsocks2022InboundModes.MultiUser, inbound.Mode);
        Assert.Equal(["tcp", "udp"], inbound.Networks);
        Assert.Equal(2, inbound.Users.Count);
        Assert.All(inbound.Users, static user => Assert.False(user.HasRelayDestination));
    }

    [Fact]
    public void TryBuild_ignores_later_relay_destination_when_first_shadowsocks_2022_user_selects_multi_user_mode()
    {
        var result = ShadowsocksInboundRuntimePlanner.TryBuild(
            [
                new TestInboundDefinition
                {
                    Tag = "ss-2022-multi-ignore-relay",
                    Enabled = true,
                    Protocol = "shadowsocks",
                    ListenAddress = "127.0.0.1",
                    Port = 8388,
                    Security = ShadowsocksCipherTypes.Blake3Aes256Gcm,
                    Password = CreateShadowsocks2022Key(ShadowsocksCipherTypes.Blake3Aes256Gcm),
                    Users2022 =
                    [
                        new TestShadowsocks2022User
                        {
                            UserId = "user-a",
                            Password = CreateShadowsocks2022Key(ShadowsocksCipherTypes.Blake3Aes256Gcm, 32)
                        },
                        new TestShadowsocks2022User
                        {
                            UserId = "user-b",
                            Password = CreateShadowsocks2022Key(ShadowsocksCipherTypes.Blake3Aes256Gcm, 64),
                            Address = " relay.example.com ",
                            Port = 53
                        }
                    ]
                }
            ],
            out var plan,
            out var error);

        Assert.True(result, error);
        var inbound = Assert.Single(plan.Inbounds2022);
        Assert.Equal(Shadowsocks2022InboundModes.MultiUser, inbound.Mode);
        var userB = Assert.Single(inbound.Users, static user => user.UserId == "user-b");
        Assert.Equal(string.Empty, userB.Address);
        Assert.Equal(0, userB.Port);
    }

    [Fact]
    public void TryBuild_adapts_generic_shadowsocks_users_into_shadowsocks_2022_multi_user_definition()
    {
        var result = ShadowsocksInboundRuntimePlanner.TryBuild(
            [
                new TestInboundDefinition
                {
                    Tag = "ss-2022-adapted",
                    Enabled = true,
                    Protocol = "shadowsocks",
                    ListenAddress = "127.0.0.1",
                    Port = 8388,
                    Security = ShadowsocksCipherTypes.Blake3Aes256Gcm,
                    Password = CreateShadowsocks2022Key(ShadowsocksCipherTypes.Blake3Aes256Gcm),
                    Networks = ["tcp"],
                    Users =
                    [
                        new TestShadowsocksUser
                        {
                            UserId = "user-a",
                            Cipher = string.Empty,
                            Password = CreateShadowsocks2022Key(ShadowsocksCipherTypes.Blake3Aes256Gcm, 32)
                        },
                        new TestShadowsocksUser
                        {
                            UserId = "user-b",
                            Cipher = string.Empty,
                            Password = CreateShadowsocks2022Key(ShadowsocksCipherTypes.Blake3Aes256Gcm, 64)
                        }
                    ]
                }
            ],
            out var plan,
            out var error);

        Assert.True(result, error);
        Assert.Empty(plan.Inbounds);
        var inbound = Assert.Single(plan.Inbounds2022);
        Assert.Equal(Shadowsocks2022InboundModes.MultiUser, inbound.Mode);
        Assert.Equal(2, inbound.Users.Count);
        Assert.All(inbound.Users, static user => Assert.Equal(string.Empty, user.Cipher));
    }

    [Fact]
    public void TryBuild_builds_shadowsocks_2022_relay_definition()
    {
        var result = ShadowsocksInboundRuntimePlanner.TryBuild(
            [
                new TestInboundDefinition
                {
                    Tag = "ss-2022-relay",
                    Enabled = true,
                    Protocol = "shadowsocks",
                    ListenAddress = "127.0.0.1",
                    Port = 8388,
                    Security = ShadowsocksCipherTypes.Blake3Aes128Gcm,
                    Password = CreateShadowsocks2022Key(ShadowsocksCipherTypes.Blake3Aes128Gcm),
                    Networks = ["udp"],
                    Users2022 =
                    [
                        new TestShadowsocks2022User
                        {
                            UserId = "relay-a",
                            Password = CreateShadowsocks2022Key(ShadowsocksCipherTypes.Blake3Aes128Gcm, 32),
                            Address = " relay.example.com ",
                            Port = 53
                        }
                    ]
                }
            ],
            out var plan,
            out var error);

        Assert.True(result, error);
        var inbound = Assert.Single(plan.Inbounds2022);
        Assert.Equal(Shadowsocks2022InboundModes.Relay, inbound.Mode);
        var user = Assert.Single(inbound.Users);
        Assert.Equal("relay.example.com", user.Address);
        Assert.Equal(53, user.Port);
    }

    [Fact]
    public void TryBuild_rejects_shadowsocks_2022_chacha_multi_user_definition()
    {
        var result = ShadowsocksInboundRuntimePlanner.TryBuild(
            [
                new TestInboundDefinition
                {
                    Tag = "ss-2022-chacha-multi",
                    Enabled = true,
                    Protocol = "shadowsocks",
                    ListenAddress = "127.0.0.1",
                    Port = 8388,
                    Security = ShadowsocksCipherTypes.Blake3ChaCha20Poly1305,
                    Password = CreateShadowsocks2022Key(ShadowsocksCipherTypes.Blake3ChaCha20Poly1305),
                    Networks = ["tcp"],
                    Users2022 =
                    [
                        new TestShadowsocks2022User
                        {
                            UserId = "user-a",
                            Password = CreateShadowsocks2022Key(ShadowsocksCipherTypes.Blake3ChaCha20Poly1305, 32)
                        }
                    ]
                }
            ],
            out _,
            out var error);

        Assert.False(result);
        Assert.Equal(
            "Shadowsocks 2022 inbound 'ss-2022-chacha-multi' supports multi-user and relay modes only for 2022-blake3-aes-*-gcm methods.",
            error);
    }

    [Theory]
    [InlineData(ShadowsocksCipherTypes.Aes128Gcm, "secret")]
    [InlineData(ShadowsocksCipherTypes.XChaCha20Poly1305, "secret-x")]
    public async Task RuntimeState_matches_tcp_user_from_first_payload(string cipher, string password)
    {
        var user = new ShadowsocksUser
        {
            UserId = "tcp-user",
            Cipher = cipher,
            Password = password,
            RuntimeKey = RuntimeUserKeys.Create(InboundProtocols.Shadowsocks, "ss-entry", "tcp-user"),
            BytesPerSecond = 0
        };

        var payload = await CreateTcpClientPayloadAsync(
            user.Cipher,
            user.Password,
            "target.example.com",
            443,
            Encoding.ASCII.GetBytes("hello-ss-tcp"));

        var state = new ShadowsocksInboundRuntimeState([user]);

        var matched = state.TryMatchTcpUser(payload, out var resolvedUser, out var resolvedAccount);

        Assert.True(matched);
        Assert.NotNull(resolvedUser);
        Assert.NotNull(resolvedAccount);
        Assert.Equal(user.UserId, resolvedUser!.UserId);
        Assert.Equal(user.Cipher, resolvedAccount!.Cipher);
    }

    [Theory]
    [InlineData(ShadowsocksCipherTypes.ChaCha20Poly1305, "secret")]
    [InlineData(ShadowsocksCipherTypes.XChaCha20Poly1305, "secret-x")]
    public void RuntimeState_decodes_udp_packet_to_user(string cipher, string password)
    {
        var user = new ShadowsocksUser
        {
            UserId = "udp-user",
            Cipher = cipher,
            Password = password,
            RuntimeKey = RuntimeUserKeys.Create(InboundProtocols.Shadowsocks, "ss-entry", "udp-user"),
            BytesPerSecond = 0
        };

        var account = ShadowsocksAccount.Create(user.Cipher, user.Password);
        var encoded = ShadowsocksProtocolCodec.EncodeUdpPacket(
            account,
            "dns.example.com",
            53,
            Encoding.ASCII.GetBytes("hello-ss-udp"));

        var state = new ShadowsocksInboundRuntimeState([user]);

        var decoded = state.TryDecodeUdpPacket(encoded, out var resolvedUser, out var resolvedAccount, out var packet);

        Assert.True(decoded);
        Assert.NotNull(resolvedUser);
        Assert.NotNull(resolvedAccount);
        Assert.NotNull(packet);
        Assert.Equal(user.UserId, resolvedUser!.UserId);
        Assert.Equal(user.Cipher, resolvedAccount!.Cipher);
        Assert.Equal("dns.example.com", packet!.Host);
        Assert.Equal(53, packet.Port);
        Assert.Equal("hello-ss-udp", Encoding.ASCII.GetString(packet.Payload));
    }

    [Theory]
    [InlineData(ShadowsocksCipherTypes.Blake3Aes128Gcm)]
    [InlineData(ShadowsocksCipherTypes.Blake3ChaCha20Poly1305)]
    public async Task RuntimeState_matches_shadowsocks_2022_single_user_from_first_payload(string method)
    {
        var key = CreateShadowsocks2022Key(method);
        var user = new Shadowsocks2022User
        {
            UserId = "tcp-2022-user",
            Password = key,
            RuntimeKey = RuntimeUserKeys.Create(InboundProtocols.Shadowsocks, "ss-2022-entry", "tcp-2022-user"),
            BytesPerSecond = 0
        };

        var payload = await CreateTcp2022ClientPayloadAsync(
            method,
            key,
            "target.example.com",
            443,
            Encoding.ASCII.GetBytes("hello-ss-2022-tcp"));

        var state = new Shadowsocks2022InboundRuntimeState(
            method,
            key,
            Shadowsocks2022InboundModes.SingleUser,
            [user]);

        var matched = state.TryMatchTcpUser(payload, out var resolvedUser, out var resolvedAccount);

        Assert.True(matched);
        Assert.NotNull(resolvedUser);
        Assert.NotNull(resolvedAccount);
        Assert.Equal(user.UserId, resolvedUser!.UserId);
        Assert.Equal(method, resolvedAccount!.Method);
    }

    [Theory]
    [InlineData(ShadowsocksCipherTypes.Blake3Aes128Gcm)]
    [InlineData(ShadowsocksCipherTypes.Blake3Aes256Gcm)]
    public async Task RuntimeState_matches_shadowsocks_2022_multi_user_from_first_payload(string method)
    {
        var serverKey = CreateShadowsocks2022Key(method);
        var sharedIdentityKey = CreateShadowsocks2022Key(method, 32);
        var userKeyA = CreateShadowsocks2022Key(method, 64);
        var userIdentityKeyB = CreateShadowsocks2022Key(method, 96);
        var userKeyB = CreateShadowsocks2022Key(method, 128);
        Shadowsocks2022User[] users =
        [
            new Shadowsocks2022User
            {
                UserId = "user-a",
                Password = $"{sharedIdentityKey}:{userKeyA}",
                RuntimeKey = RuntimeUserKeys.Create(InboundProtocols.Shadowsocks, "ss-2022-entry", "user-a"),
                BytesPerSecond = 0
            },
            new Shadowsocks2022User
            {
                UserId = "user-b",
                Password = $"{sharedIdentityKey}:{userIdentityKeyB}:{userKeyB}",
                RuntimeKey = RuntimeUserKeys.Create(InboundProtocols.Shadowsocks, "ss-2022-entry", "user-b"),
                BytesPerSecond = 0
            }
        ];

        var payload = await CreateTcp2022ClientPayloadAsync(
            method,
            $"{serverKey}:{sharedIdentityKey}:{userIdentityKeyB}:{userKeyB}",
            "target.example.com",
            443,
            Encoding.ASCII.GetBytes("hello-ss-2022-multi-tcp"));

        var state = new Shadowsocks2022InboundRuntimeState(
            method,
            serverKey,
            Shadowsocks2022InboundModes.MultiUser,
            users);

        var matched = state.TryMatchTcpUser(payload, out var resolvedUser, out var resolvedAccount);

        Assert.True(matched);
        Assert.NotNull(resolvedUser);
        Assert.NotNull(resolvedAccount);
        Assert.Equal("user-b", resolvedUser!.UserId);
        Assert.Equal(method, resolvedAccount!.Method);
    }

    [Theory]
    [InlineData(ShadowsocksCipherTypes.Blake3Aes128Gcm)]
    [InlineData(ShadowsocksCipherTypes.Blake3ChaCha20Poly1305)]
    public void RuntimeState_decodes_shadowsocks_2022_udp_packet_to_user(string method)
    {
        var key = CreateShadowsocks2022Key(method);
        var user = new Shadowsocks2022User
        {
            UserId = "udp-2022-user",
            Password = key,
            RuntimeKey = RuntimeUserKeys.Create(InboundProtocols.Shadowsocks, "ss-2022-entry", "udp-2022-user"),
            BytesPerSecond = 0
        };

        var account = Shadowsocks2022Account.Create(method, key);
        var encoded = Shadowsocks2022ProtocolCodec.EncodeUdpPacket(
            account,
            "dns.example.com",
            53,
            Encoding.ASCII.GetBytes("hello-ss-2022-udp"));

        var state = new Shadowsocks2022InboundRuntimeState(
            method,
            key,
            Shadowsocks2022InboundModes.SingleUser,
            [user]);

        var decoded = state.TryDecodeUdpPacket(encoded, out var resolvedUser, out var resolvedAccount, out var packet);

        Assert.True(decoded);
        Assert.NotNull(resolvedUser);
        Assert.NotNull(resolvedAccount);
        Assert.NotNull(packet);
        Assert.Equal(user.UserId, resolvedUser!.UserId);
        Assert.Equal(method, resolvedAccount!.Method);
        Assert.Equal("dns.example.com", packet!.Host);
        Assert.Equal(53, packet.Port);
        Assert.Equal("hello-ss-2022-udp", Encoding.ASCII.GetString(packet.Payload));
    }

    [Theory]
    [InlineData(ShadowsocksCipherTypes.Blake3Aes128Gcm)]
    [InlineData(ShadowsocksCipherTypes.Blake3Aes256Gcm)]
    public void RuntimeState_decodes_shadowsocks_2022_multi_user_udp_packet_to_user(string method)
    {
        var serverKey = CreateShadowsocks2022Key(method);
        var sharedIdentityKey = CreateShadowsocks2022Key(method, 32);
        var userKeyA = CreateShadowsocks2022Key(method, 64);
        var userIdentityKeyB = CreateShadowsocks2022Key(method, 96);
        var userKeyB = CreateShadowsocks2022Key(method, 128);
        var account = Shadowsocks2022Account.Create(method, $"{serverKey}:{sharedIdentityKey}:{userIdentityKeyB}:{userKeyB}");
        var encoded = Shadowsocks2022ProtocolCodec.EncodeUdpPacket(
            account,
            "dns.example.com",
            53,
            Encoding.ASCII.GetBytes("hello-ss-2022-multi-udp"));
        var state = new Shadowsocks2022InboundRuntimeState(
            method,
            serverKey,
            Shadowsocks2022InboundModes.MultiUser,
            [
                new Shadowsocks2022User
                {
                    UserId = "udp-2022-user-a",
                    Password = $"{sharedIdentityKey}:{userKeyA}",
                    RuntimeKey = RuntimeUserKeys.Create(InboundProtocols.Shadowsocks, "ss-2022-entry", "udp-2022-user-a"),
                    BytesPerSecond = 0
                },
                new Shadowsocks2022User
                {
                    UserId = "udp-2022-user-b",
                    Password = $"{sharedIdentityKey}:{userIdentityKeyB}:{userKeyB}",
                    RuntimeKey = RuntimeUserKeys.Create(InboundProtocols.Shadowsocks, "ss-2022-entry", "udp-2022-user-b"),
                    BytesPerSecond = 0
                }
            ]);

        var decoded = state.TryDecodeUdpPacket(encoded, out var resolvedUser, out var resolvedAccount, out var packet);

        Assert.True(decoded);
        Assert.NotNull(resolvedUser);
        Assert.NotNull(resolvedAccount);
        Assert.NotNull(packet);
        Assert.Equal("udp-2022-user-b", resolvedUser!.UserId);
        Assert.Equal(method, resolvedAccount!.Method);
        Assert.Equal("dns.example.com", packet!.Host);
        Assert.Equal(53, packet.Port);
        Assert.Equal("hello-ss-2022-multi-udp", Encoding.ASCII.GetString(packet.Payload));
    }

    [Fact]
    public void RuntimeState_rejects_shadowsocks_2022_user_with_non_empty_per_user_cipher()
    {
        const string method = ShadowsocksCipherTypes.Blake3Aes128Gcm;
        var serverKey = CreateShadowsocks2022Key(method);

        var exception = Assert.Throws<InvalidOperationException>(() => new Shadowsocks2022InboundRuntimeState(
            method,
            serverKey,
            Shadowsocks2022InboundModes.MultiUser,
            [
                new Shadowsocks2022User
                {
                    UserId = "user-a",
                    Cipher = method,
                    Password = CreateShadowsocks2022Key(method, 32),
                    RuntimeKey = RuntimeUserKeys.Create(InboundProtocols.Shadowsocks, "ss-2022-entry", "user-a"),
                    BytesPerSecond = 0
                }
            ]));

        Assert.Equal(
            "Shadowsocks 2022 inbound requires empty per-user cipher in multi-user mode.",
            exception.Message);
    }

    [Fact]
    public void RuntimeState_rejects_shadowsocks_2022_relay_user_without_destination()
    {
        const string method = ShadowsocksCipherTypes.Blake3Aes128Gcm;
        var serverKey = CreateShadowsocks2022Key(method);

        var exception = Assert.Throws<InvalidOperationException>(() => new Shadowsocks2022InboundRuntimeState(
            method,
            serverKey,
            Shadowsocks2022InboundModes.Relay,
            [
                new Shadowsocks2022User
                {
                    UserId = "relay-a",
                    Password = CreateShadowsocks2022Key(method, 32),
                    RuntimeKey = RuntimeUserKeys.Create(InboundProtocols.Shadowsocks, "ss-2022-entry", "relay-a"),
                    BytesPerSecond = 0
                }
            ]));

        Assert.Equal("Shadowsocks 2022 relay inbound requires a valid relay destination.", exception.Message);
    }

    [Fact]
    public void RuntimeState_rejects_shadowsocks_2022_duplicate_managed_user_keys()
    {
        const string method = ShadowsocksCipherTypes.Blake3Aes128Gcm;
        var serverKey = CreateShadowsocks2022Key(method);
        var userKey = CreateShadowsocks2022Key(method, 32);

        var exception = Assert.Throws<InvalidOperationException>(() => new Shadowsocks2022InboundRuntimeState(
            method,
            serverKey,
            Shadowsocks2022InboundModes.MultiUser,
            [
                new Shadowsocks2022User
                {
                    UserId = "user-a",
                    Password = userKey,
                    RuntimeKey = RuntimeUserKeys.Create(InboundProtocols.Shadowsocks, "ss-2022-entry", "user-a"),
                    BytesPerSecond = 0
                },
                new Shadowsocks2022User
                {
                    UserId = "user-b",
                    Password = userKey,
                    RuntimeKey = RuntimeUserKeys.Create(InboundProtocols.Shadowsocks, "ss-2022-entry", "user-b"),
                    BytesPerSecond = 0
                }
            ]));

        Assert.Equal("Shadowsocks 2022 inbound contains duplicate per-user keys.", exception.Message);
    }

    [Fact]
    public void RuntimeState_rejects_shadowsocks_2022_single_user_with_multiple_users()
    {
        const string method = ShadowsocksCipherTypes.Blake3Aes128Gcm;
        var serverKey = CreateShadowsocks2022Key(method);

        var exception = Assert.Throws<InvalidOperationException>(() => new Shadowsocks2022InboundRuntimeState(
            method,
            serverKey,
            Shadowsocks2022InboundModes.SingleUser,
            [
                new Shadowsocks2022User
                {
                    UserId = "user-a",
                    Password = serverKey,
                    RuntimeKey = RuntimeUserKeys.Create(InboundProtocols.Shadowsocks, "ss-2022-entry", "user-a"),
                    BytesPerSecond = 0
                },
                new Shadowsocks2022User
                {
                    UserId = "user-b",
                    Password = serverKey,
                    RuntimeKey = RuntimeUserKeys.Create(InboundProtocols.Shadowsocks, "ss-2022-entry", "user-b"),
                    BytesPerSecond = 0
                }
            ]));

        Assert.Equal("Shadowsocks 2022 single-user inbound does not support multiple users.", exception.Message);
    }

    [Fact]
    public void RuntimeCapabilities_contains_shadowsocks_inbound()
        => Assert.Contains(InboundProtocols.Shadowsocks, RuntimeCapabilities.SupportedInboundProtocols);

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

    private static async Task<byte[]> CreateTcpClientPayloadAsync(
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

    private static async Task<byte[]> CreateTcp2022ClientPayloadAsync(
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

    private sealed record TestInboundDefinition : IShadowsocksInboundDefinition, IShadowsocksInboundScopeDefinition, IShadowsocks2022InboundScopeDefinition
    {
        public string Tag { get; init; } = string.Empty;

        public bool Enabled { get; init; }

        public string Protocol { get; init; } = InboundProtocols.Shadowsocks;

        public string ListenAddress { get; init; } = "0.0.0.0";

        public int Port { get; init; } = 8388;

        public int HandshakeTimeoutSeconds { get; init; } = 60;

        public string Security { get; init; } = ShadowsocksCipherTypes.Aes128Gcm;

        public string Password { get; init; } = string.Empty;

        public int UserLevel { get; init; }

        public IReadOnlyList<string> Networks { get; init; } = Array.Empty<string>();

        public IRuntimeSniffingDefinition Sniffing { get; init; } = RuntimeSniffingOptions.Disabled;

        public IReadOnlyList<IShadowsocksUserDefinition> Users { get; init; } = Array.Empty<IShadowsocksUserDefinition>();

        public IReadOnlyList<IShadowsocks2022UserDefinition> Users2022 { get; init; } = Array.Empty<IShadowsocks2022UserDefinition>();

        public IReadOnlyList<IShadowsocksUserDefinition> GetShadowsocksUsers() => Users;

        public IReadOnlyList<IShadowsocks2022UserDefinition> GetShadowsocks2022Users() => Users2022;

        public IRuntimeSniffingDefinition GetSniffing() => Sniffing;
    }

    private sealed record TestShadowsocksUser : IShadowsocksUserDefinition
    {
        public string UserId { get; init; } = string.Empty;

        public int Level { get; init; }

        public string Cipher { get; init; } = string.Empty;

        public string Password { get; init; } = string.Empty;

        public long BytesPerSecond { get; init; }

        public int DeviceLimit { get; init; }
    }

    private sealed record TestShadowsocks2022User : IShadowsocks2022UserDefinition
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
}

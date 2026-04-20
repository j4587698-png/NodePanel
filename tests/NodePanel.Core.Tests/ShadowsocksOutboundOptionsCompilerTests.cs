using NodePanel.Core.Runtime;

namespace NodePanel.Core.Tests;

public sealed class ShadowsocksOutboundOptionsCompilerTests
{
    [Fact]
    public void Compile_converts_legacy_container_with_2022_method_to_shadowsocks2022_options()
    {
        var compiled = ShadowsocksOutboundOptionsCompiler.Compile(
            new RuntimeShadowsocksOutboundOptions
            {
                Tag = " ss-edge ",
                ServerHost = " server.example.com ",
                ServerPort = 8388,
                Cipher = " 2022-blake3-aes-128-gcm ",
                Password = " secret-key ",
                UdpOverTcp = true,
                UdpOverTcpVersion = 2,
                ConnectTimeoutSeconds = 5
            });

        var shadowsocks2022 = Assert.IsType<RuntimeShadowsocks2022OutboundOptions>(compiled);
        Assert.Equal("ss-edge", shadowsocks2022.Tag);
        Assert.Equal("server.example.com", shadowsocks2022.ServerHost);
        Assert.Equal(8388, shadowsocks2022.ServerPort);
        Assert.Equal(ShadowsocksCipherTypes.Blake3Aes128Gcm, shadowsocks2022.Method);
        Assert.Equal("secret-key", shadowsocks2022.Key);
        Assert.True(shadowsocks2022.UdpOverTcp);
        Assert.Equal(2, shadowsocks2022.UdpOverTcpVersion);
        Assert.Equal(5, shadowsocks2022.ConnectTimeoutSeconds);
    }

    [Theory]
    [InlineData(" aes-256-gcm ", ShadowsocksCipherTypes.Aes256Gcm)]
    [InlineData(" aead_aes_256_gcm ", ShadowsocksCipherTypes.Aes256Gcm)]
    [InlineData(" plain ", ShadowsocksCipherTypes.None)]
    public void Compile_converts_2022_container_with_regular_method_to_legacy_options_and_ignores_uot(
        string method,
        string expectedCipher)
    {
        var compiled = ShadowsocksOutboundOptionsCompiler.Compile(
            new RuntimeShadowsocks2022OutboundOptions
            {
                Tag = " ss-edge ",
                ServerHost = " server.example.com ",
                ServerPort = 8388,
                Method = method,
                Key = " secret ",
                UdpOverTcp = true,
                UdpOverTcpVersion = 2,
                ConnectTimeoutSeconds = 5
            });

        var shadowsocks = Assert.IsType<RuntimeShadowsocksOutboundOptions>(compiled);
        Assert.Equal("ss-edge", shadowsocks.Tag);
        Assert.Equal("server.example.com", shadowsocks.ServerHost);
        Assert.Equal(8388, shadowsocks.ServerPort);
        Assert.Equal(expectedCipher, shadowsocks.Cipher);
        Assert.Equal("secret", shadowsocks.Password);
        Assert.False(shadowsocks.UdpOverTcp);
        Assert.Equal(0, shadowsocks.UdpOverTcpVersion);
        Assert.Equal(5, shadowsocks.ConnectTimeoutSeconds);
    }

    [Fact]
    public void RuntimeOutboundSettingsCatalog_create_canonicalizes_shadowsocks2022_entry()
    {
        var catalog = RuntimeOutboundSettingsCatalog.Create(
        [
            new RuntimeShadowsocksOutboundOptions
            {
                Tag = "ss-2022",
                ServerHost = "server.example.com",
                ServerPort = 8388,
                Cipher = ShadowsocksCipherTypes.Blake3Aes256Gcm,
                Password = Convert.ToBase64String(new byte[32])
            }
        ]);

        Assert.True(catalog.TryGetShadowsocks2022("ss-2022", out var shadowsocks2022));
        Assert.Equal(ShadowsocksCipherTypes.Blake3Aes256Gcm, shadowsocks2022.Method);
    }

    [Fact]
    public void RuntimeOutboundSettingsCatalog_create_rejects_invalid_port()
    {
        var exception = Assert.Throws<InvalidOperationException>(() => RuntimeOutboundSettingsCatalog.Create(
        [
            new RuntimeShadowsocksOutboundOptions
            {
                Tag = "ss-invalid-port",
                ServerHost = "server.example.com",
                ServerPort = 0,
                Cipher = ShadowsocksCipherTypes.Aes128Gcm,
                Password = "secret"
            }
        ]));

        Assert.Equal("Invalid Shadowsocks port.", exception.Message);
    }

    [Fact]
    public void RuntimeOutboundSettingsCatalog_create_rejects_missing_password_even_for_none_cipher()
    {
        var exception = Assert.Throws<InvalidOperationException>(() => RuntimeOutboundSettingsCatalog.Create(
        [
            new RuntimeShadowsocksOutboundOptions
            {
                Tag = "ss-none",
                ServerHost = "server.example.com",
                ServerPort = 8388,
                Cipher = ShadowsocksCipherTypes.None,
                Password = string.Empty
            }
        ]));

        Assert.Equal("Shadowsocks password is not specified.", exception.Message);
    }

    [Fact]
    public void RuntimeOutboundSettingsCatalog_create_rejects_unknown_cipher()
    {
        var exception = Assert.Throws<InvalidOperationException>(() => RuntimeOutboundSettingsCatalog.Create(
        [
            new RuntimeShadowsocksOutboundOptions
            {
                Tag = "ss-unknown",
                ServerHost = "server.example.com",
                ServerPort = 8388,
                Cipher = "demo-cipher",
                Password = "secret"
            }
        ]));

        Assert.Equal("unknown cipher method: demo-cipher", exception.Message);
    }
}

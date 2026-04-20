using System.Net.Quic;
using System.Net.Security;
using System.Runtime.Versioning;
using System.Security.Authentication;
using NodePanel.Core.Runtime;

namespace NodePanel.Core.Tests;

[SupportedOSPlatform("windows")]
[SupportedOSPlatform("linux")]
[SupportedOSPlatform("macos")]
public sealed class RuntimeQuicServerConnectionOptionsFactoryTests
{
    [Fact]
    public void Create_maps_tls_alpn_timeouts_windows_and_inbound_stream_capacity()
    {
        using var certificate = TestCertificateFactory.CreateSelfSignedServerCertificate("localhost", ["localhost"]);

        var connectionOptions = RuntimeQuicServerConnectionOptionsFactory.Create(
            ["h3"],
            new RuntimeTlsOptions
            {
                Certificate = certificate
            },
            new RuntimeQuicOptions
            {
                InitStreamReceiveWindow = 16_384,
                InitConnReceiveWindow = 32_768,
                MaxIdleTimeoutSeconds = 29,
                KeepAlivePeriodSeconds = 11,
                MaxIncomingStreams = 8
            });

        Assert.Equal(TimeSpan.FromSeconds(10), connectionOptions.HandshakeTimeout);
        Assert.Equal(TimeSpan.FromSeconds(29), connectionOptions.IdleTimeout);
        Assert.Equal(TimeSpan.FromSeconds(11), connectionOptions.KeepAliveInterval);
        Assert.Equal(8, connectionOptions.MaxInboundBidirectionalStreams);
        Assert.Equal(16, connectionOptions.MaxInboundUnidirectionalStreams);

        var authOptions = connectionOptions.ServerAuthenticationOptions;
        Assert.Equal(SslProtocols.Tls13, authOptions.EnabledSslProtocols);
        Assert.Equal(["h3"], authOptions.ApplicationProtocols!.Select(static protocol => protocol.ToString()).ToArray());

        var receiveWindowSizes = Assert.IsType<QuicReceiveWindowSizes>(connectionOptions.InitialReceiveWindowSizes);
        Assert.Equal(32_768, receiveWindowSizes.Connection);
        Assert.Equal(16_384, receiveWindowSizes.LocallyInitiatedBidirectionalStream);
        Assert.Equal(16_384, receiveWindowSizes.RemotelyInitiatedBidirectionalStream);
        Assert.Equal(16_384, receiveWindowSizes.UnidirectionalStream);
    }

    [Fact]
    public void Create_for_h3_defaults_idle_timeout_keepalive_and_unidirectional_stream_capacity()
    {
        using var certificate = TestCertificateFactory.CreateSelfSignedServerCertificate("localhost", ["localhost"]);

        var connectionOptions = RuntimeQuicServerConnectionOptionsFactory.Create(
            ["h3"],
            new RuntimeTlsOptions
            {
                Certificate = certificate
            },
            RuntimeQuicOptions.Empty);

        Assert.Equal(TimeSpan.FromSeconds(300), connectionOptions.IdleTimeout);
        Assert.Equal(TimeSpan.FromSeconds(10), connectionOptions.KeepAliveInterval);
        Assert.Equal(128, connectionOptions.MaxInboundBidirectionalStreams);
        Assert.Equal(16, connectionOptions.MaxInboundUnidirectionalStreams);
    }

    [Fact]
    public void Create_preserves_initial_receive_windows_when_initial_and_max_differ()
    {
        using var certificate = TestCertificateFactory.CreateSelfSignedServerCertificate("localhost", ["localhost"]);

        var connectionOptions = RuntimeQuicServerConnectionOptionsFactory.Create(
            ["h3"],
            new RuntimeTlsOptions
            {
                Certificate = certificate
            },
            new RuntimeQuicOptions
            {
                InitStreamReceiveWindow = 16_384,
                MaxStreamReceiveWindow = 65_536,
                InitConnReceiveWindow = 32_768,
                MaxConnReceiveWindow = 131_072
            });

        var receiveWindowSizes = Assert.IsType<QuicReceiveWindowSizes>(connectionOptions.InitialReceiveWindowSizes);
        Assert.Equal(32_768, receiveWindowSizes.Connection);
        Assert.Equal(16_384, receiveWindowSizes.LocallyInitiatedBidirectionalStream);
        Assert.Equal(16_384, receiveWindowSizes.RemotelyInitiatedBidirectionalStream);
        Assert.Equal(16_384, receiveWindowSizes.UnidirectionalStream);
    }

    [Fact]
    public void Create_uses_max_receive_windows_when_initial_values_are_not_configured()
    {
        using var certificate = TestCertificateFactory.CreateSelfSignedServerCertificate("localhost", ["localhost"]);

        var connectionOptions = RuntimeQuicServerConnectionOptionsFactory.Create(
            ["h3"],
            new RuntimeTlsOptions
            {
                Certificate = certificate
            },
            new RuntimeQuicOptions
            {
                MaxStreamReceiveWindow = 65_536,
                MaxConnReceiveWindow = 131_072
            });

        var receiveWindowSizes = Assert.IsType<QuicReceiveWindowSizes>(connectionOptions.InitialReceiveWindowSizes);
        Assert.Equal(131_072, receiveWindowSizes.Connection);
        Assert.Equal(65_536, receiveWindowSizes.LocallyInitiatedBidirectionalStream);
        Assert.Equal(65_536, receiveWindowSizes.RemotelyInitiatedBidirectionalStream);
        Assert.Equal(65_536, receiveWindowSizes.UnidirectionalStream);
    }

    [Fact]
    public void Create_rejects_too_small_receive_window()
    {
        using var certificate = TestCertificateFactory.CreateSelfSignedServerCertificate("localhost", ["localhost"]);

        var exception = Assert.Throws<ArgumentOutOfRangeException>(() => RuntimeQuicServerConnectionOptionsFactory.Create(
            ["h3"],
            new RuntimeTlsOptions
            {
                Certificate = certificate
            },
            new RuntimeQuicOptions
            {
                InitStreamReceiveWindow = 16_383
            }));

        Assert.Contains("receive window", exception.Message, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void Create_rejects_idle_timeout_outside_xray_range()
    {
        using var certificate = TestCertificateFactory.CreateSelfSignedServerCertificate("localhost", ["localhost"]);

        var exception = Assert.Throws<ArgumentOutOfRangeException>(() => RuntimeQuicServerConnectionOptionsFactory.Create(
            ["h3"],
            new RuntimeTlsOptions
            {
                Certificate = certificate
            },
            new RuntimeQuicOptions
            {
                MaxIdleTimeoutSeconds = 3
            }));

        Assert.Contains("MaxIdleTimeoutSeconds", exception.Message, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void Create_rejects_keepalive_outside_xray_range()
    {
        using var certificate = TestCertificateFactory.CreateSelfSignedServerCertificate("localhost", ["localhost"]);

        var exception = Assert.Throws<ArgumentOutOfRangeException>(() => RuntimeQuicServerConnectionOptionsFactory.Create(
            ["h3"],
            new RuntimeTlsOptions
            {
                Certificate = certificate
            },
            new RuntimeQuicOptions
            {
                KeepAlivePeriodSeconds = 61
            }));

        Assert.Contains("KeepAlivePeriodSeconds", exception.Message, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void Create_rejects_supported_congestion_value_when_runtime_cannot_apply_it()
    {
        using var certificate = TestCertificateFactory.CreateSelfSignedServerCertificate("localhost", ["localhost"]);

        var exception = Assert.Throws<NotSupportedException>(() => RuntimeQuicServerConnectionOptionsFactory.Create(
            ["h3"],
            new RuntimeTlsOptions
            {
                Certificate = certificate
            },
            new RuntimeQuicOptions
            {
                Congestion = " reNo "
            }));

        Assert.Contains("congestion", exception.Message, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void Create_rejects_disabling_path_mtu_discovery()
    {
        using var certificate = TestCertificateFactory.CreateSelfSignedServerCertificate("localhost", ["localhost"]);

        var exception = Assert.Throws<NotSupportedException>(() => RuntimeQuicServerConnectionOptionsFactory.Create(
            ["h3"],
            new RuntimeTlsOptions
            {
                Certificate = certificate
            },
            new RuntimeQuicOptions
            {
                DisablePathMtuDiscovery = true
            }));

        Assert.Contains("path MTU", exception.Message, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void Create_rejects_unsupported_udp_hop_configuration()
    {
        using var certificate = TestCertificateFactory.CreateSelfSignedServerCertificate("localhost", ["localhost"]);

        var exception = Assert.Throws<NotSupportedException>(() => RuntimeQuicServerConnectionOptionsFactory.Create(
            ["h3"],
            new RuntimeTlsOptions
            {
                Certificate = certificate
            },
            new RuntimeQuicOptions
            {
                UdpHop = new RuntimeUdpHopOptions
                {
                    Ports = [3000, 4000]
                }
            }));

        Assert.Contains("UDP hop", exception.Message, StringComparison.OrdinalIgnoreCase);
    }
}

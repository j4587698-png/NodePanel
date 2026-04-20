using Microsoft.Extensions.Configuration;
using NodePanel.ControlPlane.Configuration;
using NodePanel.Service.Configuration;

namespace NodePanel.Service.Tests;

public sealed class NodePanelOptionsLoaderTests
{
    [Fact]
    public void Load_merges_argument_overrides_and_parses_unified_bootstrap_config()
    {
        var configuration = new ConfigurationBuilder()
            .AddInMemoryCollection(new Dictionary<string, string?>
            {
                [$"{NodePanelOptions.SectionName}:{nameof(NodePanelOptions.CachedConfigPath)}"] = "runtime-cache.json",
                [$"{NodePanelOptions.SectionName}:{nameof(NodePanelOptions.PanelUrl)}"] = "wss://config-panel.example/ws",
                [$"{NodePanelOptions.SectionName}:{nameof(NodePanelOptions.Identity)}:{nameof(NodeIdentityOptions.NodeId)}"] = "config-node",
                [$"{NodePanelOptions.SectionName}:{nameof(NodePanelOptions.ControlPlane)}:{nameof(ControlPlaneOptions.Enabled)}"] = "false",
                [$"{NodePanelOptions.SectionName}:{nameof(NodePanelOptions.ControlPlane)}:{nameof(ControlPlaneOptions.AccessToken)}"] = "config-token",
                [$"{NodePanelOptions.SectionName}:{nameof(NodePanelOptions.ControlPlane)}:{nameof(ControlPlaneOptions.ConnectTimeoutSeconds)}"] = "21",
                [$"{NodePanelOptions.SectionName}:{nameof(NodePanelOptions.ControlPlane)}:{nameof(ControlPlaneOptions.HeartbeatIntervalSeconds)}"] = "31",
                [$"{NodePanelOptions.SectionName}:{nameof(NodePanelOptions.ControlPlane)}:{nameof(ControlPlaneOptions.ReconnectDelaySeconds)}"] = "7",
                [$"{NodePanelOptions.SectionName}:{nameof(NodePanelOptions.Bootstrap)}:{nameof(NodeServiceConfig.Inbounds)}:0:{nameof(InboundConfig.Tag)}"] = "vless-tls",
                [$"{NodePanelOptions.SectionName}:{nameof(NodePanelOptions.Bootstrap)}:{nameof(NodeServiceConfig.Inbounds)}:0:{nameof(InboundConfig.Enabled)}"] = "true",
                [$"{NodePanelOptions.SectionName}:{nameof(NodePanelOptions.Bootstrap)}:{nameof(NodeServiceConfig.Inbounds)}:0:{nameof(InboundConfig.Protocol)}"] = "vless",
                [$"{NodePanelOptions.SectionName}:{nameof(NodePanelOptions.Bootstrap)}:{nameof(NodeServiceConfig.Inbounds)}:0:{nameof(InboundConfig.Transport)}"] = "tls",
                [$"{NodePanelOptions.SectionName}:{nameof(NodePanelOptions.Bootstrap)}:{nameof(NodeServiceConfig.Inbounds)}:0:{nameof(InboundConfig.ListenAddress)}"] = "0.0.0.0",
                [$"{NodePanelOptions.SectionName}:{nameof(NodePanelOptions.Bootstrap)}:{nameof(NodeServiceConfig.Inbounds)}:0:{nameof(InboundConfig.Port)}"] = "443",
                [$"{NodePanelOptions.SectionName}:{nameof(NodePanelOptions.Bootstrap)}:{nameof(NodeServiceConfig.Certificate)}:{nameof(CertificateOptions.AltNames)}:0"] = "cdn.example.com",
                [$"{NodePanelOptions.SectionName}:{nameof(NodePanelOptions.Bootstrap)}:{nameof(NodeServiceConfig.Policy)}:{nameof(PolicyConfig.Level)}:1:{nameof(SessionLevelPolicyConfig.Timeout)}:{nameof(SessionTimeoutPolicyConfig.ConnectionIdle)}"] = "600",
                [$"{NodePanelOptions.SectionName}:{nameof(NodePanelOptions.Bootstrap)}:{nameof(NodeServiceConfig.Dns)}:{nameof(DnsOptions.Servers)}:0:{nameof(DnsHttpServerConfig.Url)}"] = "https://1.1.1.1/dns-query",
                [$"{NodePanelOptions.SectionName}:{nameof(NodePanelOptions.Bootstrap)}:{nameof(NodeServiceConfig.Dns)}:{nameof(DnsOptions.Servers)}:0:{nameof(DnsHttpServerConfig.Headers)}:Accept"] = "application/dns-json",
                [$"{NodePanelOptions.SectionName}:{nameof(NodePanelOptions.Bootstrap)}:{nameof(NodeServiceConfig.Telemetry)}:{nameof(TelemetryOptions.FlushIntervalSeconds)}"] = "9"
            })
            .Build();

        var options = NodePanelOptionsLoader.Load(
            configuration,
            [
                "--panel-url=wss://arg-panel.example/ws",
                "--node-id=arg-node",
                "--control-plane-access-token=arg-token"
            ]);

        Assert.Equal("wss://arg-panel.example/ws", options.PanelUrl);
        Assert.Equal("wss://arg-panel.example/ws", options.ControlPlane.Url);
        Assert.True(options.ControlPlane.Enabled);
        Assert.Equal("arg-token", options.ControlPlane.AccessToken);
        Assert.Equal("arg-node", options.Identity.NodeId);
        Assert.Equal("runtime-cache.json", options.CachedConfigPath);
        Assert.Equal(21, options.ControlPlane.ConnectTimeoutSeconds);
        Assert.Equal(31, options.ControlPlane.HeartbeatIntervalSeconds);
        Assert.Equal(7, options.ControlPlane.ReconnectDelaySeconds);

        var inbound = Assert.Single(options.Bootstrap.Inbounds);
        Assert.True(inbound.Enabled);
        Assert.Equal("vless", inbound.Protocol);
        Assert.Equal("tls", inbound.Transport);
        Assert.Equal(443, inbound.Port);
        Assert.Equal("0.0.0.0", inbound.ListenAddress);
        Assert.Equal(["cdn.example.com"], options.Bootstrap.Certificate.AltNames);
        Assert.Equal(600, options.Bootstrap.Policy.Level[1].Timeout.ConnectionIdle);

        var dnsServer = Assert.Single(options.Bootstrap.Dns.Servers);
        Assert.Equal("https://1.1.1.1/dns-query", dnsServer.Url);
        Assert.Equal("application/dns-json", dnsServer.Headers["Accept"]);
        Assert.Equal(9, options.Bootstrap.Telemetry.FlushIntervalSeconds);
    }

    [Fact]
    public void Load_uses_defaults_when_nodepanel_section_is_missing()
    {
        var configuration = new ConfigurationBuilder()
            .AddInMemoryCollection(new Dictionary<string, string?>())
            .Build();

        var options = NodePanelOptionsLoader.Load(configuration, []);

        Assert.Equal(string.Empty, options.PanelUrl);
        Assert.Equal("node-runtime-config.json", options.CachedConfigPath);
        Assert.True(options.ControlPlane.Enabled);
        Assert.Equal(string.Empty, options.ControlPlane.Url);
        Assert.Equal(string.Empty, options.ControlPlane.AccessToken);
        Assert.Empty(options.Bootstrap.Inbounds);
    }
}

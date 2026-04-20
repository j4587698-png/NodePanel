using System.Net;
using NodePanel.Core.Runtime;

namespace NodePanel.Core.Tests;

public sealed class DokodemoInboundRuntimeTests
{
    [Fact]
    public void RuntimeCapabilities_contains_dokodemo_door_inbound()
        => Assert.Contains(InboundProtocols.DokodemoDoor, RuntimeCapabilities.SupportedInboundProtocols);

    [Fact]
    public void DokodemoInboundRuntimePlanner_accepts_udp_network_when_follow_redirect_is_disabled()
    {
        var result = DokodemoInboundRuntimePlanner.TryBuild(
        [
            new TestDokodemoInboundDefinition
            {
                Tag = "dokodemo",
                ListenAddress = "127.0.0.1",
                Port = 12345,
                Networks = [RoutingNetworks.Udp]
            }
        ],
            out var plan,
            out var error);

        Assert.True(result);
        Assert.Null(error);

        var inbound = Assert.Single(plan.Inbounds);
        Assert.True(inbound.HasUdp);
        Assert.False(inbound.HasTcp);
    }

    [Fact]
    public void DokodemoInboundRuntimePlanner_accepts_tunnel_alias_and_preserves_user_level_and_mark()
    {
        var result = DokodemoInboundRuntimePlanner.TryBuild(
        [
            new TestDokodemoInboundDefinition
            {
                Tag = "dokodemo",
                Protocol = " TUNNEL ",
                ListenAddress = "127.0.0.1",
                Port = 12345,
                Networks = [RoutingNetworks.Udp],
                FollowRedirect = true,
                UserLevel = 7,
                Mark = 101
            }
        ],
            out var plan,
            out var error);

        Assert.True(result);
        Assert.Null(error);

        var inbound = Assert.Single(plan.Inbounds);
        Assert.True(inbound.HasUdp);
        Assert.True(inbound.FollowRedirect);
        Assert.Equal(7, inbound.UserLevel);
        Assert.Equal(101, inbound.Mark);
    }

    [Fact]
    public void DokodemoInboundDestinationResolver_uses_loopback_and_listener_port_when_destination_is_empty()
    {
        var destination = DokodemoInboundDestinationResolver.Resolve(
            new DokodemoInboundSessionOptions
            {
                InboundTag = "dokodemo",
                Network = RoutingNetworks.Tcp,
                LocalEndPoint = new IPEndPoint(IPAddress.Any, 18080)
            });

        Assert.Equal("127.0.0.1", destination.Host);
        Assert.Equal(18080, destination.Port);
        Assert.Equal(DispatchNetwork.Tcp, destination.Network);
    }

    [Fact]
    public void DokodemoInboundDestinationResolver_applies_port_map_override_when_follow_redirect_is_disabled()
    {
        var destination = DokodemoInboundDestinationResolver.Resolve(
            new DokodemoInboundSessionOptions
            {
                InboundTag = "dokodemo",
                Network = RoutingNetworks.Tcp,
                DestinationHost = "example.org",
                DestinationPort = 443,
                LocalEndPoint = new IPEndPoint(IPAddress.Loopback, 10000),
                PortMap = new Dictionary<string, string>(StringComparer.Ordinal)
                {
                    ["10000"] = "127.0.0.1:8443"
                }
            });

        Assert.Equal("127.0.0.1", destination.Host);
        Assert.Equal(8443, destination.Port);
    }

    [Fact]
    public void DokodemoInboundDestinationResolver_uses_original_destination_when_follow_redirect_is_enabled()
    {
        var destination = DokodemoInboundDestinationResolver.Resolve(
            new DokodemoInboundSessionOptions
            {
                InboundTag = "dokodemo",
                Network = RoutingNetworks.Tcp,
                DestinationHost = "example.org",
                DestinationPort = 80,
                FollowRedirect = true,
                OriginalDestinationEndPoint = new IPEndPoint(IPAddress.Parse("203.0.113.7"), 8443),
                LocalEndPoint = new IPEndPoint(IPAddress.Loopback, 10000),
                PortMap = new Dictionary<string, string>(StringComparer.Ordinal)
                {
                    ["10000"] = "127.0.0.1:9443"
                }
            });

        Assert.Equal("203.0.113.7", destination.Host);
        Assert.Equal(8443, destination.Port);
    }

    [Fact]
    public void DokodemoInboundDestinationResolver_applies_port_map_override_for_udp_destination()
    {
        var destination = DokodemoInboundDestinationResolver.Resolve(
            new DokodemoInboundSessionOptions
            {
                InboundTag = "dokodemo",
                Network = RoutingNetworks.Udp,
                DestinationHost = "example.org",
                DestinationPort = 53,
                LocalEndPoint = new IPEndPoint(IPAddress.Loopback, 10000),
                PortMap = new Dictionary<string, string>(StringComparer.Ordinal)
                {
                    ["10000"] = "127.0.0.1:5353"
                }
            });

        Assert.Equal("127.0.0.1", destination.Host);
        Assert.Equal(5353, destination.Port);
        Assert.Equal(DispatchNetwork.Udp, destination.Network);
    }

    private sealed record TestDokodemoInboundDefinition : IDokodemoInboundDefinition
    {
        public string Tag { get; init; } = string.Empty;

        public bool Enabled { get; init; } = true;

        public string Protocol { get; init; } = InboundProtocols.DokodemoDoor;

        public string ListenAddress { get; init; } = string.Empty;

        public int Port { get; init; }

        public string DestinationHost { get; init; } = string.Empty;

        public int DestinationPort { get; init; }

        public IReadOnlyDictionary<string, string> PortMap { get; init; }
            = new Dictionary<string, string>(StringComparer.Ordinal);

        public int UserLevel { get; init; }

        public int Mark { get; init; }

        public IReadOnlyList<string> Networks { get; init; } = [RoutingNetworks.Tcp];

        public bool FollowRedirect { get; init; }

        public IRuntimeSniffingDefinition Sniffing { get; init; } = RuntimeSniffingOptions.Disabled;
    }
}

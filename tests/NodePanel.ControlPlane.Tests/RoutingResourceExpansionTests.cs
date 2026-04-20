using System.Net;
using System.Text;
using NodePanel.ControlPlane.Configuration;
using NodePanel.ControlPlane.Runtime;
using NodePanel.Core.Runtime;

namespace NodePanel.ControlPlane.Tests;

public sealed class RoutingResourceExpansionTests
{
    [Fact]
    public void TryBuild_expands_geosite_and_geoip_resources()
    {
        var directory = CreateTempDirectory();
        try
        {
            var geoSitePath = Path.Combine(directory, "geosite.dat");
            var geoIpPath = Path.Combine(directory, "geoip.dat");
            WriteGeoSiteDat(
                geoSitePath,
                new GeoSiteEntry(
                    "CN",
                    [
                        new GeoDomainEntry(2, "ads.example.cn", ["ads"]),
                        new GeoDomainEntry(2, "plain.example.cn", Array.Empty<string>())
                    ]));
            WriteGeoIpDat(
                geoIpPath,
                new GeoIpEntry(
                    "US",
                    [new GeoCidrEntry("203.0.113.0", 24)]));

            var builder = new NodeRuntimeSnapshotBuilder(
            [
                new TrojanInboundRuntimeCompiler()
            ]);

            var success = builder.TryBuild(
                1,
                new NodeServiceConfig
                {
                    RoutingResources = new RoutingResourceOptions
                    {
                        GeoSitePath = geoSitePath,
                        GeoIpPath = geoIpPath
                    },
                    Outbounds =
                    [
                        new OutboundConfig
                        {
                            Tag = "direct",
                            Enabled = true,
                            Protocol = OutboundProtocols.Freedom
                        },
                        new OutboundConfig
                        {
                            Tag = "resource-route",
                            Enabled = true,
                            Protocol = OutboundProtocols.Freedom
                        }
                    ],
                    RoutingRules =
                    [
                        new RoutingRuleConfig
                        {
                            OutboundTag = " resource-route ",
                            Domains = [" geosite:cn@ads "],
                            DestinationCidrs = [" geoip:!us "]
                        }
                    ]
                },
                [OutboundProtocols.Freedom],
                out var snapshot,
                out var error);

            Assert.True(success, error);

            var normalizedRule = Assert.Single(snapshot.Config.RoutingRules);
            Assert.Equal(["domain:ads.example.cn"], normalizedRule.Domains);
            Assert.Equal(["!203.0.113.0/24"], normalizedRule.DestinationCidrs);

            Assert.True(snapshot.Plan.Outbound.TryResolveOutboundTag(
                new DispatchContext
                {
                    DetectedDomain = "api.ads.example.cn",
                    TargetAddresses = [IPAddress.Parse("198.51.100.7")]
                },
                out var matchedTag));
            Assert.Equal("resource-route", matchedTag);

            Assert.True(snapshot.Plan.Outbound.TryResolveOutboundTag(
                new DispatchContext
                {
                    DetectedDomain = "api.ads.example.cn",
                    TargetAddresses = [IPAddress.Parse("203.0.113.7")]
                },
                out var fallbackTag));
            Assert.Equal("direct", fallbackTag);
        }
        finally
        {
            Directory.Delete(directory, recursive: true);
        }
    }

    [Fact]
    public void TryBuild_expands_external_geosite_and_geoip_resources_from_resource_directory()
    {
        var directory = CreateTempDirectory();
        try
        {
            var domainFile = Path.Combine(directory, "custom-sites.dat");
            var ipFile = Path.Combine(directory, "custom-ip.dat");
            WriteGeoSiteDat(
                domainFile,
                new GeoSiteEntry(
                    "US",
                    [
                        new GeoDomainEntry(3, "video.example.com", ["stream"]),
                        new GeoDomainEntry(2, "ignored.example.com", Array.Empty<string>())
                    ]));
            WriteGeoIpDat(
                ipFile,
                new GeoIpEntry(
                    "US",
                    [new GeoCidrEntry("198.51.100.0", 24)]));

            var builder = new NodeRuntimeSnapshotBuilder(
            [
                new TrojanInboundRuntimeCompiler()
            ]);

            var success = builder.TryBuild(
                2,
                new NodeServiceConfig
                {
                    RoutingResources = new RoutingResourceOptions
                    {
                        ResourceDirectory = directory
                    },
                    Outbounds =
                    [
                        new OutboundConfig
                        {
                            Tag = "direct",
                            Enabled = true,
                            Protocol = OutboundProtocols.Freedom
                        },
                        new OutboundConfig
                        {
                            Tag = "ext-route",
                            Enabled = true,
                            Protocol = OutboundProtocols.Freedom
                        }
                    ],
                    RoutingRules =
                    [
                        new RoutingRuleConfig
                        {
                            OutboundTag = " ext-route ",
                            Domains = [" ext-domain:custom-sites.dat:us@stream "],
                            DestinationCidrs = [" ext-ip:custom-ip.dat:us "]
                        }
                    ]
                },
                [OutboundProtocols.Freedom],
                out var snapshot,
                out var error);

            Assert.True(success, error);

            var normalizedRule = Assert.Single(snapshot.Config.RoutingRules);
            Assert.Equal(["full:video.example.com"], normalizedRule.Domains);
            Assert.Equal(["198.51.100.0/24"], normalizedRule.DestinationCidrs);

            Assert.True(snapshot.Plan.Outbound.TryResolveOutboundTag(
                new DispatchContext
                {
                    DetectedDomain = "video.example.com",
                    TargetAddresses = [IPAddress.Parse("198.51.100.9")]
                },
                out var matchedTag));
            Assert.Equal("ext-route", matchedTag);

            Assert.True(snapshot.Plan.Outbound.TryResolveOutboundTag(
                new DispatchContext
                {
                    DetectedDomain = "video.example.com",
                    TargetAddresses = [IPAddress.Parse("203.0.113.9")]
                },
                out var fallbackTag));
            Assert.Equal("direct", fallbackTag);
        }
        finally
        {
            Directory.Delete(directory, recursive: true);
        }
    }

    private static string CreateTempDirectory()
    {
        var path = Path.Combine(Path.GetTempPath(), "NodePanel-RoutingResources-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(path);
        return path;
    }

    private static void WriteGeoSiteDat(string path, params GeoSiteEntry[] entries)
        => File.WriteAllBytes(path, EncodeGeoSiteList(entries));

    private static void WriteGeoIpDat(string path, params GeoIpEntry[] entries)
        => File.WriteAllBytes(path, EncodeGeoIpList(entries));

    private static byte[] EncodeGeoSiteList(IReadOnlyList<GeoSiteEntry> entries)
    {
        var buffer = new List<byte>();
        foreach (var entry in entries)
        {
            WriteMessageField(buffer, 1, EncodeGeoSite(entry));
        }

        return buffer.ToArray();
    }

    private static byte[] EncodeGeoIpList(IReadOnlyList<GeoIpEntry> entries)
    {
        var buffer = new List<byte>();
        foreach (var entry in entries)
        {
            WriteMessageField(buffer, 1, EncodeGeoIp(entry));
        }

        return buffer.ToArray();
    }

    private static byte[] EncodeGeoSite(GeoSiteEntry entry)
    {
        var buffer = new List<byte>();
        WriteStringField(buffer, 1, entry.CountryCode);
        foreach (var domain in entry.Domains)
        {
            WriteMessageField(buffer, 2, EncodeGeoDomain(domain));
        }

        return buffer.ToArray();
    }

    private static byte[] EncodeGeoDomain(GeoDomainEntry entry)
    {
        var buffer = new List<byte>();
        WriteVarintField(buffer, 1, (ulong)entry.Type);
        WriteStringField(buffer, 2, entry.Value);
        foreach (var attribute in entry.Attributes)
        {
            WriteMessageField(buffer, 3, EncodeGeoDomainAttribute(attribute));
        }

        return buffer.ToArray();
    }

    private static byte[] EncodeGeoDomainAttribute(string attribute)
    {
        var buffer = new List<byte>();
        WriteStringField(buffer, 1, attribute);
        return buffer.ToArray();
    }

    private static byte[] EncodeGeoIp(GeoIpEntry entry)
    {
        var buffer = new List<byte>();
        WriteStringField(buffer, 1, entry.CountryCode);
        foreach (var cidr in entry.Cidrs)
        {
            WriteMessageField(buffer, 2, EncodeGeoCidr(cidr));
        }

        return buffer.ToArray();
    }

    private static byte[] EncodeGeoCidr(GeoCidrEntry entry)
    {
        var buffer = new List<byte>();
        WriteBytesField(buffer, 1, IPAddress.Parse(entry.Address).GetAddressBytes());
        WriteVarintField(buffer, 2, (ulong)entry.PrefixLength);
        return buffer.ToArray();
    }

    private static void WriteVarintField(List<byte> buffer, int fieldNumber, ulong value)
    {
        WriteVarint(buffer, ((ulong)fieldNumber << 3) | 0UL);
        WriteVarint(buffer, value);
    }

    private static void WriteStringField(List<byte> buffer, int fieldNumber, string value)
        => WriteBytesField(buffer, fieldNumber, Encoding.UTF8.GetBytes(value));

    private static void WriteBytesField(List<byte> buffer, int fieldNumber, byte[] value)
    {
        WriteVarint(buffer, ((ulong)fieldNumber << 3) | 2UL);
        WriteVarint(buffer, (ulong)value.Length);
        buffer.AddRange(value);
    }

    private static void WriteMessageField(List<byte> buffer, int fieldNumber, byte[] payload)
        => WriteBytesField(buffer, fieldNumber, payload);

    private static void WriteVarint(List<byte> buffer, ulong value)
    {
        while (value >= 0x80)
        {
            buffer.Add((byte)((value & 0x7FUL) | 0x80UL));
            value >>= 7;
        }

        buffer.Add((byte)value);
    }

    private sealed record GeoSiteEntry(string CountryCode, IReadOnlyList<GeoDomainEntry> Domains);

    private sealed record GeoDomainEntry(int Type, string Value, IReadOnlyList<string> Attributes);

    private sealed record GeoIpEntry(string CountryCode, IReadOnlyList<GeoCidrEntry> Cidrs);

    private sealed record GeoCidrEntry(string Address, int PrefixLength);
}

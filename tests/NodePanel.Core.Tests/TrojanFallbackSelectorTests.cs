using System.Text;
using NodePanel.Core.Runtime;

namespace NodePanel.Core.Tests;

public sealed class TrojanFallbackSelectorTests
{
    [Fact]
    public void Select_uses_global_default_when_named_path_does_not_match()
    {
        var selected = TrojanFallbackSelector.Select(
            new[]
            {
                CreateFallback(dest: "127.0.0.1:7000"),
                CreateFallback(name: "example.com", path: "/api", dest: "127.0.0.1:7001")
            },
            "api.example.com",
            "http/1.1",
            CreateHttpRequest("/other"));

        Assert.NotNull(selected);
        Assert.Equal("127.0.0.1:7000", selected!.Dest);
    }

    [Fact]
    public void Select_prefers_longest_partial_server_name_match()
    {
        var selected = TrojanFallbackSelector.Select(
            new[]
            {
                CreateFallback(dest: "127.0.0.1:7000"),
                CreateFallback(name: "example.com", dest: "127.0.0.1:7001"),
                CreateFallback(name: "api.example.com", dest: "127.0.0.1:7002")
            },
            "foo.api.example.com",
            string.Empty,
            CreateHttpRequest("/"));

        Assert.NotNull(selected);
        Assert.Equal("127.0.0.1:7002", selected!.Dest);
    }

    [Fact]
    public void Select_inherits_empty_alpn_path_rules_into_specific_alpn()
    {
        var selected = TrojanFallbackSelector.Select(
            new[]
            {
                CreateFallback(name: "example.com", dest: "127.0.0.1:7001"),
                CreateFallback(name: "example.com", alpn: "h2", path: "/grpc", dest: "127.0.0.1:7002")
            },
            "example.com",
            "h2",
            CreateHttpRequest("/healthz"));

        Assert.NotNull(selected);
        Assert.Equal("127.0.0.1:7001", selected!.Dest);
    }

    private static TestTrojanFallback CreateFallback(
        string name = "",
        string alpn = "",
        string path = "",
        string type = "tcp",
        string dest = "127.0.0.1:7000",
        int proxyProtocolVersion = 0)
        => new()
        {
            Name = name,
            Alpn = alpn,
            Path = path,
            Type = type,
            Dest = dest,
            ProxyProtocolVersion = proxyProtocolVersion
        };

    private static byte[] CreateHttpRequest(string path)
        => Encoding.ASCII.GetBytes(
            $"GET {path} HTTP/1.1\r\nHost: example.com\r\nConnection: close\r\n\r\n");
}

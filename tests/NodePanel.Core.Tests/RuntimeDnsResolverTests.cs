using System.Net;
using System.Net.Http;
using System.Net.Sockets;
using System.Text;
using NodePanel.Core.Runtime;

namespace NodePanel.Core.Tests;

public sealed class RuntimeDnsResolverTests
{
    [Fact]
    public async Task ResolveAsync_uses_http_dns_and_caches_successful_results()
    {
        var handler = new RecordingHttpMessageHandler(request =>
        {
            var uri = request.RequestUri?.ToString() ?? string.Empty;
            var payload = uri.EndsWith("type=A", StringComparison.Ordinal)
                ? """
                  {
                    "Answer": [
                      {
                        "type": 1,
                        "data": "203.0.113.10"
                      }
                    ]
                  }
                  """
                : """
                  {
                    "Answer": [
                      {
                        "type": 28,
                        "data": "2001:db8::10"
                      }
                    ]
                  }
                  """;

            return new HttpResponseMessage(HttpStatusCode.OK)
            {
                Content = new StringContent(payload, Encoding.UTF8, "application/json")
            };
        });

        using var httpClient = new HttpClient(handler)
        {
            Timeout = Timeout.InfiniteTimeSpan
        };
        var resolver = new RuntimeDnsResolver(
            new FixedDnsRuntimeSettingsProvider(
                new DnsRuntimeSettings
                {
                    Mode = DnsModes.Http,
                    TimeoutSeconds = 5,
                    CacheTtlSeconds = 60,
                    Servers =
                    [
                        new DnsHttpServerRuntime
                        {
                            Url = "https://dns.example/resolve"
                        }
                    ]
                }),
            httpClient);

        var first = await resolver.ResolveAsync("edge.example.com", CancellationToken.None);
        var second = await resolver.ResolveAsync("edge.example.com", CancellationToken.None);

        Assert.Equal(["203.0.113.10", "2001:db8::10"], first.Select(static address => address.ToString()).ToArray());
        Assert.Equal(["203.0.113.10", "2001:db8::10"], second.Select(static address => address.ToString()).ToArray());
        Assert.Equal(2, handler.RequestUris.Count);
        Assert.Contains(handler.RequestUris, static uri => uri.Contains("name=edge.example.com", StringComparison.Ordinal));
        Assert.Contains(handler.RequestUris, static uri => uri.EndsWith("type=A", StringComparison.Ordinal));
        Assert.Contains(handler.RequestUris, static uri => uri.EndsWith("type=AAAA", StringComparison.Ordinal));
    }

    [Fact]
    public async Task LookupAsync_preserves_http_dns_ttl_and_queries_only_requested_family()
    {
        var handler = new RecordingHttpMessageHandler(static request =>
        {
            var uri = request.RequestUri?.ToString() ?? string.Empty;
            Assert.EndsWith("type=A", uri, StringComparison.Ordinal);

            return new HttpResponseMessage(HttpStatusCode.OK)
            {
                Content = new StringContent(
                    """
                    {
                      "Status": 0,
                      "Answer": [
                        {
                          "type": 1,
                          "TTL": 123,
                          "data": "203.0.113.20"
                        }
                      ]
                    }
                    """,
                    Encoding.UTF8,
                    "application/json")
            };
        });

        using var httpClient = new HttpClient(handler)
        {
            Timeout = Timeout.InfiniteTimeSpan
        };
        var resolver = new RuntimeDnsResolver(
            new FixedDnsRuntimeSettingsProvider(
                new DnsRuntimeSettings
                {
                    Mode = DnsModes.Http,
                    Servers =
                    [
                        new DnsHttpServerRuntime
                        {
                            Url = "https://dns.example/resolve"
                        }
                    ]
                }),
            httpClient);

        var result = await resolver.LookupAsync(
            "ttl.example",
            new DnsLookupOptions
            {
                IPv4Enable = true,
                IPv6Enable = false
            },
            CancellationToken.None);

        var address = Assert.Single(result.Addresses);
        Assert.Equal(IPAddress.Parse("203.0.113.20"), address);
        Assert.Equal(123u, result.TtlSeconds);
        Assert.False(result.IsEmptyResponse);
        Assert.Equal(DnsResponseCodes.Success, result.ResponseCode);
        Assert.Single(handler.RequestUris);
    }

    [Fact]
    public async Task LookupAsync_returns_empty_response_when_http_dns_has_no_answers()
    {
        var handler = new RecordingHttpMessageHandler(static _ => new HttpResponseMessage(HttpStatusCode.OK)
        {
            Content = new StringContent(
                """
                {
                  "Status": 0,
                  "Answer": []
                }
                """,
                Encoding.UTF8,
                "application/json")
        });

        using var httpClient = new HttpClient(handler)
        {
            Timeout = Timeout.InfiniteTimeSpan
        };
        var resolver = new RuntimeDnsResolver(
            new FixedDnsRuntimeSettingsProvider(
                new DnsRuntimeSettings
                {
                    Mode = DnsModes.Http,
                    Servers =
                    [
                        new DnsHttpServerRuntime
                        {
                            Url = "https://dns.example/resolve"
                        }
                    ]
                }),
            httpClient);

        var result = await resolver.LookupAsync(
            "empty.example",
            new DnsLookupOptions
            {
                IPv4Enable = true,
                IPv6Enable = false
            },
            CancellationToken.None);

        Assert.Empty(result.Addresses);
        Assert.True(result.IsEmptyResponse);
        Assert.Equal(DnsResponseCodes.Success, result.ResponseCode);
    }

    [Fact]
    public async Task LookupAsync_returns_dns_response_code_when_http_dns_status_is_nonzero()
    {
        var handler = new RecordingHttpMessageHandler(static _ => new HttpResponseMessage(HttpStatusCode.OK)
        {
            Content = new StringContent(
                """
                {
                  "Status": 3
                }
                """,
                Encoding.UTF8,
                "application/json")
        });

        using var httpClient = new HttpClient(handler)
        {
            Timeout = Timeout.InfiniteTimeSpan
        };
        var resolver = new RuntimeDnsResolver(
            new FixedDnsRuntimeSettingsProvider(
                new DnsRuntimeSettings
                {
                    Mode = DnsModes.Http,
                    Servers =
                    [
                        new DnsHttpServerRuntime
                        {
                            Url = "https://dns.example/resolve"
                        }
                    ]
                }),
            httpClient);

        var result = await resolver.LookupAsync(
            "missing.example",
            new DnsLookupOptions
            {
                IPv4Enable = true,
                IPv6Enable = false
            },
            CancellationToken.None);

        Assert.Equal(DnsResponseCodes.NameError, result.ResponseCode);
        Assert.False(result.IsEmptyResponse);
        Assert.Empty(result.Addresses);
    }

    [Fact]
    public async Task LookupAsync_returns_fake_ip_when_fake_dns_is_enabled()
    {
        var settingsProvider = new FixedDnsRuntimeSettingsProvider(
            new DnsRuntimeSettings
            {
                FakeDnsPools =
                [
                    new FakeDnsPoolRuntime
                    {
                        IpPool = FakeDnsDefaults.IPv4Pool,
                        LruSize = 256
                    },
                    new FakeDnsPoolRuntime
                    {
                        IpPool = FakeDnsDefaults.IPv6Pool,
                        LruSize = 256
                    }
                ]
            });
        var fakeDnsEngine = new RuntimeFakeDnsEngine(settingsProvider);
        var resolver = new RuntimeDnsResolver(
            settingsProvider,
            fakeDnsEngine: fakeDnsEngine);

        var result = await resolver.LookupAsync(
            "fake.example",
            new DnsLookupOptions
            {
                IPv4Enable = true,
                IPv6Enable = false,
                FakeEnable = true
            },
            CancellationToken.None);

        var address = Assert.Single(result.Addresses);
        Assert.Equal(AddressFamily.InterNetwork, address.AddressFamily);
        Assert.True(fakeDnsEngine.IsIPInPool(address));
        Assert.Equal("fake.example", fakeDnsEngine.GetDomainFromFakeDns(address));
        Assert.Equal(FakeDnsDefaults.DefaultTtlSeconds, result.TtlSeconds);
        Assert.True(result.IsFakeResponse);
        Assert.False(result.IsEmptyResponse);
        Assert.Equal(DnsResponseCodes.Success, result.ResponseCode);
    }

    [Fact]
    public async Task ResolveAsync_uses_real_dns_when_fake_dns_is_not_explicitly_enabled()
    {
        var handler = new RecordingHttpMessageHandler(static request =>
        {
            var uri = request.RequestUri?.ToString() ?? string.Empty;
            var payload = uri.EndsWith("type=A", StringComparison.Ordinal)
                ? """
                  {
                    "Status": 0,
                    "Answer": [
                      {
                        "type": 1,
                        "TTL": 60,
                        "data": "203.0.113.30"
                      }
                    ]
                  }
                  """
                : """
                  {
                    "Status": 0,
                    "Answer": []
                  }
                  """;

            return new HttpResponseMessage(HttpStatusCode.OK)
            {
                Content = new StringContent(payload, Encoding.UTF8, "application/json")
            };
        });

        using var httpClient = new HttpClient(handler)
        {
            Timeout = Timeout.InfiniteTimeSpan
        };
        var settingsProvider = new FixedDnsRuntimeSettingsProvider(
            new DnsRuntimeSettings
            {
                Mode = DnsModes.Http,
                Servers =
                [
                    new DnsHttpServerRuntime
                    {
                        Url = "https://dns.example/resolve"
                    }
                ],
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
        var resolver = new RuntimeDnsResolver(
            settingsProvider,
            httpClient,
            fakeDnsEngine);

        var result = await resolver.ResolveAsync("real.example", CancellationToken.None);

        var address = Assert.Single(result);
        Assert.Equal(IPAddress.Parse("203.0.113.30"), address);
        Assert.Null(fakeDnsEngine.GetDomainFromFakeDns(address));
        Assert.Equal(2, handler.RequestUris.Count);
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

    private sealed class RecordingHttpMessageHandler : HttpMessageHandler
    {
        private readonly Func<HttpRequestMessage, HttpResponseMessage> _responseFactory;

        public RecordingHttpMessageHandler(Func<HttpRequestMessage, HttpResponseMessage> responseFactory)
        {
            _responseFactory = responseFactory;
        }

        public List<string> RequestUris { get; } = [];

        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            RequestUris.Add(request.RequestUri?.ToString() ?? string.Empty);
            return Task.FromResult(_responseFactory(request));
        }
    }
}

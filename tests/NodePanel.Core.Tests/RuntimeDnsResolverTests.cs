using System.Net;
using System.Net.Http;
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

using System.Linq;
using NodePanel.Core.Runtime;

namespace NodePanel.Core.Tests;

public sealed class RuntimeRealityOptionsTests
{
    [Fact]
    public void TryValidateForReality_accepts_empty_fingerprint_like_xray_core_default()
    {
        var options = CreateValidOptions();

        var valid = options.TryValidateForReality(out var normalized, out var error);

        Assert.True(valid, error);
        Assert.Equal(string.Empty, normalized.Fingerprint);
        Assert.Equal("/", normalized.SpiderX);
    }

    [Fact]
    public void TryValidateForReality_accepts_known_xray_core_fingerprint()
    {
        var options = CreateValidOptions("hellochrome_120");

        var valid = options.TryValidateForReality(out var normalized, out var error);

        Assert.True(valid, error);
        Assert.Equal("hellochrome_120", normalized.Fingerprint);
    }

    [Fact]
    public void TryValidateForReality_rejects_unknown_fingerprint()
    {
        var options = CreateValidOptions("not-a-real-fingerprint");

        var valid = options.TryValidateForReality(out _, out var error);

        Assert.False(valid);
        Assert.Contains("unknown", error, StringComparison.OrdinalIgnoreCase);
    }

    [Theory]
    [InlineData("hellochrome_133")]
    [InlineData("hellofirefox_148")]
    [InlineData("hellosafari_26_3")]
    public void TryValidateForReality_rejects_fingerprints_not_exposed_by_local_xray_core(string fingerprint)
    {
        var options = CreateValidOptions(fingerprint);

        var valid = options.TryValidateForReality(out _, out var error);

        Assert.False(valid);
        Assert.Contains("unknown", error, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task SecureAsync_rejects_unknown_fingerprint_even_without_external_config_compiler()
    {
        var exception = await Assert.ThrowsAsync<NotSupportedException>(() =>
            RuntimeRealityHandshakeProviders.Default.SecureAsync(
                new RuntimeRealityHandshakeRequest
                {
                    TransportStream = Stream.Null,
                    ServerHost = "127.0.0.1",
                    ServerName = "edge.example.com",
                    TransportProtocol = RuntimeInternetTransportProtocols.Grpc,
                    ApplicationProtocols = ["h2"],
                    RealityOptions = CreateValidOptions("not-a-real-fingerprint")
                },
                CancellationToken.None).AsTask());

        Assert.Contains("unknown", exception.Message, StringComparison.OrdinalIgnoreCase);
    }

    [Theory]
    [InlineData("unsafe")]
    [InlineData("hellogolang")]
    public void TryValidateForReality_rejects_fingerprints_blocked_by_xray_core(string fingerprint)
    {
        var options = CreateValidOptions(fingerprint);

        var valid = options.TryValidateForReality(out _, out var error);

        Assert.False(valid);
        Assert.Contains("does not support", error, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void Normalize_trims_master_key_log_and_preserves_show()
    {
        var normalized = new RuntimeRealityOptions
        {
            Show = true,
            MasterKeyLog = "  logs/reality.keys  ",
            PublicKey = ToBase64Url(Enumerable.Range(1, 32).Select(static value => (byte)value).ToArray())
        }.Normalize();

        Assert.True(normalized.Show);
        Assert.Equal("logs/reality.keys", normalized.MasterKeyLog);
    }

    [Fact]
    public void Normalize_treats_none_master_key_log_as_empty_like_xray_core()
    {
        var normalized = new RuntimeRealityOptions
        {
            MasterKeyLog = "  NoNe  "
        }.Normalize();

        Assert.Equal(string.Empty, normalized.MasterKeyLog);
        Assert.True(normalized.IsEmpty);
    }

    [Fact]
    public void Normalize_reencodes_remaining_spider_query_like_xray_core()
    {
        var normalized = new RuntimeRealityOptions
        {
            SpiderX = "/portal?z=last&keep+name=hello+world&p=10-20&a=first&r=99"
        }.Normalize();

        Assert.Equal("/portal?a=first&keep+name=hello+world&z=last", normalized.SpiderX);
        Assert.Equal([10L, 20L, 0L, 0L, 0L, 0L, 0L, 0L, 99L, 99L], normalized.SpiderY);
    }

    [Fact]
    public void Normalize_uses_first_repeated_spider_range_value_like_xray_core()
    {
        var normalized = new RuntimeRealityOptions
        {
            SpiderX = "/portal?p=10-20&p=30-40&keep=1"
        }.Normalize();

        Assert.Equal("/portal?keep=1", normalized.SpiderX);
        Assert.Equal([10L, 20L, 0L, 0L, 0L, 0L, 0L, 0L, 0L, 0L], normalized.SpiderY);
    }

    [Fact]
    public void Normalize_ignores_later_repeated_spider_range_when_first_value_is_empty()
    {
        var normalized = new RuntimeRealityOptions
        {
            SpiderX = "/portal?p=&p=30-40&keep=1"
        }.Normalize();

        Assert.Equal("/portal?keep=1", normalized.SpiderX);
        Assert.Equal(new long[10], normalized.SpiderY);
    }

    private static RuntimeRealityOptions CreateValidOptions(string fingerprint = "")
        => new()
        {
            Fingerprint = fingerprint,
            PublicKey = ToBase64Url(Enumerable.Range(1, 32).Select(static value => (byte)value).ToArray())
        };

    private static string ToBase64Url(byte[] bytes)
        => Convert.ToBase64String(bytes)
            .TrimEnd('=')
            .Replace('+', '-')
            .Replace('/', '_');
}

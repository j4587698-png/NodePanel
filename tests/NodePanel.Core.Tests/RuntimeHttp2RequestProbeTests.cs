using NodePanel.Core.Runtime;

namespace NodePanel.Core.Tests;

public sealed class RuntimeHttp2RequestProbeTests
{
    [Fact]
    public void LooksLikeConnectionPreface_returns_true_for_http2_preface()
    {
        var payload = Http2InitialPayloadTestBuilder.BuildPrefaceOnly();

        Assert.True(RuntimeHttp2RequestProbe.LooksLikeConnectionPreface(payload));
    }

    [Fact]
    public void TryExtractRequestPath_reads_first_http2_request_path()
    {
        var payload = Http2InitialPayloadTestBuilder.BuildRequestInitialPayload(
            method: "GET",
            path: "/xhttp/?x_padding=X");

        var result = RuntimeHttp2RequestProbe.TryExtractRequestPath(payload, out var path);

        Assert.True(result);
        Assert.Equal("/xhttp/", new Uri("https://edge.example.com" + path).AbsolutePath);
    }
}

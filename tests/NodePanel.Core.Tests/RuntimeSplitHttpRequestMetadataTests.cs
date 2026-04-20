using NodePanel.Core.Runtime;

namespace NodePanel.Core.Tests;

public sealed class RuntimeSplitHttpRequestMetadataTests
{
    [Fact]
    public void NormalizePath_matches_xray_core_path_and_query_rules()
    {
        Assert.Equal("/split/", RuntimeSplitHttpRequestMetadata.NormalizePath("split"));
        Assert.Equal("/split/?foo=bar", RuntimeSplitHttpRequestMetadata.NormalizePath("split?foo=bar"));
        Assert.Equal("/?foo=bar", RuntimeSplitHttpRequestMetadata.NormalizePath("?foo=bar"));
    }

    [Fact]
    public void ApplyToRequest_and_ExtractFromRequest_round_trip_path_and_query_placements()
    {
        var requestTarget = RuntimeSplitHttpRequestMetadata.NormalizePath("split?foo=bar");
        var requestHeaders = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);

        RuntimeSplitHttpRequestMetadata.ApplyToRequest(
            ref requestTarget,
            requestHeaders,
            sessionPlacement: "path",
            sessionKey: string.Empty,
            sessionId: "session/1",
            seqPlacement: "query",
            seqKey: string.Empty,
            seqValue: "2 3");

        Assert.Equal("/split/session%2F1?foo=bar&x_seq=2%203", requestTarget);
        Assert.Empty(requestHeaders);

        var (sessionId, seqValue) = RuntimeSplitHttpRequestMetadata.ExtractFromRequest(
            requestTarget,
            requestHeaders,
            configuredPath: "split?foo=bar",
            sessionPlacement: "path",
            sessionKey: string.Empty,
            seqPlacement: "query",
            seqKey: string.Empty);

        Assert.Equal("session/1", sessionId);
        Assert.Equal("2 3", seqValue);
    }

    [Fact]
    public void ApplyToRequest_and_ExtractFromRequest_round_trip_header_and_cookie_placements()
    {
        var requestTarget = RuntimeSplitHttpRequestMetadata.NormalizePath("/split");
        var requestHeaders = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
        {
            ["Cookie"] = "pref=1"
        };

        RuntimeSplitHttpRequestMetadata.ApplyToRequest(
            ref requestTarget,
            requestHeaders,
            sessionPlacement: "header",
            sessionKey: string.Empty,
            sessionId: "session-1",
            seqPlacement: "cookie",
            seqKey: string.Empty,
            seqValue: "7");

        Assert.Equal("/split/", requestTarget);
        Assert.Equal("session-1", requestHeaders["X-Session"]);
        Assert.Equal("pref=1; x_seq=7", requestHeaders["Cookie"]);

        var (sessionId, seqValue) = RuntimeSplitHttpRequestMetadata.ExtractFromRequest(
            requestTarget,
            requestHeaders,
            configuredPath: "/split",
            sessionPlacement: "header",
            sessionKey: string.Empty,
            seqPlacement: "cookie",
            seqKey: string.Empty);

        Assert.Equal("session-1", sessionId);
        Assert.Equal("7", seqValue);
    }

    [Fact]
    public void ApplyToRequest_and_ExtractFromRequest_round_trip_cookie_and_path_with_custom_keys()
    {
        var requestTarget = RuntimeSplitHttpRequestMetadata.NormalizePath("/split");
        var requestHeaders = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);

        RuntimeSplitHttpRequestMetadata.ApplyToRequest(
            ref requestTarget,
            requestHeaders,
            sessionPlacement: "cookie",
            sessionKey: "session_id",
            sessionId: "alpha",
            seqPlacement: "path",
            seqKey: "ignored",
            seqValue: "99");

        Assert.Equal("/split/99", requestTarget);
        Assert.Equal("session_id=alpha", requestHeaders["Cookie"]);

        var (sessionId, seqValue) = RuntimeSplitHttpRequestMetadata.ExtractFromRequest(
            requestTarget,
            requestHeaders,
            configuredPath: "/split",
            sessionPlacement: "cookie",
            sessionKey: "session_id",
            seqPlacement: "path",
            seqKey: "ignored");

        Assert.Equal("alpha", sessionId);
        Assert.Equal("99", seqValue);
    }
}

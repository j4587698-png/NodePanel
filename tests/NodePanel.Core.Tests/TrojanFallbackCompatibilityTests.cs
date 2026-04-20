using NodePanel.Core.Runtime;

namespace NodePanel.Core.Tests;

public sealed class TrojanFallbackCompatibilityTests
{
    [Fact]
    public void NormalizeUnixSocketPath_linux_single_at_uses_abstract_socket_without_padding()
    {
        var normalized = TrojanFallbackCompatibility.NormalizeUnixSocketPath("@alpha", linuxLikePlatform: true);

        Assert.Equal(6, normalized.Length);
        Assert.Equal('\0', normalized[0]);
        Assert.Equal("alpha", normalized[1..]);
    }

    [Fact]
    public void NormalizeUnixSocketPath_linux_double_at_uses_padded_abstract_socket_like_xray_core()
    {
        var normalized = TrojanFallbackCompatibility.NormalizeUnixSocketPath("@@alpha", linuxLikePlatform: true);

        Assert.Equal(108, normalized.Length);
        Assert.Equal('\0', normalized[0]);
        Assert.Equal('a', normalized[1]);
        Assert.Equal('l', normalized[2]);
        Assert.Equal('p', normalized[3]);
        Assert.Equal('h', normalized[4]);
        Assert.Equal('a', normalized[5]);
        Assert.DoesNotContain('@', normalized[1..6]);
        foreach (var ch in normalized[6..])
        {
            Assert.Equal('\0', ch);
        }
    }

    [Fact]
    public void NormalizeUnixSocketPath_non_linux_preserves_double_at_literal_path()
    {
        var normalized = TrojanFallbackCompatibility.NormalizeUnixSocketPath("@@alpha", linuxLikePlatform: false);

        Assert.Equal("@@alpha", normalized);
    }
}

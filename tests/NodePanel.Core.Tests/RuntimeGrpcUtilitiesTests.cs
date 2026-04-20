using NodePanel.Core.Runtime;

namespace NodePanel.Core.Tests;

public sealed class RuntimeGrpcUtilitiesTests
{
    [Theory]
    [InlineData("hello", "hello")]
    [InlineData("hello/world!", "hello%2Fworld%21")]
    [InlineData("/my/sample/path/a|b", "my/sample/path")]
    [InlineData("/hello /world!/a|b", "hello%20/world%21")]
    [InlineData("/foo", "")]
    public void ResolveServiceName_matches_xray_core_behavior(string serviceName, string expected)
        => Assert.Equal(expected, RuntimeGrpcUtilities.ResolveServiceName(serviceName));

    [Theory]
    [InlineData("hello", "Tun")]
    [InlineData("/my/sample/path/tun_service|multi_service", "tun_service")]
    [InlineData("/my/sample/path/tun_service", "tun_service")]
    [InlineData("/m y/sa !mple/pa\\th/tun\\_serv!ice", "tun%5C_serv%21ice")]
    public void ResolveTunStreamName_matches_xray_core_behavior(string serviceName, string expected)
        => Assert.Equal(expected, RuntimeGrpcUtilities.ResolveTunStreamName(serviceName));

    [Theory]
    [InlineData("hello", "TunMulti")]
    [InlineData("/my/sample/path/tun_service|multi_service", "multi_service")]
    [InlineData("/my/sample/path/multi_service", "multi_service")]
    [InlineData("/m y/sa !mple/pa\\th/mu%lti\\_serv!ice", "mu%25lti%5C_serv%21ice")]
    public void ResolveTunMultiStreamName_matches_xray_core_behavior(string serviceName, string expected)
        => Assert.Equal(expected, RuntimeGrpcUtilities.ResolveTunMultiStreamName(serviceName));

    [Fact]
    public void ResolveMethodPath_builds_expected_tun_path()
    {
        Assert.Equal("/my/sample/path/tun_service", RuntimeGrpcUtilities.ResolveMethodPath("/my/sample/path/tun_service|multi_service", multiMode: false));
        Assert.Equal("/my/sample/path/multi_service", RuntimeGrpcUtilities.ResolveMethodPath("/my/sample/path/tun_service|multi_service", multiMode: true));
    }
}

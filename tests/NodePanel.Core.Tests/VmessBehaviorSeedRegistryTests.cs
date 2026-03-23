using NodePanel.Core.Protocol;
using NodePanel.Core.Runtime;

namespace NodePanel.Core.Tests;

public sealed class VmessBehaviorSeedRegistryTests
{
    [Fact]
    public void GetOrCreate_freezes_behavior_seed_per_key()
    {
        var registry = new VmessBehaviorSeedRegistry(static () => 0xABCDEF01UL);
        var firstUsers = new[] { CreateUser("11111111-1111-1111-1111-111111111111") };
        var secondUsers = new[] { CreateUser("22222222-2222-2222-2222-222222222222") };

        var firstSeed = registry.GetOrCreate("vmess-inbound-a", firstUsers);
        var secondSeed = registry.GetOrCreate("vmess-inbound-a", secondUsers);
        var thirdSeed = registry.GetOrCreate("vmess-inbound-b", secondUsers);

        Assert.Equal(firstSeed, secondSeed);
        Assert.Equal(
            VmessHandshakeDrainer.ComputeBehaviorSeed(firstUsers, 0xABCDEF01UL),
            firstSeed);
        Assert.Equal(
            VmessHandshakeDrainer.ComputeBehaviorSeed(secondUsers, 0xABCDEF01UL),
            thirdSeed);
        Assert.NotEqual(firstSeed, thirdSeed);
    }

    [Fact]
    public void GetOrCreate_freezes_fallback_seed_per_key_when_users_have_no_valid_uuid()
    {
        ulong nextFallback = 40;
        var registry = new VmessBehaviorSeedRegistry(() => ++nextFallback);
        var users = new[] { CreateUser("not-a-uuid") };

        var firstSeed = registry.GetOrCreate("vmess-inbound-a", users);
        var secondSeed = registry.GetOrCreate("vmess-inbound-a", users);
        var thirdSeed = registry.GetOrCreate("vmess-inbound-b", users);

        Assert.Equal(41UL, firstSeed);
        Assert.Equal(firstSeed, secondSeed);
        Assert.Equal(42UL, thirdSeed);
    }

    private static VmessUser CreateUser(string uuid)
        => new()
        {
            UserId = "vmess-user",
            Uuid = uuid,
            CmdKey = Enumerable.Range(1, 16).Select(static value => (byte)value).ToArray(),
            BytesPerSecond = 0
        };
}

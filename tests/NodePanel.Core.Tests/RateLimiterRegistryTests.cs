using NodePanel.Core.Runtime;

namespace NodePanel.Core.Tests;

public sealed class RateLimiterRegistryTests
{
    [Fact]
    public void GetUserGate_uses_runtime_key_to_isolate_same_user_across_inbounds()
    {
        var registry = new RateLimiterRegistry();
        var firstUser = CreateScopedUser("shared-user", "in-a", 128);
        var secondUser = CreateScopedUser("shared-user", "in-b", 256);

        registry.Apply(globalBytesPerSecond: 0, [firstUser, secondUser]);

        var firstGate = registry.GetUserGate(firstUser);
        var secondGate = registry.GetUserGate(secondUser);

        Assert.NotSame(firstGate, secondGate);
    }

    [Fact]
    public void Apply_removes_only_the_inactive_runtime_key()
    {
        var registry = new RateLimiterRegistry();
        var firstUser = CreateScopedUser("shared-user", "in-a", 128);
        var secondUser = CreateScopedUser("shared-user", "in-b", 256);

        registry.Apply(globalBytesPerSecond: 0, [firstUser, secondUser]);

        var firstGate = registry.GetUserGate(firstUser);
        var secondGate = registry.GetUserGate(secondUser);

        registry.Apply(globalBytesPerSecond: 0, [firstUser]);

        Assert.Same(firstGate, registry.GetUserGate(firstUser));
        Assert.NotSame(secondGate, registry.GetUserGate(secondUser));
    }

    private static TrojanUser CreateScopedUser(string userId, string inboundTag, long bytesPerSecond)
        => new()
        {
            UserId = userId,
            PasswordHash = $"{userId}-{inboundTag}",
            RuntimeKey = RuntimeUserKeys.Create(InboundProtocols.Trojan, inboundTag, userId),
            BytesPerSecond = bytesPerSecond,
            DeviceLimit = 1
        };
}

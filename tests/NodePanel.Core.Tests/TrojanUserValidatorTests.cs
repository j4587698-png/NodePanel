using NodePanel.Core.Protocol;
using NodePanel.Core.Runtime;

namespace NodePanel.Core.Tests;

public sealed class TrojanUserValidatorTests
{
    [Fact]
    public void TryAuthenticate_follows_live_users_and_normalizes_hash()
    {
        var user = new TrojanUser
        {
            UserId = "trojan-user",
            PasswordHash = "0123456789abcdef0123456789abcdef0123456789abcdef01234567",
            BytesPerSecond = 0
        };

        var validator = new TrojanUserValidator(Array.Empty<TrojanUser>());
        Assert.False(validator.TryAuthenticate(user.PasswordHash, out _));

        validator.AddUser(user);
        Assert.True(validator.TryAuthenticate(user.PasswordHash.ToUpperInvariant(), out var authenticatedUser));
        Assert.Equal(user.UserId, authenticatedUser!.UserId);

        Assert.True(validator.RemoveUser(user.UserId));
        Assert.False(validator.TryAuthenticate(user.PasswordHash, out _));
    }
}

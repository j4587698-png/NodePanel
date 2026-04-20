using NodePanel.Core.Protocol;
using NodePanel.Core.Runtime;

namespace NodePanel.Core.Tests;

public sealed class VmessTimedUserValidatorTests
{
    [Fact]
    public void BehaviorSeed_freezes_fallback_seed_per_validator_instance()
    {
        ulong nextFallback = 40;
        var users = new[] { CreateUserWithUuid("not-a-uuid", 1) };

        var firstValidator = new VmessTimedUserValidator(
            users,
            new VmessAuthIdHistory(),
            () => ++nextFallback);
        var secondValidator = new VmessTimedUserValidator(
            users,
            new VmessAuthIdHistory(),
            () => ++nextFallback);

        Assert.Equal(41UL, firstValidator.BehaviorSeed);
        Assert.Equal(41UL, firstValidator.BehaviorSeed);
        Assert.Equal(42UL, secondValidator.BehaviorSeed);
    }

    [Fact]
    public void BehaviorSeed_accumulates_users_added_before_fusion()
    {
        const ulong fallbackSeed = 0xABCDEF01UL;
        var firstUser = CreateUserWithUuid("11111111-1111-1111-1111-111111111111", 1);
        var secondUser = CreateUserWithUuid("22222222-2222-2222-2222-222222222222", 17);
        var validator = new VmessTimedUserValidator(
            [firstUser],
            new VmessAuthIdHistory(),
            static () => fallbackSeed);

        validator.AddUser(secondUser);

        Assert.Equal(
            VmessHandshakeDrainer.ComputeBehaviorSeed([firstUser, secondUser], fallbackSeed),
            validator.BehaviorSeed);
    }

    [Fact]
    public void BehaviorSeed_does_not_change_when_user_added_after_fusion()
    {
        const ulong fallbackSeed = 0xABCDEF01UL;
        var firstUser = CreateUserWithUuid("11111111-1111-1111-1111-111111111111", 1);
        var secondUser = CreateUserWithUuid("22222222-2222-2222-2222-222222222222", 17);
        var validator = new VmessTimedUserValidator(
            [firstUser],
            new VmessAuthIdHistory(),
            static () => fallbackSeed);

        var firstBehaviorSeed = validator.BehaviorSeed;
        validator.AddUser(secondUser);

        Assert.Equal(firstBehaviorSeed, validator.BehaviorSeed);
    }

    [Fact]
    public void BehaviorSeed_does_not_roll_back_when_user_removed_before_fusion()
    {
        const ulong fallbackSeed = 0xABCDEF01UL;
        var firstUser = CreateUserWithUuid("11111111-1111-1111-1111-111111111111", 1);
        var secondUser = CreateUserWithUuid("22222222-2222-2222-2222-222222222222", 17);
        var validator = new VmessTimedUserValidator(
            [firstUser],
            new VmessAuthIdHistory(),
            static () => fallbackSeed);

        validator.AddUser(secondUser);
        Assert.True(validator.RemoveUser(secondUser.UserId));

        Assert.Equal(
            VmessHandshakeDrainer.ComputeBehaviorSeed([firstUser, secondUser], fallbackSeed),
            validator.BehaviorSeed);
    }

    [Fact]
    public void TryMatchUser_isolates_replay_history_per_validator_instance()
    {
        var user = CreateUser(1);
        var authId = VmessTestRequestEncoder.CreateAuthId(
            user,
            timestamp: DateTimeOffset.UtcNow.ToUnixTimeSeconds(),
            random: 0x11223344u);

        var firstValidator = new VmessTimedUserValidator([user]);
        Assert.True(firstValidator.TryMatchUser(authId, out var firstMatch, out var firstError));
        Assert.Null(firstError);
        Assert.Equal(user.UserId, firstMatch!.UserId);

        Assert.False(firstValidator.TryMatchUser(authId, out _, out var replayError));
        Assert.NotNull(replayError);
        Assert.Contains("replayed request", replayError!.Message, StringComparison.OrdinalIgnoreCase);

        var secondValidator = new VmessTimedUserValidator([user]);
        Assert.True(secondValidator.TryMatchUser(authId, out var secondMatch, out var secondError));
        Assert.Null(secondError);
        Assert.Equal(user.UserId, secondMatch!.UserId);
    }

    [Fact]
    public void RemoveUser_detaches_auth_id_matcher_from_live_snapshot()
    {
        var user = CreateUser(7);
        var authId = VmessTestRequestEncoder.CreateAuthId(
            user,
            timestamp: DateTimeOffset.UtcNow.ToUnixTimeSeconds(),
            random: 0x55667788u);

        var validator = new VmessTimedUserValidator(Array.Empty<VmessUser>());
        validator.AddUser(user);
        Assert.Single(validator.GetUsers());

        Assert.True(validator.RemoveUser(user.UserId));
        Assert.Empty(validator.GetUsers());

        Assert.False(validator.TryMatchUser(authId, out _, out var error));
        Assert.NotNull(error);
        Assert.Contains("user do not exist", error!.Message, StringComparison.OrdinalIgnoreCase);
    }

    private static VmessUser CreateUser(int keySeed)
        => CreateUserWithUuid(Guid.NewGuid().ToString("D"), keySeed);

    private static VmessUser CreateUserWithUuid(string uuid, int keySeed)
        => new()
        {
            UserId = "vmess-user",
            Uuid = uuid,
            CmdKey = Enumerable.Range(keySeed, 16).Select(static value => (byte)value).ToArray(),
            BytesPerSecond = 0
        };
}

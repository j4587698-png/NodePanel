using NodePanel.Core.Protocol;
using NodePanel.Core.Runtime;

namespace NodePanel.Core.Tests;

public sealed class VlessUserValidatorTests
{
    [Fact]
    public void TryResolveUser_follows_live_users()
    {
        const string uuid = "11111111-1111-1111-1111-111111111111";
        var user = CreateUser("vless-user", uuid);
        var validator = new VlessUserValidator(Array.Empty<VlessUser>());

        Assert.False(validator.TryResolveUser(uuid, out _));

        validator.AddUser(user);
        Assert.True(validator.TryResolveUser(uuid, out var resolvedUser));
        Assert.Equal(user.UserId, resolvedUser!.UserId);

        Assert.True(validator.RemoveUser(user.UserId));
        Assert.False(validator.TryResolveUser(uuid, out _));
    }

    [Fact]
    public void TryResolveUser_matches_processed_uuid_key_like_xray_core()
    {
        const string uuid = "11111111-1111-1111-1111-111111111111";
        var user = CreateUser("vless-user", uuid);
        var validator = new VlessUserValidator([user]);
        var equivalentUuid = CreateProcessedUuidEquivalent(uuid, 0xAA, 0x55);

        Assert.True(validator.TryResolveUser(equivalentUuid, out var resolvedUser));
        Assert.Equal(user.UserId, resolvedUser!.UserId);
    }

    private static VlessUser CreateUser(string userId, string uuid)
        => new()
        {
            UserId = userId,
            Uuid = uuid,
            BytesPerSecond = 0
        };

    private static string CreateProcessedUuidEquivalent(string uuid, byte byte6, byte byte7)
    {
        Span<byte> uuidBytes = stackalloc byte[16];
        Assert.True(ProtocolUuid.TryWriteBytes(uuid, uuidBytes));
        uuidBytes[6] = byte6;
        uuidBytes[7] = byte7;
        return ProtocolUuid.Format(uuidBytes);
    }
}

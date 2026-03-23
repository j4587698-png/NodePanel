using NodePanel.Core.Protocol;
using NodePanel.Core.Runtime;

namespace NodePanel.Core.Tests;

public sealed class VmessInboundRuntimeStateTests
{
    [Fact]
    public void BehaviorSeed_freezes_fallback_seed_per_runtime_state()
    {
        ulong nextFallback = 40;
        var users = new[] { CreateUser("not-a-uuid") };

        var firstState = CreateRuntimeState(users, () => ++nextFallback);
        var secondState = CreateRuntimeState(users, () => ++nextFallback);

        Assert.Equal(41UL, firstState.BehaviorSeed);
        Assert.Equal(41UL, firstState.BehaviorSeed);
        Assert.Equal(42UL, secondState.BehaviorSeed);
    }

    [Fact]
    public async Task ReadAsync_isolates_replay_history_per_runtime_state()
    {
        using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(10));

        var user = CreateUser("11111111-1111-1111-1111-111111111111");
        var request = CreateMuxRequest(user);
        var authId = VmessTestRequestEncoder.CreateAuthId(user, random: 0x11223344u);
        var headerBytes = VmessTestRequestEncoder.BuildRequestHeader(user, request, authId);
        var reader = new VmessHandshakeReader();
        var firstRuntimeState = CreateRuntimeState([user], static () => 0xABCDEF01UL);
        var reloadedRuntimeState = CreateRuntimeState([user], static () => 0xABCDEF02UL);

        var decodedRequest = await reader.ReadAsync(
            new MemoryStream(headerBytes, writable: false),
            [user],
            drainOnFailure: false,
            firstRuntimeState,
            cts.Token);
        Assert.Equal(request.RequestBodyKey, decodedRequest.RequestBodyKey);
        Assert.Equal(request.RequestBodyIv, decodedRequest.RequestBodyIv);

        var replay = await Assert.ThrowsAsync<UnauthorizedAccessException>(() => reader.ReadAsync(
            new MemoryStream(headerBytes, writable: false),
            [user],
            drainOnFailure: false,
            firstRuntimeState,
            cts.Token).AsTask());
        Assert.Contains("invalid user", replay.Message, StringComparison.OrdinalIgnoreCase);
        Assert.NotNull(replay.InnerException);
        Assert.Contains("replayed request", replay.InnerException!.Message, StringComparison.OrdinalIgnoreCase);

        var decodedAfterReload = await reader.ReadAsync(
            new MemoryStream(headerBytes, writable: false),
            [user],
            drainOnFailure: false,
            reloadedRuntimeState,
            cts.Token);
        Assert.Equal(request.RequestBodyKey, decodedAfterReload.RequestBodyKey);
        Assert.Equal(request.RequestBodyIv, decodedAfterReload.RequestBodyIv);
    }

    private static VmessInboundRuntimeState CreateRuntimeState(
        IReadOnlyList<VmessUser> users,
        Func<ulong> fallbackSeedFactory)
        => new(
            users,
            fallbackSeedFactory,
            new VmessSessionHistory(),
            new VmessAuthIdHistory());

    private static VmessUser CreateUser(string uuid)
        => new()
        {
            UserId = "vmess-user",
            Uuid = uuid,
            CmdKey = Enumerable.Range(1, 16).Select(static value => (byte)value).ToArray(),
            BytesPerSecond = 0
        };

    private static VmessRequest CreateMuxRequest(VmessUser user)
        => new()
        {
            Version = 1,
            User = user,
            RequestBodyKey = Enumerable.Range(0x10, 16).Select(static value => (byte)value).ToArray(),
            RequestBodyIv = Enumerable.Range(0x80, 16).Select(static value => (byte)value).ToArray(),
            ResponseHeader = 0x5A,
            Option = VmessRequestOptions.ChunkStream |
                     VmessRequestOptions.ChunkMasking |
                     VmessRequestOptions.GlobalPadding |
                     VmessRequestOptions.AuthenticatedLength,
            Security = VmessSecurityType.Aes128Gcm,
            Command = VmessCommand.Mux,
            TargetHost = "v1.mux.cool",
            TargetPort = 0
        };
}

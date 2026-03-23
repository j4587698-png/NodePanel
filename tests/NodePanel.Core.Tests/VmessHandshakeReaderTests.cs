using NodePanel.Core.Protocol;
using NodePanel.Core.Runtime;

namespace NodePanel.Core.Tests;

public sealed class VmessHandshakeReaderTests
{
    [Fact]
    public async Task ReadAsync_rejects_replayed_auth_id_for_identical_aead_request()
    {
        using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(10));

        var user = CreateUser(1);
        var request = CreateMuxRequest(user);
        var headerBytes = VmessTestRequestEncoder.BuildRequestHeader(user, request);
        var reader = new VmessHandshakeReader(new VmessSessionHistory());

        var decodedRequest = await reader.ReadAsync(
            new MemoryStream(headerBytes, writable: false),
            [user],
            cts.Token);
        Assert.Equal(request.RequestBodyKey, decodedRequest.RequestBodyKey);
        Assert.Equal(request.RequestBodyIv, decodedRequest.RequestBodyIv);

        var exception = await Assert.ThrowsAsync<UnauthorizedAccessException>(() => reader.ReadAsync(
            new MemoryStream(headerBytes, writable: false),
            [user],
            cts.Token).AsTask());
        Assert.Contains("invalid user", exception.Message, StringComparison.OrdinalIgnoreCase);
        Assert.NotNull(exception.InnerException);
        Assert.Contains("replayed request", exception.InnerException!.Message, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task ReadAsync_rejects_duplicated_session_id_across_distinct_auth_ids()
    {
        using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(10));

        var user = CreateUser(1);
        var request = CreateMuxRequest(user);
        var firstHeaderBytes = VmessTestRequestEncoder.BuildRequestHeader(
            user,
            request,
            VmessTestRequestEncoder.CreateAuthId(user, random: 0x11223344u));
        var secondHeaderBytes = VmessTestRequestEncoder.BuildRequestHeader(
            user,
            request,
            VmessTestRequestEncoder.CreateAuthId(user, random: 0x55667788u));
        var reader = new VmessHandshakeReader(new VmessSessionHistory());

        var decodedRequest = await reader.ReadAsync(
            new MemoryStream(firstHeaderBytes, writable: false),
            [user],
            cts.Token);
        Assert.Equal(request.RequestBodyKey, decodedRequest.RequestBodyKey);
        Assert.Equal(request.RequestBodyIv, decodedRequest.RequestBodyIv);

        var exception = await Assert.ThrowsAsync<InvalidDataException>(() => reader.ReadAsync(
            new MemoryStream(secondHeaderBytes, writable: false),
            [user],
            cts.Token).AsTask());
        Assert.Contains("duplicated session id", exception.Message, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("replay", exception.Message, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task ReadAsync_rejects_replayed_auth_id_across_distinct_sessions()
    {
        using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(10));

        var user = CreateUser(1);
        var firstRequest = CreateMuxRequest(user);
        var secondRequest = firstRequest with
        {
            RequestBodyKey = Enumerable.Range(0x30, 16).Select(static value => (byte)value).ToArray(),
            RequestBodyIv = Enumerable.Range(0x50, 16).Select(static value => (byte)value).ToArray()
        };
        var authId = VmessTestRequestEncoder.CreateAuthId(user, random: 0x11223344u);
        var firstHeaderBytes = VmessTestRequestEncoder.BuildRequestHeader(user, firstRequest, authId);
        var secondHeaderBytes = VmessTestRequestEncoder.BuildRequestHeader(user, secondRequest, authId);
        var reader = new VmessHandshakeReader(new VmessSessionHistory(), new VmessAuthIdHistory());

        var decodedRequest = await reader.ReadAsync(
            new MemoryStream(firstHeaderBytes, writable: false),
            [user],
            cts.Token);
        Assert.Equal(firstRequest.RequestBodyKey, decodedRequest.RequestBodyKey);
        Assert.Equal(firstRequest.RequestBodyIv, decodedRequest.RequestBodyIv);

        var exception = await Assert.ThrowsAsync<UnauthorizedAccessException>(() => reader.ReadAsync(
            new MemoryStream(secondHeaderBytes, writable: false),
            [user],
            cts.Token).AsTask());
        Assert.Contains("invalid user", exception.Message, StringComparison.OrdinalIgnoreCase);
        Assert.NotNull(exception.InnerException);
        Assert.Contains("replayed request", exception.InnerException!.Message, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task ReadAsync_rejects_expired_auth_id_as_invalid_user()
    {
        using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(10));

        var user = CreateUser(1);
        var request = CreateMuxRequest(user);
        var expiredAuthId = VmessTestRequestEncoder.CreateAuthId(
            user,
            timestamp: DateTimeOffset.UtcNow.AddMinutes(-10).ToUnixTimeSeconds(),
            random: 0x55667788u);
        var headerBytes = VmessTestRequestEncoder.BuildRequestHeader(user, request, expiredAuthId);
        var reader = new VmessHandshakeReader(new VmessSessionHistory(), new VmessAuthIdHistory());

        var exception = await Assert.ThrowsAsync<UnauthorizedAccessException>(() => reader.ReadAsync(
            new MemoryStream(headerBytes, writable: false),
            [user],
            cts.Token).AsTask());
        Assert.Contains("invalid user", exception.Message, StringComparison.OrdinalIgnoreCase);
        Assert.NotNull(exception.InnerException);
        Assert.Contains("invalid timestamp", exception.InnerException!.Message, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task ReadAsync_reports_aead_read_failed_when_header_is_truncated()
    {
        using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(10));

        var user = CreateUser(1);
        var request = CreateMuxRequest(user);
        var headerBytes = VmessTestRequestEncoder.BuildRequestHeader(user, request);
        var truncated = headerBytes.AsSpan(0, 24).ToArray();
        var reader = new VmessHandshakeReader(new VmessSessionHistory(), new VmessAuthIdHistory());

        var exception = await Assert.ThrowsAsync<InvalidDataException>(() => reader.ReadAsync(
            new MemoryStream(truncated, writable: false),
            [user],
            cts.Token).AsTask());
        Assert.Contains("AEAD read failed, drain skipped", exception.Message, StringComparison.OrdinalIgnoreCase);
        Assert.IsType<EndOfStreamException>(exception.InnerException);
    }

    [Fact]
    public async Task ReadAsync_rejects_zero_security_value_as_auto()
    {
        using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(10));

        var user = CreateUser(1);
        var request = CreateMuxRequest(user) with
        {
            Security = VmessSecurityType.Unknown
        };
        var headerBytes = VmessTestRequestEncoder.BuildRequestHeader(user, request);
        var reader = new VmessHandshakeReader(new VmessSessionHistory(), new VmessAuthIdHistory());

        var exception = await Assert.ThrowsAsync<NotSupportedException>(() => reader.ReadAsync(
            new MemoryStream(headerBytes, writable: false),
            [user],
            cts.Token).AsTask());
        Assert.Contains("unknown security type", exception.Message, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("Auto", exception.Message, StringComparison.Ordinal);
    }

    [Fact]
    public async Task ReadAsync_drains_remaining_bytes_on_invalid_user_when_enabled()
    {
        using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(10));

        var validUser = CreateUser(1);
        var invalidUser = CreateUser(101);
        var invalidRequest = CreateMuxRequest(invalidUser);
        var headerBytes = VmessTestRequestEncoder.BuildRequestHeader(invalidUser, invalidRequest);
        var payload = headerBytes.Concat(Enumerable.Repeat((byte)0x5A, 4096)).ToArray();
        await using var stream = new MemoryStream(payload, writable: false);
        var reader = new VmessHandshakeReader(new VmessSessionHistory());

        var exception = await Assert.ThrowsAsync<IOException>(() => reader.ReadAsync(
            stream,
            [validUser],
            drainOnFailure: true,
            cts.Token).AsTask());
        Assert.Contains("drained connection", exception.Message, StringComparison.OrdinalIgnoreCase);
        Assert.IsType<UnauthorizedAccessException>(exception.InnerException);
        Assert.Contains("invalid user", exception.InnerException!.Message, StringComparison.OrdinalIgnoreCase);
        Assert.True(stream.Position > 16);
        Assert.True(stream.Position <= payload.Length);
    }

    [Fact]
    public async Task ReadAsync_reports_incomplete_drain_on_invalid_user_when_stream_ends_early()
    {
        using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(10));

        var validUser = CreateUser(1);
        var invalidUser = CreateUser(101);
        var invalidRequest = CreateMuxRequest(invalidUser);
        var headerBytes = VmessTestRequestEncoder.BuildRequestHeader(invalidUser, invalidRequest);
        await using var stream = new MemoryStream(headerBytes, writable: false);
        var reader = new VmessHandshakeReader(new VmessSessionHistory());

        var exception = await Assert.ThrowsAsync<IOException>(() => reader.ReadAsync(
            stream,
            [validUser],
            drainOnFailure: true,
            cts.Token).AsTask());
        Assert.Contains("unable to drain connection", exception.Message, StringComparison.OrdinalIgnoreCase);
        Assert.IsType<EndOfStreamException>(exception.InnerException);
        Assert.IsType<UnauthorizedAccessException>(exception.InnerException.InnerException);
        Assert.Contains("invalid user", exception.InnerException.InnerException!.Message, StringComparison.OrdinalIgnoreCase);
        Assert.Equal(headerBytes.Length, stream.Position);
    }

    [Fact]
    public async Task ReadAsync_keeps_remaining_bytes_on_invalid_user_when_drain_disabled()
    {
        using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(10));

        var validUser = CreateUser(1);
        var invalidUser = CreateUser(101);
        var invalidRequest = CreateMuxRequest(invalidUser);
        var headerBytes = VmessTestRequestEncoder.BuildRequestHeader(invalidUser, invalidRequest);
        var payload = headerBytes.Concat(Enumerable.Repeat((byte)0x5A, 32)).ToArray();
        await using var stream = new MemoryStream(payload, writable: false);
        var reader = new VmessHandshakeReader(new VmessSessionHistory());

        var exception = await Assert.ThrowsAsync<UnauthorizedAccessException>(() => reader.ReadAsync(
            stream,
            [validUser],
            drainOnFailure: false,
            cts.Token).AsTask());
        Assert.Contains("invalid user", exception.Message, StringComparison.OrdinalIgnoreCase);
        Assert.Equal(16, stream.Position);
    }

    [Fact]
    public void TryRegister_allows_reuse_after_expiration()
    {
        var now = new DateTimeOffset(2026, 3, 22, 0, 0, 0, TimeSpan.Zero);
        var history = new VmessSessionHistory(
            TimeSpan.FromMinutes(3),
            TimeSpan.FromSeconds(30),
            () => now);
        var request = CreateMuxRequest(CreateUser(1));

        Assert.True(history.TryRegister(request));
        Assert.False(history.TryRegister(request));

        now = now.AddMinutes(4);

        Assert.True(history.TryRegister(request));
    }

    [Fact]
    public void TryRegisterAuthId_allows_reuse_after_expiration()
    {
        var now = new DateTimeOffset(2026, 3, 22, 0, 0, 0, TimeSpan.Zero);
        var history = new VmessAuthIdHistory(
            TimeSpan.FromSeconds(120),
            TimeSpan.FromSeconds(30),
            () => now);
        var authId = Enumerable.Range(0x10, 16).Select(static value => (byte)value).ToArray();

        Assert.True(history.TryRegister(authId));
        Assert.False(history.TryRegister(authId));

        now = now.AddSeconds(121);

        Assert.True(history.TryRegister(authId));
    }

    private static VmessUser CreateUser(int keySeed)
        => new()
        {
            UserId = "vmess-user",
            Uuid = Guid.NewGuid().ToString("D"),
            CmdKey = Enumerable.Range(keySeed, 16).Select(static value => (byte)value).ToArray(),
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

using System.Net.Sockets;
using System.Security.Authentication;

namespace NodePanel.Core.Runtime;

public sealed record RuntimeRealityTargetProbeRequest
{
    public required string DestinationHost { get; init; }

    public int DestinationPort { get; init; } = 443;

    public required string ServerName { get; init; }

    public string Fingerprint { get; init; } = "chrome";

    public int Attempts { get; init; } = 3;

    public TimeSpan Timeout { get; init; } = TimeSpan.FromSeconds(5);

    public IReadOnlyList<string> ApplicationProtocols { get; init; } = ["h2", "http/1.1"];
}

public sealed record RuntimeRealityTargetProbeAttempt
{
    public required int Attempt { get; init; }

    public required bool Success { get; init; }

    public required string Message { get; init; }

    public ushort? CipherSuite { get; init; }

    public ushort? KeyShareGroup { get; init; }

    public bool SawCompatibilityChangeCipherSpec { get; init; }

    public bool SawEncryptedHandshake { get; init; }
}

public sealed record RuntimeRealityTargetProbeResult
{
    public required string Destination { get; init; }

    public required string ServerName { get; init; }

    public required int Attempts { get; init; }

    public required int Successes { get; init; }

    public required IReadOnlyList<RuntimeRealityTargetProbeAttempt> Results { get; init; }

    public bool Success => Attempts > 0 && Successes == Attempts;
}

public static class RuntimeRealityUtilities
{
    public static bool TryDerivePublicKey(
        string privateKey,
        out string publicKey,
        out string? error)
    {
        publicKey = string.Empty;
        error = null;

        if (string.IsNullOrWhiteSpace(privateKey))
        {
            error = "REALITY private key is empty.";
            return false;
        }

        if (!RuntimeRealityOptions.TryDecodeBase64Url(privateKey.Trim(), out var privateKeyBytes) ||
            privateKeyBytes.Length != RuntimeX25519.KeyLength)
        {
            error = "REALITY private key must be a base64url-encoded 32-byte X25519 key.";
            return false;
        }

        publicKey = EncodeBase64Url(RuntimeX25519.DerivePublicKey(privateKeyBytes));
        return true;
    }

    public static async ValueTask<RuntimeRealityTargetProbeResult> ProbeTargetAsync(
        RuntimeRealityTargetProbeRequest request,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(request);

        var destinationHost = request.DestinationHost.Trim();
        var serverName = request.ServerName.Trim();
        var attempts = Math.Clamp(request.Attempts, 1, 5);
        var timeout = request.Timeout <= TimeSpan.Zero ? TimeSpan.FromSeconds(5) : request.Timeout;
        var results = new List<RuntimeRealityTargetProbeAttempt>(attempts);

        for (var attempt = 1; attempt <= attempts; attempt++)
        {
            results.Add(await ProbeOnceAsync(
                    request with
                    {
                        DestinationHost = destinationHost,
                        ServerName = serverName,
                        Timeout = timeout
                    },
                    attempt,
                    cancellationToken)
                .ConfigureAwait(false));
        }

        return new RuntimeRealityTargetProbeResult
        {
            Destination = $"{destinationHost}:{request.DestinationPort}",
            ServerName = serverName,
            Attempts = attempts,
            Successes = results.Count(static item => item.Success),
            Results = results
        };
    }

    private static async ValueTask<RuntimeRealityTargetProbeAttempt> ProbeOnceAsync(
        RuntimeRealityTargetProbeRequest request,
        int attempt,
        CancellationToken cancellationToken)
    {
        using var timeoutCts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        timeoutCts.CancelAfter(request.Timeout);

        try
        {
            using var client = new TcpClient();
            await client
                .ConnectAsync(request.DestinationHost, request.DestinationPort, timeoutCts.Token)
                .ConfigureAwait(false);
            await using var stream = client.GetStream();

            var clientHello = BuildClientHello(request);
            await stream.WriteAsync(clientHello.AsMemory(0, clientHello.Length), timeoutCts.Token).ConfigureAwait(false);
            await stream.FlushAsync(timeoutCts.Token).ConfigureAwait(false);

            var firstRecord = await RuntimeTls13Record.ReadAsync(stream, allowEof: false, timeoutCts.Token).ConfigureAwait(false);
            if (firstRecord is null || firstRecord.Type != RuntimeTls13RecordType.Handshake)
            {
                return Fail(
                    attempt,
                    $"目标没有返回 TLS ServerHello，首个记录类型为 {DescribeRecordType(firstRecord?.Type)}。");
            }

            if (!TryExtractServerHello(firstRecord.Payload, out var serverHelloMessage, out var extractError))
            {
                return Fail(attempt, extractError);
            }

            RuntimeTls13ServerHello serverHello;
            try
            {
                serverHello = RuntimeTls13ServerHello.Parse(serverHelloMessage);
            }
            catch (AuthenticationException ex)
            {
                return Fail(attempt, ex.Message);
            }

            if (serverHello.IsHelloRetryRequest)
            {
                return new RuntimeRealityTargetProbeAttempt
                {
                    Attempt = attempt,
                    Success = false,
                    Message = "目标返回 HelloRetryRequest，作为 REALITY fallback 目标不够稳。",
                    CipherSuite = serverHello.CipherSuite,
                    KeyShareGroup = serverHello.KeyShareGroup
                };
            }

            var sawCompatibilityChangeCipherSpec = false;
            var sawEncryptedHandshake = false;
            for (var recordIndex = 0; recordIndex < 3; recordIndex++)
            {
                var record = await RuntimeTls13Record.ReadAsync(stream, allowEof: true, timeoutCts.Token).ConfigureAwait(false);
                if (record is null)
                {
                    break;
                }

                if (record.Type == RuntimeTls13RecordType.ChangeCipherSpec &&
                    RuntimeTls13Record.IsCompatibilityChangeCipherSpec(record.Payload))
                {
                    sawCompatibilityChangeCipherSpec = true;
                    continue;
                }

                if (record.Type == RuntimeTls13RecordType.ApplicationData)
                {
                    sawEncryptedHandshake = true;
                    break;
                }

                if (record.Type == RuntimeTls13RecordType.Alert)
                {
                    return new RuntimeRealityTargetProbeAttempt
                    {
                        Attempt = attempt,
                        Success = false,
                        Message = "目标在 ServerHello 后返回 TLS alert。",
                        CipherSuite = serverHello.CipherSuite,
                        KeyShareGroup = serverHello.KeyShareGroup,
                        SawCompatibilityChangeCipherSpec = sawCompatibilityChangeCipherSpec
                    };
                }
            }

            var success = sawCompatibilityChangeCipherSpec && sawEncryptedHandshake;
            return new RuntimeRealityTargetProbeAttempt
            {
                Attempt = attempt,
                Success = success,
                Message = success
                    ? "目标返回 TLS 1.3 ServerHello、compat CCS 和加密握手记录。"
                    : "目标支持 TLS 1.3，但后续记录不是 REALITY 常见的 CCS + encrypted handshake 形态。",
                CipherSuite = serverHello.CipherSuite,
                KeyShareGroup = serverHello.KeyShareGroup,
                SawCompatibilityChangeCipherSpec = sawCompatibilityChangeCipherSpec,
                SawEncryptedHandshake = sawEncryptedHandshake
            };
        }
        catch (OperationCanceledException) when (!cancellationToken.IsCancellationRequested)
        {
            return Fail(attempt, "探测超时。目标站或当前网络不稳定。");
        }
        catch (Exception ex) when (ex is SocketException or IOException or AuthenticationException or InvalidOperationException or NotSupportedException)
        {
            return Fail(attempt, ex.Message);
        }
    }

    private static byte[] BuildClientHello(RuntimeRealityTargetProbeRequest request)
    {
        var profile = RuntimeRealityTls13ClientHelloProfileCatalog.Resolve(request.Fingerprint);
        var keyShares = BuildClientKeyShares(profile);
        return RuntimeRealityTls13ClientHelloBuilder.Build(
            new RuntimeRealityHandshakeRequest
            {
                TransportStream = Stream.Null,
                ServerHost = request.DestinationHost,
                ServerName = request.ServerName,
                TransportProtocol = RuntimeInternetTransportProtocols.Tcp,
                ApplicationProtocols = request.ApplicationProtocols,
                RealityOptions = RuntimeRealityOptions.Empty,
                EnabledSslProtocols = SslProtocols.Tls13
            },
            profile,
            keyShares);
    }

    private static Dictionary<ushort, byte[]> BuildClientKeyShares(RuntimeRealityTls13ClientHelloProfile profile)
    {
        var keyShareRequirements = RuntimeTls13KeyShareNegotiation.ResolveClientKeyShareRequirements(profile);

        using var x25519KeyPair = RuntimeX25519.CreateKeyPair();
        var usesX25519HybridGroup = keyShareRequirements.UsesX25519Kyber768Draft00 ||
                                    keyShareRequirements.UsesX25519MlKem768;
        var reuseHybridClassicalX25519KeyShare = profile.ReuseHybridClassicalX25519KeyShare;
        using var x25519HybridKeyPair = usesX25519HybridGroup && !reuseHybridClassicalX25519KeyShare
            ? RuntimeX25519.CreateKeyPair()
            : null;
        using var x25519MlKem768KeyPair = usesX25519HybridGroup
            ? RuntimeX25519MlKem768.CreateMlKemKeyPair()
            : null;
        using var secp256r1KeyPair = RuntimeSecp256r1.CreateKeyPair();
        using var secp256r1MlKem768KeyPair = keyShareRequirements.UsesSecp256r1MlKem768
            ? RuntimeSecp256r1MlKem768.CreateMlKemKeyPair()
            : null;
        using var secp384r1KeyPair = RuntimeSecp384r1.CreateKeyPair();
        using var secp384r1MlKem1024KeyPair = keyShareRequirements.UsesSecp384r1MlKem1024
            ? RuntimeSecp384r1MlKem1024.CreateMlKemKeyPair()
            : null;
        using var secp521r1KeyPair = keyShareRequirements.UsesSecp521r1
            ? RuntimeSecp521r1.CreateKeyPair()
            : null;

        var keyShares = new Dictionary<ushort, byte[]>
        {
            [RuntimeTlsNamedGroups.X25519] = x25519KeyPair.PublicKey.ToArray(),
            [RuntimeTlsNamedGroups.Secp256r1] = secp256r1KeyPair.PublicKey.ToArray(),
            [RuntimeTlsNamedGroups.Secp384r1] = secp384r1KeyPair.PublicKey.ToArray()
        };

        if (secp521r1KeyPair is not null)
        {
            keyShares[RuntimeTlsNamedGroups.Secp521r1] = secp521r1KeyPair.PublicKey.ToArray();
        }

        var x25519HybridClassicalPublicKey = reuseHybridClassicalX25519KeyShare
            ? x25519KeyPair.PublicKey
            : x25519HybridKeyPair?.PublicKey ?? Array.Empty<byte>();
        if (x25519HybridClassicalPublicKey.Length > 0 &&
            x25519MlKem768KeyPair?.PublicKey.Length > 0)
        {
            keyShares[RuntimeTlsNamedGroups.X25519Kyber768Draft00] =
                RuntimeX25519Kyber768Draft00.BuildClientKeyShare(
                    x25519HybridClassicalPublicKey,
                    x25519MlKem768KeyPair.PublicKey);
            keyShares[RuntimeTlsNamedGroups.X25519MLKem768] =
                RuntimeX25519MlKem768.BuildClientKeyShare(
                    x25519HybridClassicalPublicKey,
                    x25519MlKem768KeyPair.PublicKey);
        }

        if (secp256r1MlKem768KeyPair is not null)
        {
            keyShares[RuntimeTlsNamedGroups.Secp256r1MLKem768] =
                RuntimeSecp256r1MlKem768.BuildClientKeyShare(
                    secp256r1KeyPair.PublicKey,
                    secp256r1MlKem768KeyPair.PublicKey);
        }

        if (secp384r1MlKem1024KeyPair is not null)
        {
            keyShares[RuntimeTlsNamedGroups.Secp384r1MLKem1024] =
                RuntimeSecp384r1MlKem1024.BuildClientKeyShare(
                    secp384r1KeyPair.PublicKey,
                    secp384r1MlKem1024KeyPair.PublicKey);
        }

        return keyShares;
    }

    private static bool TryExtractServerHello(
        ReadOnlySpan<byte> recordPayload,
        out byte[] serverHelloMessage,
        out string error)
    {
        serverHelloMessage = Array.Empty<byte>();
        error = string.Empty;
        if (recordPayload.Length < 4 || recordPayload[0] != (byte)RuntimeTls13HandshakeType.ServerHello)
        {
            error = "目标首个 handshake message 不是 ServerHello。";
            return false;
        }

        var messageLength = (recordPayload[1] << 16) | (recordPayload[2] << 8) | recordPayload[3];
        var totalLength = messageLength + 4;
        if (totalLength > recordPayload.Length)
        {
            error = "目标 ServerHello 长度不完整。";
            return false;
        }

        serverHelloMessage = recordPayload[..totalLength].ToArray();
        return true;
    }

    private static RuntimeRealityTargetProbeAttempt Fail(int attempt, string message)
        => new()
        {
            Attempt = attempt,
            Success = false,
            Message = message
        };

    private static string DescribeRecordType(RuntimeTls13RecordType? type)
        => type.HasValue ? $"0x{(byte)type.Value:X2}" : "EOF";

    private static string EncodeBase64Url(byte[] payload)
        => Convert.ToBase64String(payload)
            .TrimEnd('=')
            .Replace('+', '-')
            .Replace('/', '_');
}
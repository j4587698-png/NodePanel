using System.Buffers;
using System.Net.Http.Headers;
using System.Net;
using System.Net.Http;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.Json;
using Microsoft.Extensions.Logging;
using NodePanel.ControlPlane.Configuration;

namespace NodePanel.Service.Acme;

public sealed class ManagedAcmeCertificateService : IDisposable
{
    private readonly AcmeHttpChallengeStore _challengeStore;
    private readonly HttpClient _httpClient;
    private readonly ILogger<ManagedAcmeCertificateService> _logger;
    private readonly SemaphoreSlim _nonceGate = new(1, 1);
    private string _replayNonce = string.Empty;

    public ManagedAcmeCertificateService(
        AcmeHttpChallengeStore challengeStore,
        ILogger<ManagedAcmeCertificateService> logger)
    {
        _challengeStore = challengeStore;
        _logger = logger;
        _httpClient = new HttpClient(
            new SocketsHttpHandler
            {
                AutomaticDecompression = DecompressionMethods.Deflate | DecompressionMethods.GZip
            })
        {
            Timeout = Timeout.InfiniteTimeSpan
        };
        _httpClient.DefaultRequestHeaders.UserAgent.Add(new ProductInfoHeaderValue("NodePanel.Service", "0.1"));
    }

    public void Dispose()
    {
        _httpClient.Dispose();
        _nonceGate.Dispose();
    }

    public async Task IssueAsync(CertificateOptions config, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(config);

        using var timeoutCts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        timeoutCts.CancelAfter(TimeSpan.FromSeconds(Math.Max(120, config.ExternalTimeoutSeconds)));
        var operationToken = timeoutCts.Token;

        var directory = await GetDirectoryAsync(config, operationToken).ConfigureAwait(false);
        using var account = await LoadOrCreateAccountAsync(config, directory, operationToken).ConfigureAwait(false);
        var order = await CreateOrderAsync(config, directory, account, operationToken).ConfigureAwait(false);

        await CompleteHttp01ChallengesAsync(config, directory, account, order.AuthorizationUrls, operationToken).ConfigureAwait(false);

        using var certificateKey = RSA.Create(2048);
        var csr = CreateCertificateSigningRequest(config, certificateKey);
        var certificateUrl = await FinalizeOrderAsync(directory, account, order, csr, operationToken).ConfigureAwait(false);
        var fullChainPem = await DownloadCertificateAsync(directory, account, certificateUrl, operationToken).ConfigureAwait(false);

        WriteCertificatePackage(config, fullChainPem, certificateKey);
        _logger.LogInformation("Managed ACME issued certificate for {Domain}.", config.Domain);
    }

    private async Task<AcmeDirectoryDocument> GetDirectoryAsync(CertificateOptions config, CancellationToken cancellationToken)
    {
        var url = AcmeKnownDirectoryUrls.Resolve(config);
        using var response = await _httpClient.GetAsync(url, cancellationToken).ConfigureAwait(false);
        var content = await response.Content.ReadAsStringAsync(cancellationToken).ConfigureAwait(false);
        response.EnsureSuccessStatusCode();

        using var document = JsonDocument.Parse(content);
        var root = document.RootElement;
        return new AcmeDirectoryDocument(
            GetRequiredString(root, "newNonce"),
            GetRequiredString(root, "newAccount"),
            GetRequiredString(root, "newOrder"));
    }

    private async Task<AcmeAccountContext> LoadOrCreateAccountAsync(
        CertificateOptions config,
        AcmeDirectoryDocument directory,
        CancellationToken cancellationToken)
    {
        var stateDirectory = ResolveStateDirectory(config);
        Directory.CreateDirectory(stateDirectory);

        var accountKeyPath = Path.Combine(stateDirectory, "account.key.pem");
        var accountUrlPath = Path.Combine(stateDirectory, "account.url.txt");

        ECDsa accountKey;
        if (File.Exists(accountKeyPath))
        {
            accountKey = ECDsa.Create();
            accountKey.ImportFromPem(await File.ReadAllTextAsync(accountKeyPath, cancellationToken).ConfigureAwait(false));
        }
        else
        {
            accountKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
            await File.WriteAllTextAsync(accountKeyPath, accountKey.ExportPkcs8PrivateKeyPem(), Encoding.ASCII, cancellationToken).ConfigureAwait(false);
        }

        var accountUrl = File.Exists(accountUrlPath)
            ? (await File.ReadAllTextAsync(accountUrlPath, cancellationToken).ConfigureAwait(false)).Trim()
            : string.Empty;

        var account = AcmeAccountContext.Create(accountKey, accountUrl);
        if (!string.IsNullOrWhiteSpace(account.AccountUrl))
        {
            return account;
        }

        account.AccountUrl = await RegisterAccountAsync(config, directory, account, cancellationToken).ConfigureAwait(false);
        await File.WriteAllTextAsync(accountUrlPath, account.AccountUrl, Encoding.UTF8, cancellationToken).ConfigureAwait(false);
        return account;
    }

    private async Task<string> RegisterAccountAsync(
        CertificateOptions config,
        AcmeDirectoryDocument directory,
        AcmeAccountContext account,
        CancellationToken cancellationToken)
    {
        var payload = BuildNewAccountPayload(config.Email);
        var response = await SendSignedRequestAsync(
            directory.NewAccountUrl,
            payload,
            directory,
            account,
            useKid: false,
            accept: null,
            cancellationToken).ConfigureAwait(false);

        if (string.IsNullOrWhiteSpace(response.Location))
        {
            throw new InvalidOperationException("ACME account registration did not return a Location header.");
        }

        return response.Location;
    }

    private async Task<AcmeOrderContext> CreateOrderAsync(
        CertificateOptions config,
        AcmeDirectoryDocument directory,
        AcmeAccountContext account,
        CancellationToken cancellationToken)
    {
        var payload = BuildNewOrderPayload(ResolveDomains(config));
        var response = await SendSignedRequestAsync(
            directory.NewOrderUrl,
            payload,
            directory,
            account,
            useKid: true,
            accept: null,
            cancellationToken).ConfigureAwait(false);

        if (string.IsNullOrWhiteSpace(response.Location))
        {
            throw new InvalidOperationException("ACME order creation did not return a Location header.");
        }

        using var document = JsonDocument.Parse(response.Body);
        var root = document.RootElement;
        var authorizationUrls = root.GetProperty("authorizations")
            .EnumerateArray()
            .Select(static element => element.GetString())
            .Where(static value => !string.IsNullOrWhiteSpace(value))
            .Cast<string>()
            .ToArray();

        return new AcmeOrderContext(
            response.Location,
            GetRequiredString(root, "finalize"),
            authorizationUrls);
    }

    private async Task CompleteHttp01ChallengesAsync(
        CertificateOptions config,
        AcmeDirectoryDocument directory,
        AcmeAccountContext account,
        IReadOnlyList<string> authorizationUrls,
        CancellationToken cancellationToken)
    {
        await EnsureChallengeListenerReadyAsync(config, cancellationToken).ConfigureAwait(false);

        foreach (var authorizationUrl in authorizationUrls)
        {
            var authorization = await GetAuthorizationAsync(directory, account, authorizationUrl, cancellationToken).ConfigureAwait(false);
            if (string.Equals(authorization.Status, "valid", StringComparison.Ordinal))
            {
                continue;
            }

            if (!string.Equals(authorization.Status, "pending", StringComparison.Ordinal))
            {
                throw new InvalidOperationException(
                    $"Authorization for {authorization.Identifier} is in unexpected state '{authorization.Status}'. {authorization.ErrorDetail}".Trim());
            }

            if (string.IsNullOrWhiteSpace(authorization.ChallengeUrl) || string.IsNullOrWhiteSpace(authorization.Token))
            {
                throw new InvalidOperationException($"Authorization for {authorization.Identifier} does not contain an http-01 challenge.");
            }

            var keyAuthorization = $"{authorization.Token}.{account.JwkThumbprint}";
            _challengeStore.PutResponse(authorization.Token, keyAuthorization);

            try
            {
                await SendSignedRequestAsync(
                    authorization.ChallengeUrl,
                    "{}",
                    directory,
                    account,
                    useKid: true,
                    accept: null,
                    cancellationToken).ConfigureAwait(false);

                await WaitForAuthorizationAsync(directory, account, authorizationUrl, authorization.Identifier, cancellationToken).ConfigureAwait(false);
            }
            finally
            {
                _challengeStore.RemoveResponse(authorization.Token);
            }
        }
    }

    private async Task EnsureChallengeListenerReadyAsync(CertificateOptions config, CancellationToken cancellationToken)
    {
        var snapshot = _challengeStore.GetListenerSnapshot();
        if (IsMatchingListener(snapshot, config))
        {
            return;
        }

        using var waitCts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        waitCts.CancelAfter(TimeSpan.FromSeconds(10));

        try
        {
            while (!waitCts.IsCancellationRequested)
            {
                await _challengeStore.WaitForListenerChangeAsync(snapshot.Version, waitCts.Token).ConfigureAwait(false);
                snapshot = _challengeStore.GetListenerSnapshot();
                if (IsMatchingListener(snapshot, config))
                {
                    return;
                }
            }
        }
        catch (OperationCanceledException) when (!cancellationToken.IsCancellationRequested)
        {
        }

        var reason = string.IsNullOrWhiteSpace(snapshot.LastError)
            ? "HTTP-01 listener is not ready."
            : snapshot.LastError;
        throw new InvalidOperationException(reason);
    }

    private static bool IsMatchingListener(AcmeHttpChallengeListenerSnapshot snapshot, CertificateOptions config)
        => snapshot.IsListening &&
           snapshot.Port == config.HttpChallengePort &&
           string.Equals(snapshot.ListenAddress, config.HttpChallengeListenAddress, StringComparison.Ordinal);

    private async Task<AcmeAuthorizationDocument> GetAuthorizationAsync(
        AcmeDirectoryDocument directory,
        AcmeAccountContext account,
        string authorizationUrl,
        CancellationToken cancellationToken)
    {
        var response = await SendSignedRequestAsync(
            authorizationUrl,
            string.Empty,
            directory,
            account,
            useKid: true,
            accept: null,
            cancellationToken).ConfigureAwait(false);

        using var document = JsonDocument.Parse(response.Body);
        var root = document.RootElement;

        var identifier = root.TryGetProperty("identifier", out var identifierElement)
            ? GetRequiredString(identifierElement, "value")
            : authorizationUrl;

        var status = GetRequiredString(root, "status");
        string challengeUrl = string.Empty;
        string token = string.Empty;
        var errorDetail = ExtractProblemDetail(root);

        if (root.TryGetProperty("challenges", out var challengeArray))
        {
            foreach (var challenge in challengeArray.EnumerateArray())
            {
                if (!string.Equals(GetRequiredString(challenge, "type"), CertificateChallengeTypes.Http01, StringComparison.Ordinal))
                {
                    continue;
                }

                challengeUrl = GetRequiredString(challenge, "url");
                token = GetRequiredString(challenge, "token");

                if (string.IsNullOrWhiteSpace(errorDetail) && challenge.TryGetProperty("error", out var challengeError))
                {
                    errorDetail = ExtractProblemDetail(challengeError);
                }

                break;
            }
        }

        return new AcmeAuthorizationDocument(identifier, status, challengeUrl, token, errorDetail);
    }

    private async Task WaitForAuthorizationAsync(
        AcmeDirectoryDocument directory,
        AcmeAccountContext account,
        string authorizationUrl,
        string identifier,
        CancellationToken cancellationToken)
    {
        for (var attempt = 0; attempt < 60; attempt++)
        {
            var current = await GetAuthorizationAsync(directory, account, authorizationUrl, cancellationToken).ConfigureAwait(false);
            if (string.Equals(current.Status, "valid", StringComparison.Ordinal))
            {
                return;
            }

            if (string.Equals(current.Status, "invalid", StringComparison.Ordinal))
            {
                var detail = string.IsNullOrWhiteSpace(current.ErrorDetail) ? "ACME authorization failed." : current.ErrorDetail;
                throw new InvalidOperationException($"{identifier}: {detail}");
            }

            await Task.Delay(TimeSpan.FromSeconds(2), cancellationToken).ConfigureAwait(false);
        }

        throw new TimeoutException($"Timed out waiting for ACME authorization of {identifier}.");
    }

    private async Task<string> FinalizeOrderAsync(
        AcmeDirectoryDocument directory,
        AcmeAccountContext account,
        AcmeOrderContext order,
        byte[] csr,
        CancellationToken cancellationToken)
    {
        var payload = BuildFinalizePayload(csr);
        await SendSignedRequestAsync(
            order.FinalizeUrl,
            payload,
            directory,
            account,
            useKid: true,
            accept: null,
            cancellationToken).ConfigureAwait(false);

        for (var attempt = 0; attempt < 90; attempt++)
        {
            var current = await GetOrderStatusAsync(directory, account, order.OrderUrl, cancellationToken).ConfigureAwait(false);
            if (string.Equals(current.Status, "valid", StringComparison.Ordinal) && !string.IsNullOrWhiteSpace(current.CertificateUrl))
            {
                return current.CertificateUrl;
            }

            if (string.Equals(current.Status, "invalid", StringComparison.Ordinal))
            {
                var detail = string.IsNullOrWhiteSpace(current.ErrorDetail) ? "ACME order failed." : current.ErrorDetail;
                throw new InvalidOperationException(detail);
            }

            await Task.Delay(TimeSpan.FromSeconds(2), cancellationToken).ConfigureAwait(false);
        }

        throw new TimeoutException($"Timed out waiting for ACME order to finalize for {order.OrderUrl}.");
    }

    private async Task<AcmeOrderStatusDocument> GetOrderStatusAsync(
        AcmeDirectoryDocument directory,
        AcmeAccountContext account,
        string orderUrl,
        CancellationToken cancellationToken)
    {
        var response = await SendSignedRequestAsync(
            orderUrl,
            string.Empty,
            directory,
            account,
            useKid: true,
            accept: null,
            cancellationToken).ConfigureAwait(false);

        using var document = JsonDocument.Parse(response.Body);
        var root = document.RootElement;
        var certificateUrl = root.TryGetProperty("certificate", out var certificateElement)
            ? certificateElement.GetString() ?? string.Empty
            : string.Empty;

        return new AcmeOrderStatusDocument(
            GetRequiredString(root, "status"),
            certificateUrl,
            ExtractProblemDetail(root));
    }

    private async Task<string> DownloadCertificateAsync(
        AcmeDirectoryDocument directory,
        AcmeAccountContext account,
        string certificateUrl,
        CancellationToken cancellationToken)
    {
        var response = await SendSignedRequestAsync(
            certificateUrl,
            string.Empty,
            directory,
            account,
            useKid: true,
            accept: "application/pem-certificate-chain",
            cancellationToken).ConfigureAwait(false);

        return response.Body;
    }

    private static byte[] CreateCertificateSigningRequest(CertificateOptions config, RSA key)
    {
        var request = new CertificateRequest(
            $"CN={config.Domain}",
            key,
            HashAlgorithmName.SHA256,
            RSASignaturePadding.Pkcs1);

        request.CertificateExtensions.Add(new X509BasicConstraintsExtension(false, false, 0, false));
        request.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.DigitalSignature | X509KeyUsageFlags.KeyEncipherment, false));
        request.CertificateExtensions.Add(new X509SubjectKeyIdentifierExtension(request.PublicKey, false));

        var subjectAlternativeNames = new SubjectAlternativeNameBuilder();
        foreach (var domain in ResolveDomains(config))
        {
            subjectAlternativeNames.AddDnsName(domain);
        }

        request.CertificateExtensions.Add(subjectAlternativeNames.Build());
        return request.CreateSigningRequest();
    }

    private static void WriteCertificatePackage(CertificateOptions config, string fullChainPem, RSA certificateKey)
    {
        var certificates = ReadCertificates(fullChainPem);
        if (certificates.Count == 0)
        {
            throw new InvalidOperationException("ACME certificate response did not contain any certificates.");
        }

        try
        {
            using var leafWithPrivateKey = certificates[0].CopyWithPrivateKey(certificateKey);
            var exportCollection = new X509Certificate2Collection();
            exportCollection.Add(leafWithPrivateKey);

            foreach (var certificate in certificates.Skip(1))
            {
                if (!string.Equals(certificate.Thumbprint, leafWithPrivateKey.Thumbprint, StringComparison.OrdinalIgnoreCase))
                {
                    exportCollection.Add(certificate);
                }
            }

            var pfxBytes = exportCollection.Export(X509ContentType.Pkcs12, config.PfxPassword);
            if (pfxBytes is null || pfxBytes.Length == 0)
            {
                throw new InvalidOperationException("Failed to export the ACME certificate package.");
            }

            var outputPath = Path.GetFullPath(config.PfxPath);
            var directory = Path.GetDirectoryName(outputPath);
            if (!string.IsNullOrWhiteSpace(directory))
            {
                Directory.CreateDirectory(directory);
            }

            var tempPath = outputPath + ".tmp";
            File.WriteAllBytes(tempPath, pfxBytes);
            File.Move(tempPath, outputPath, overwrite: true);
        }
        finally
        {
            foreach (var certificate in certificates)
            {
                certificate.Dispose();
            }
        }
    }

    private async Task<AcmeHttpResponse> SendSignedRequestAsync(
        string url,
        string payloadJson,
        AcmeDirectoryDocument directory,
        AcmeAccountContext account,
        bool useKid,
        string? accept,
        CancellationToken cancellationToken)
    {
        for (var attempt = 0; attempt < 2; attempt++)
        {
            var nonce = await ConsumeNonceAsync(directory.NewNonceUrl, cancellationToken).ConfigureAwait(false);
            using var request = new HttpRequestMessage(HttpMethod.Post, url)
            {
                Content = CreateJwsContent(url, payloadJson, nonce, account, useKid)
            };

            if (!string.IsNullOrWhiteSpace(accept))
            {
                request.Headers.Accept.ParseAdd(accept);
            }

            using var response = await _httpClient.SendAsync(request, cancellationToken).ConfigureAwait(false);
            CaptureReplayNonce(response);
            var body = await response.Content.ReadAsStringAsync(cancellationToken).ConfigureAwait(false);

            if (response.IsSuccessStatusCode)
            {
                return new AcmeHttpResponse(
                    body,
                    response.Headers.Location?.ToString() ?? string.Empty);
            }

            if (attempt == 0 && IsBadNonce(body))
            {
                continue;
            }

            throw CreateAcmeException(response.StatusCode, body);
        }

        throw new InvalidOperationException("ACME request retry budget was exhausted.");
    }

    private HttpContent CreateJwsContent(
        string url,
        string payloadJson,
        string nonce,
        AcmeAccountContext account,
        bool useKid)
    {
        var protectedHeader = Base64UrlEncode(BuildProtectedHeader(url, nonce, account, useKid));
        var payload = payloadJson.Length == 0
            ? string.Empty
            : Base64UrlEncode(Encoding.UTF8.GetBytes(payloadJson));

        var signingInput = Encoding.ASCII.GetBytes($"{protectedHeader}.{payload}");
        var signature = account.Key.SignData(
            signingInput,
            HashAlgorithmName.SHA256,
            DSASignatureFormat.IeeeP1363FixedFieldConcatenation);

        var body = $"{{\"protected\":\"{protectedHeader}\",\"payload\":\"{payload}\",\"signature\":\"{Base64UrlEncode(signature)}\"}}";
        var content = new ByteArrayContent(Encoding.UTF8.GetBytes(body));
        content.Headers.ContentType = MediaTypeHeaderValue.Parse("application/jose+json");
        return content;
    }

    private byte[] BuildProtectedHeader(string url, string nonce, AcmeAccountContext account, bool useKid)
    {
        var buffer = new ArrayBufferWriter<byte>();
        using (var writer = new Utf8JsonWriter(buffer))
        {
            writer.WriteStartObject();
            writer.WriteString("alg", "ES256");
            if (useKid)
            {
                writer.WriteString("kid", account.AccountUrl);
            }
            else
            {
                writer.WriteStartObject("jwk");
                writer.WriteString("crv", "P-256");
                writer.WriteString("kty", "EC");
                writer.WriteString("x", account.JwkX);
                writer.WriteString("y", account.JwkY);
                writer.WriteEndObject();
            }

            writer.WriteString("nonce", nonce);
            writer.WriteString("url", url);
            writer.WriteEndObject();
        }

        return buffer.WrittenSpan.ToArray();
    }

    private async Task<string> ConsumeNonceAsync(string newNonceUrl, CancellationToken cancellationToken)
    {
        await _nonceGate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            if (!string.IsNullOrWhiteSpace(_replayNonce))
            {
                var nonce = _replayNonce;
                _replayNonce = string.Empty;
                return nonce;
            }
        }
        finally
        {
            _nonceGate.Release();
        }

        using var request = new HttpRequestMessage(HttpMethod.Head, newNonceUrl);
        using var response = await _httpClient.SendAsync(request, cancellationToken).ConfigureAwait(false);
        response.EnsureSuccessStatusCode();

        var nonceValue = GetReplayNonce(response);
        if (string.IsNullOrWhiteSpace(nonceValue))
        {
            throw new InvalidOperationException("ACME server did not return a Replay-Nonce header.");
        }

        return nonceValue;
    }

    private void CaptureReplayNonce(HttpResponseMessage response)
    {
        var replayNonce = GetReplayNonce(response);
        if (string.IsNullOrWhiteSpace(replayNonce))
        {
            return;
        }

        _replayNonce = replayNonce;
    }

    private static string GetReplayNonce(HttpResponseMessage response)
        => response.Headers.TryGetValues("Replay-Nonce", out var values)
            ? values.FirstOrDefault() ?? string.Empty
            : string.Empty;

    private static bool IsBadNonce(string body)
    {
        try
        {
            using var document = JsonDocument.Parse(body);
            return document.RootElement.TryGetProperty("type", out var typeElement) &&
                   string.Equals(typeElement.GetString(), "urn:ietf:params:acme:error:badNonce", StringComparison.Ordinal);
        }
        catch (JsonException)
        {
            return false;
        }
    }

    private static Exception CreateAcmeException(HttpStatusCode statusCode, string body)
    {
        var detail = body;
        try
        {
            using var document = JsonDocument.Parse(body);
            detail = ExtractProblemDetail(document.RootElement);
        }
        catch (JsonException)
        {
        }

        detail = string.IsNullOrWhiteSpace(detail) ? $"HTTP {(int)statusCode}" : detail;
        return new InvalidOperationException($"ACME request failed: {detail}");
    }

    private static string BuildNewAccountPayload(string email)
    {
        var buffer = new ArrayBufferWriter<byte>();
        using (var writer = new Utf8JsonWriter(buffer))
        {
            writer.WriteStartObject();
            writer.WriteBoolean("termsOfServiceAgreed", true);
            if (!string.IsNullOrWhiteSpace(email))
            {
                writer.WriteStartArray("contact");
                writer.WriteStringValue($"mailto:{email}");
                writer.WriteEndArray();
            }

            writer.WriteEndObject();
        }

        return Encoding.UTF8.GetString(buffer.WrittenSpan);
    }

    private static string BuildNewOrderPayload(IReadOnlyList<string> domains)
    {
        var buffer = new ArrayBufferWriter<byte>();
        using (var writer = new Utf8JsonWriter(buffer))
        {
            writer.WriteStartObject();
            writer.WriteStartArray("identifiers");
            foreach (var domain in domains)
            {
                writer.WriteStartObject();
                writer.WriteString("type", "dns");
                writer.WriteString("value", domain);
                writer.WriteEndObject();
            }

            writer.WriteEndArray();
            writer.WriteEndObject();
        }

        return Encoding.UTF8.GetString(buffer.WrittenSpan);
    }

    private static string BuildFinalizePayload(ReadOnlySpan<byte> csr)
    {
        var buffer = new ArrayBufferWriter<byte>();
        using (var writer = new Utf8JsonWriter(buffer))
        {
            writer.WriteStartObject();
            writer.WriteString("csr", Base64UrlEncode(csr));
            writer.WriteEndObject();
        }

        return Encoding.UTF8.GetString(buffer.WrittenSpan);
    }

    private static IReadOnlyList<string> ResolveDomains(CertificateOptions config)
        => new[] { config.Domain }
            .Concat(config.AltNames)
            .Where(static value => !string.IsNullOrWhiteSpace(value))
            .Select(static value => value.Trim())
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .ToArray();

    private static string ResolveStateDirectory(CertificateOptions config)
    {
        var root = string.IsNullOrWhiteSpace(config.WorkingDirectory)
            ? Path.GetDirectoryName(Path.GetFullPath(config.PfxPath)) ?? AppContext.BaseDirectory
            : Path.GetFullPath(config.WorkingDirectory);

        var directoryHash = Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(AcmeKnownDirectoryUrls.Resolve(config))))[..12].ToLowerInvariant();
        return Path.Combine(root, ".acme", $"{SanitizeFileSegment(config.Domain)}-{directoryHash}");
    }

    private static string SanitizeFileSegment(string value)
    {
        if (string.IsNullOrWhiteSpace(value))
        {
            return "default";
        }

        var invalidCharacters = Path.GetInvalidFileNameChars();
        var builder = new StringBuilder(value.Length);
        foreach (var character in value)
        {
            builder.Append(invalidCharacters.Contains(character) ? '_' : character);
        }

        return builder.ToString();
    }

    private static List<X509Certificate2> ReadCertificates(string pem)
    {
        const string beginMarker = "-----BEGIN CERTIFICATE-----";
        const string endMarker = "-----END CERTIFICATE-----";

        var certificates = new List<X509Certificate2>();
        var offset = 0;
        while (true)
        {
            var begin = pem.IndexOf(beginMarker, offset, StringComparison.Ordinal);
            if (begin < 0)
            {
                break;
            }

            begin += beginMarker.Length;
            var end = pem.IndexOf(endMarker, begin, StringComparison.Ordinal);
            if (end < 0)
            {
                throw new InvalidOperationException("Incomplete PEM certificate block.");
            }

            var base64 = pem[begin..end]
                .Replace("\r", string.Empty, StringComparison.Ordinal)
                .Replace("\n", string.Empty, StringComparison.Ordinal)
                .Trim();

            certificates.Add(X509CertificateLoader.LoadCertificate(Convert.FromBase64String(base64)));
            offset = end + endMarker.Length;
        }

        return certificates;
    }

    private static string Base64UrlEncode(ReadOnlySpan<byte> value)
        => Convert.ToBase64String(value)
            .TrimEnd('=')
            .Replace('+', '-')
            .Replace('/', '_');

    private static string GetRequiredString(JsonElement element, string propertyName)
    {
        if (!element.TryGetProperty(propertyName, out var property))
        {
            throw new InvalidOperationException($"ACME response is missing '{propertyName}'.");
        }

        var value = property.GetString();
        if (string.IsNullOrWhiteSpace(value))
        {
            throw new InvalidOperationException($"ACME response field '{propertyName}' is empty.");
        }

        return value;
    }

    private static string ExtractProblemDetail(JsonElement element)
    {
        if (element.ValueKind == JsonValueKind.Object)
        {
            if (element.TryGetProperty("detail", out var detail))
            {
                return detail.GetString() ?? string.Empty;
            }

            if (element.TryGetProperty("error", out var error))
            {
                return ExtractProblemDetail(error);
            }
        }

        return string.Empty;
    }

    private sealed record AcmeDirectoryDocument(string NewNonceUrl, string NewAccountUrl, string NewOrderUrl);

    private sealed record AcmeOrderContext(string OrderUrl, string FinalizeUrl, IReadOnlyList<string> AuthorizationUrls);

    private sealed record AcmeAuthorizationDocument(
        string Identifier,
        string Status,
        string ChallengeUrl,
        string Token,
        string ErrorDetail);

    private sealed record AcmeOrderStatusDocument(string Status, string CertificateUrl, string ErrorDetail);

    private sealed record AcmeHttpResponse(string Body, string Location);

    private sealed class AcmeAccountContext : IDisposable
    {
        private AcmeAccountContext(ECDsa key, string accountUrl, string jwkX, string jwkY, string jwkThumbprint)
        {
            Key = key;
            AccountUrl = accountUrl;
            JwkX = jwkX;
            JwkY = jwkY;
            JwkThumbprint = jwkThumbprint;
        }

        public string AccountUrl { get; set; }

        public string JwkThumbprint { get; }

        public string JwkX { get; }

        public string JwkY { get; }

        public ECDsa Key { get; }

        public void Dispose() => Key.Dispose();

        public static AcmeAccountContext Create(ECDsa key, string accountUrl)
        {
            var parameters = key.ExportParameters(false);
            var jwkX = Base64UrlEncode(parameters.Q.X);
            var jwkY = Base64UrlEncode(parameters.Q.Y);
            var thumbprintPayload = Encoding.UTF8.GetBytes($"{{\"crv\":\"P-256\",\"kty\":\"EC\",\"x\":\"{jwkX}\",\"y\":\"{jwkY}\"}}");
            var jwkThumbprint = Base64UrlEncode(SHA256.HashData(thumbprintPayload));
            return new AcmeAccountContext(key, accountUrl, jwkX, jwkY, jwkThumbprint);
        }
    }
}

using System.Collections.Concurrent;
using System.Diagnostics;
using System.Security.Cryptography.X509Certificates;
using Certes;
using Certes.Acme;
using Certes.Acme.Resource;
using Microsoft.Extensions.Logging;
using NodePanel.ControlPlane.Configuration;
using NodePanel.Panel.Models;

namespace NodePanel.Panel.Services;

public sealed class PanelCertificateService
{
    private readonly ConcurrentDictionary<string, SemaphoreSlim> _gates = new(StringComparer.Ordinal);
    private readonly DatabaseService _db;
    private readonly PanelDnsChallengeService _dnsChallengeService;
    private readonly ILogger<PanelCertificateService> _logger;
    private readonly PanelAcmeHttpChallengeStore _httpChallengeStore;
    private readonly PanelCertificateProgressTracker _panelCertificateProgressTracker;
    private readonly PanelHttpsRuntime _panelHttpsRuntime;
    private readonly PanelMutationService _panelMutationService;

    public PanelCertificateService(
        DatabaseService db,
        PanelDnsChallengeService dnsChallengeService,
        PanelAcmeHttpChallengeStore httpChallengeStore,
        PanelMutationService panelMutationService,
        PanelHttpsRuntime panelHttpsRuntime,
        PanelCertificateProgressTracker panelCertificateProgressTracker,
        ILogger<PanelCertificateService> logger)
    {
        _db = db;
        _dnsChallengeService = dnsChallengeService;
        _httpChallengeStore = httpChallengeStore;
        _panelMutationService = panelMutationService;
        _panelHttpsRuntime = panelHttpsRuntime;
        _panelCertificateProgressTracker = panelCertificateProgressTracker;
        _logger = logger;
    }

    public static bool IsRenewalDue(PanelCertificateRecord record, DateTimeOffset now)
    {
        ArgumentNullException.ThrowIfNull(record);

        if (record.NotAfter is null)
        {
            return true;
        }

        return now >= record.NotAfter.Value.AddDays(-Math.Max(1, record.RenewBeforeDays));
    }

    public static bool ShouldProcess(PanelCertificateRecord record, DateTimeOffset now)
    {
        ArgumentNullException.ThrowIfNull(record);

        if (!record.Enabled)
        {
            return false;
        }

        var interval = TimeSpan.FromMinutes(Math.Max(1, record.CheckIntervalMinutes));
        if (record.LastAttemptAt is DateTimeOffset lastAttempt && now - lastAttempt < interval)
        {
            return false;
        }

        return string.IsNullOrWhiteSpace(record.PfxBase64) || IsRenewalDue(record, now);
    }

    public async Task<PanelCertificateRecord?> RenewAsync(
        string certificateId,
        bool ignoreSchedule,
        CancellationToken cancellationToken = default)
    {
        if (!_db.IsConfigured)
        {
            throw new InvalidOperationException("Database is not configured.");
        }

        var normalizedCertificateId = certificateId?.Trim() ?? string.Empty;
        if (string.IsNullOrWhiteSpace(normalizedCertificateId))
        {
            throw new ArgumentException("Certificate id is required.", nameof(certificateId));
        }

        var gate = _gates.GetOrAdd(normalizedCertificateId, static _ => new SemaphoreSlim(1, 1));
        await gate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            var entity = await _db.FSql.Select<PanelCertificateEntity>()
                .Where(item => item.CertificateId == normalizedCertificateId)
                .FirstAsync(cancellationToken)
                .ConfigureAwait(false);

            if (entity is null)
            {
                return null;
            }

            var record = entity.ToRecord();
            if (!ignoreSchedule && !ShouldProcess(record, DateTimeOffset.UtcNow))
            {
                return record;
            }

            var triggerSource = ignoreSchedule ? "manual" : "auto";
            ValidateCertificate(record);
            StartProgress(normalizedCertificateId, triggerSource, "正在校验证书配置。");

            entity.LastAttemptAt = DateTimeOffset.UtcNow;
            entity.LastError = string.Empty;
            entity.UpdatedAt = DateTimeOffset.UtcNow;
            await _db.FSql.InsertOrUpdate<PanelCertificateEntity>()
                .SetSource(entity)
                .ExecuteAffrowsAsync(cancellationToken)
                .ConfigureAwait(false);

            var issued = await IssueCoreAsync(entity, triggerSource, cancellationToken).ConfigureAwait(false);
            entity.AcmeAccountKeyPem = issued.AccountKeyPem;
            entity.PfxBase64 = Convert.ToBase64String(issued.PfxBytes);
            entity.AssetVersion = entity.AssetVersion > 0 ? entity.AssetVersion + 1 : 1;
            entity.Thumbprint = issued.Thumbprint;
            entity.NotBefore = issued.NotBefore;
            entity.NotAfter = issued.NotAfter;
            entity.LastSuccessAt = DateTimeOffset.UtcNow;
            entity.LastError = string.Empty;
            entity.UpdatedAt = DateTimeOffset.UtcNow;

            ReportProgress(entity.CertificateId, triggerSource, issued.TotalSteps - 1, issued.TotalSteps, "正在向绑定节点下发最新证书。");
            await _db.FSql.InsertOrUpdate<PanelCertificateEntity>()
                .SetSource(entity)
                .ExecuteAffrowsAsync(cancellationToken)
                .ConfigureAwait(false);

            var affectedNodes = await _panelMutationService
                .PushNodesUsingPanelCertificateAsync(entity.CertificateId, cancellationToken)
                .ConfigureAwait(false);

            ReportProgress(entity.CertificateId, triggerSource, issued.TotalSteps, issued.TotalSteps, "正在刷新 Panel HTTPS 运行时证书。");
            await _panelHttpsRuntime.RefreshAsync(cancellationToken).ConfigureAwait(false);

            _logger.LogInformation(
                "Panel certificate {CertificateId} issued successfully. Bound nodes pushed: {NodeCount}.",
                entity.CertificateId,
                affectedNodes.Count);

            return entity.ToRecord();
        }
        catch (Exception ex)
        {
            await RecordFailureAsync(normalizedCertificateId, ex, cancellationToken).ConfigureAwait(false);
            _logger.LogWarning(ex, "Failed to issue panel certificate {CertificateId}.", normalizedCertificateId);
            throw;
        }
        finally
        {
            CompleteProgress(normalizedCertificateId);
            gate.Release();
        }
    }

    private async Task RecordFailureAsync(string certificateId, Exception exception, CancellationToken cancellationToken)
    {
        if (!_db.IsConfigured)
        {
            return;
        }

        var entity = await _db.FSql.Select<PanelCertificateEntity>()
            .Where(item => item.CertificateId == certificateId)
            .FirstAsync(cancellationToken)
            .ConfigureAwait(false);

        if (entity is null)
        {
            return;
        }

        entity.LastAttemptAt = DateTimeOffset.UtcNow;
        entity.LastError = exception.Message;
        entity.UpdatedAt = DateTimeOffset.UtcNow;

        await _db.FSql.InsertOrUpdate<PanelCertificateEntity>()
            .SetSource(entity)
            .ExecuteAffrowsAsync(cancellationToken)
            .ConfigureAwait(false);
    }

    private async Task<IssuedPanelCertificate> IssueCoreAsync(
        PanelCertificateEntity entity,
        string triggerSource,
        CancellationToken cancellationToken)
    {
        var record = entity.ToRecord();
        ReportProgress(record.CertificateId, triggerSource, 2, 0, "正在初始化 ACME 账户。");
        var accountKey = string.IsNullOrWhiteSpace(entity.AcmeAccountKeyPem)
            ? KeyFactory.NewKey(KeyAlgorithm.ES256)
            : KeyFactory.FromPem(entity.AcmeAccountKeyPem);

        var acme = new AcmeContext(AcmeKnownDirectoryUrls.Resolve(record), accountKey);
        var contacts = string.IsNullOrWhiteSpace(record.Email)
            ? new List<string>()
            : new List<string> { $"mailto:{record.Email.Trim()}" };
        _ = await acme.NewAccount(contacts, true, null, null, null).ConfigureAwait(false);

        ReportProgress(record.CertificateId, triggerSource, 3, 0, "正在创建 ACME 证书订单。");
        var domains = ResolveDomains(record);
        var order = await acme.NewOrder(domains.ToList()).ConfigureAwait(false);
        var authorizations = await order.Authorizations().ConfigureAwait(false);
        var totalSteps = (authorizations.Count() * 2) + 6;
        var currentStep = 4;

        foreach (var authorizationContext in authorizations)
        {
            var authorization = await authorizationContext.Resource().ConfigureAwait(false);
            if (authorization.Status == AuthorizationStatus.Valid)
            {
                continue;
            }

            if (authorization.Status != AuthorizationStatus.Pending)
            {
                throw new InvalidOperationException(
                    $"域名 {authorization.Identifier.Value} 当前授权状态异常: {authorization.Status}。");
            }

            var challengeType = AcmeKnownDirectoryUrls.NormalizeChallengeType(record.ChallengeType);
            switch (challengeType)
            {
                case CertificateChallengeTypes.Http01:
                    await CompleteHttpChallengeAsync(
                            record.CertificateId,
                            triggerSource,
                            totalSteps,
                            currentStep,
                            authorizationContext,
                            authorization,
                            cancellationToken)
                        .ConfigureAwait(false);
                    break;

                case CertificateChallengeTypes.Dns01:
                    await CompleteDnsChallengeAsync(
                            acme,
                            record,
                            triggerSource,
                            totalSteps,
                            currentStep,
                            authorizationContext,
                            authorization,
                            cancellationToken)
                        .ConfigureAwait(false);
                    break;

                default:
                    throw new InvalidOperationException($"Panel 不支持的 challenge 类型: {record.ChallengeType}。");
            }

            currentStep += 2;
        }

        ReportProgress(record.CertificateId, triggerSource, totalSteps - 2, totalSteps, "ACME 授权完成，正在生成证书文件。");
        var certificateKey = KeyFactory.NewKey(KeyAlgorithm.RS256);
        var certificateChain = await order.Generate(
                new CsrInfo
                {
                    CommonName = record.Domain.Trim()
                },
                certificateKey)
            .ConfigureAwait(false);

        var pfxBytes = certificateChain.ToPfx(certificateKey).Build(record.Domain.Trim(), record.PfxPassword ?? string.Empty);
        using var certificate = X509CertificateLoader.LoadPkcs12(
            pfxBytes,
            record.PfxPassword,
            X509KeyStorageFlags.EphemeralKeySet | X509KeyStorageFlags.Exportable);

        return new IssuedPanelCertificate
        {
            AccountKeyPem = accountKey.ToPem(),
            PfxBytes = pfxBytes,
            Thumbprint = certificate.Thumbprint ?? string.Empty,
            NotBefore = new DateTimeOffset(certificate.NotBefore),
            NotAfter = new DateTimeOffset(certificate.NotAfter),
            TotalSteps = totalSteps
        };
    }

    private async Task CompleteHttpChallengeAsync(
        string certificateId,
        string triggerSource,
        int totalSteps,
        int currentStep,
        IAuthorizationContext authorizationContext,
        Authorization authorization,
        CancellationToken cancellationToken)
    {
        var challenge = await authorizationContext.Http().ConfigureAwait(false);
        if (challenge is null)
        {
            throw new InvalidOperationException($"域名 {authorization.Identifier.Value} 未提供 http-01 challenge。");
        }

        ReportProgress(certificateId, triggerSource, currentStep, totalSteps, $"正在写入 HTTP-01 challenge：{authorization.Identifier.Value}。");
        _httpChallengeStore.Put(challenge.Token, challenge.KeyAuthz);
        try
        {
            _ = await challenge.Validate().ConfigureAwait(false);
            ReportProgress(certificateId, triggerSource, currentStep + 1, totalSteps, $"HTTP-01 challenge 已提交，等待 ACME 验证：{authorization.Identifier.Value}。");
            await WaitForAuthorizationAsync(
                    authorizationContext,
                    authorization.Identifier.Value,
                    certificateId,
                    triggerSource,
                    currentStep + 1,
                    totalSteps,
                    cancellationToken)
                .ConfigureAwait(false);
        }
        finally
        {
            _httpChallengeStore.Remove(challenge.Token);
        }
    }

    private async Task CompleteDnsChallengeAsync(
        AcmeContext acme,
        PanelCertificateRecord record,
        string triggerSource,
        int totalSteps,
        int currentStep,
        IAuthorizationContext authorizationContext,
        Authorization authorization,
        CancellationToken cancellationToken)
    {
        var challenge = await authorizationContext.Dns().ConfigureAwait(false);
        if (challenge is null)
        {
            throw new InvalidOperationException($"域名 {authorization.Identifier.Value} 未提供 dns-01 challenge。");
        }

        var identifier = authorization.Identifier.Value;
        var recordName = BuildDnsRecordName(identifier);
        var recordValue = acme.AccountKey.DnsTxt(challenge.Token);
        var hookContext = new DnsHookContext
        {
            CertificateId = record.CertificateId,
            Domain = identifier,
            RecordName = recordName,
            RecordValue = recordValue,
            ChallengeToken = challenge.Token
        };

        ReportProgress(record.CertificateId, triggerSource, currentStep, totalSteps, $"正在写入 DNS challenge：{identifier}。");
        if (_dnsChallengeService.HasApiProvider(record))
        {
            await _dnsChallengeService
                .PresentTxtRecordAsync(record, recordName, recordValue, cancellationToken)
                .ConfigureAwait(false);
        }
        else
        {
            await ExecuteDnsHookAsync(
                    record,
                    record.DnsHookPresentCommand,
                    record.DnsHookPresentArguments,
                    hookContext,
                    cleanup: false,
                    cancellationToken)
                .ConfigureAwait(false);
        }

        try
        {
            if (_dnsChallengeService.HasApiProvider(record))
            {
                var propagationDelay = _dnsChallengeService.GetPropagationDelay(record);
                ReportProgress(
                    record.CertificateId,
                    triggerSource,
                    currentStep,
                    totalSteps,
                    $"DNS 记录已写入，等待传播：{identifier}（{Math.Max(1, (int)Math.Ceiling(propagationDelay.TotalSeconds))} 秒）。");
                await Task.Delay(propagationDelay, cancellationToken).ConfigureAwait(false);
            }

            _ = await challenge.Validate().ConfigureAwait(false);
            ReportProgress(record.CertificateId, triggerSource, currentStep + 1, totalSteps, $"DNS challenge 已提交，等待 ACME 验证：{identifier}。");
            await WaitForAuthorizationAsync(
                    authorizationContext,
                    identifier,
                    record.CertificateId,
                    triggerSource,
                    currentStep + 1,
                    totalSteps,
                    cancellationToken)
                .ConfigureAwait(false);
        }
        finally
        {
            try
            {
                ReportProgress(record.CertificateId, triggerSource, currentStep + 1, totalSteps, $"正在清理 DNS challenge：{identifier}。");
                if (_dnsChallengeService.HasApiProvider(record))
                {
                    await _dnsChallengeService
                        .CleanupTxtRecordAsync(record, recordName, recordValue, cancellationToken)
                        .ConfigureAwait(false);
                }
                else
                {
                    await ExecuteDnsHookAsync(
                            record,
                            record.DnsHookCleanupCommand,
                            record.DnsHookCleanupArguments,
                            hookContext,
                            cleanup: true,
                            cancellationToken)
                        .ConfigureAwait(false);
                }
            }
            catch (Exception ex)
            {
                _logger.LogWarning(ex, "DNS cleanup failed for certificate {CertificateId}.", record.CertificateId);
            }
        }
    }

    private async Task ExecuteDnsHookAsync(
        PanelCertificateRecord record,
        string command,
        string arguments,
        DnsHookContext context,
        bool cleanup,
        CancellationToken cancellationToken)
    {
        if (string.IsNullOrWhiteSpace(command))
        {
            if (!cleanup)
            {
                throw new InvalidOperationException("DNS-01 模式必须配置添加 TXT 记录命令。");
            }

            return;
        }

        using var process = new Process
        {
            StartInfo = new ProcessStartInfo
            {
                FileName = ReplaceDnsHookPlaceholders(command.Trim(), context),
                Arguments = ReplaceDnsHookPlaceholders(arguments, context),
                WorkingDirectory = AppContext.BaseDirectory,
                RedirectStandardError = true,
                RedirectStandardOutput = true,
                UseShellExecute = false,
                CreateNoWindow = true
            }
        };

        foreach (var variable in record.EnvironmentVariables)
        {
            if (string.IsNullOrWhiteSpace(variable.Name))
            {
                continue;
            }

            process.StartInfo.Environment[variable.Name.Trim()] = ReplaceDnsHookPlaceholders(variable.Value, context);
        }

        process.StartInfo.Environment["NP_ACME_CERTIFICATE_ID"] = context.CertificateId;
        process.StartInfo.Environment["NP_ACME_DOMAIN"] = context.Domain;
        process.StartInfo.Environment["NP_ACME_RECORD_NAME"] = context.RecordName;
        process.StartInfo.Environment["NP_ACME_RECORD_VALUE"] = context.RecordValue;
        process.StartInfo.Environment["NP_ACME_CHALLENGE_TOKEN"] = context.ChallengeToken;

        if (!process.Start())
        {
            throw new InvalidOperationException("无法启动 DNS hook 命令。");
        }

        using var timeoutCts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        timeoutCts.CancelAfter(TimeSpan.FromMinutes(5));

        var outputTask = process.StandardOutput.ReadToEndAsync(timeoutCts.Token);
        var errorTask = process.StandardError.ReadToEndAsync(timeoutCts.Token);
        await process.WaitForExitAsync(timeoutCts.Token).ConfigureAwait(false);

        var output = await outputTask.ConfigureAwait(false);
        var error = await errorTask.ConfigureAwait(false);

        if (process.ExitCode != 0)
        {
            var suffix = string.IsNullOrWhiteSpace(error) ? output : error;
            throw new InvalidOperationException($"DNS hook 退出码 {process.ExitCode}。{suffix}".Trim());
        }
    }

    private async Task WaitForAuthorizationAsync(
        IAuthorizationContext authorizationContext,
        string identifier,
        string certificateId,
        string triggerSource,
        int currentStep,
        int totalSteps,
        CancellationToken cancellationToken)
    {
        for (var attempt = 0; attempt < 60; attempt++)
        {
            if (attempt == 0 || (attempt + 1) % 5 == 0)
            {
                ReportProgress(
                    certificateId,
                    triggerSource,
                    currentStep,
                    totalSteps,
                    $"等待 ACME 验证 {identifier}（轮询 {attempt + 1}/60）。");
            }

            var authorization = await authorizationContext.Resource().ConfigureAwait(false);
            if (authorization.Status == AuthorizationStatus.Valid)
            {
                return;
            }

            if (authorization.Status == AuthorizationStatus.Invalid)
            {
                var detail = authorization.Challenges
                    .Where(static item => item.Error is not null)
                    .Select(item => item.Error!.Detail)
                    .FirstOrDefault(static item => !string.IsNullOrWhiteSpace(item));

                throw new InvalidOperationException(
                    string.IsNullOrWhiteSpace(detail)
                        ? $"域名 {identifier} 的 ACME 授权失败。"
                        : $"域名 {identifier} 的 ACME 授权失败: {detail}");
            }

            await Task.Delay(TimeSpan.FromSeconds(2), cancellationToken).ConfigureAwait(false);
        }

        throw new TimeoutException($"等待域名 {identifier} 的 ACME 授权完成超时。");
    }

    private void StartProgress(string certificateId, string triggerSource, string stage)
        => _panelCertificateProgressTracker.Start(certificateId, triggerSource, stage, currentStep: 1, totalSteps: 0);

    private void ReportProgress(string certificateId, string triggerSource, int currentStep, int totalSteps, string stage)
        => _panelCertificateProgressTracker.Update(certificateId, triggerSource, stage, currentStep, totalSteps);

    private void CompleteProgress(string certificateId)
        => _panelCertificateProgressTracker.Complete(certificateId);

    private static void ValidateCertificate(PanelCertificateRecord record)
    {
        if (string.IsNullOrWhiteSpace(record.CertificateId))
        {
            throw new InvalidOperationException("证书 ID 不能为空。");
        }

        if (string.IsNullOrWhiteSpace(record.Domain))
        {
            throw new InvalidOperationException("证书主域名不能为空。");
        }

        var challengeType = AcmeKnownDirectoryUrls.NormalizeChallengeType(record.ChallengeType);
        var containsWildcard = ResolveDomains(record).Any(static domain => domain.StartsWith("*.", StringComparison.Ordinal));
        if (containsWildcard && challengeType != CertificateChallengeTypes.Dns01)
        {
            throw new InvalidOperationException("泛域名证书只能使用 dns-01。");
        }

        if (challengeType != CertificateChallengeTypes.Dns01)
        {
            return;
        }

        var dnsProvider = PanelDnsProviderTypes.Normalize(record.DnsProvider);
        if (string.IsNullOrWhiteSpace(dnsProvider) && string.IsNullOrWhiteSpace(record.DnsHookPresentCommand))
        {
            throw new InvalidOperationException("dns-01 模式必须配置 DNS 服务商 API，或兼容模式的添加 TXT 记录命令。");
        }

        if (!string.IsNullOrWhiteSpace(dnsProvider) && string.IsNullOrWhiteSpace(record.DnsZone))
        {
            throw new InvalidOperationException("dns-01 API 模式必须填写根域名 / Zone。");
        }

        if (PanelDnsProviderTypes.RequiresApiToken(dnsProvider) && string.IsNullOrWhiteSpace(record.DnsApiToken))
        {
            throw new InvalidOperationException("Cloudflare dns-01 模式必须填写 API Token。");
        }

        if (PanelDnsProviderTypes.RequiresAccessKeyPair(dnsProvider) &&
            (string.IsNullOrWhiteSpace(record.DnsAccessKeyId) || string.IsNullOrWhiteSpace(record.DnsAccessKeySecret)))
        {
            throw new InvalidOperationException("AliDNS / DNSPod dns-01 模式必须填写 AccessKey ID / SecretId 和 AccessKey Secret / SecretKey。");
        }
    }

    private static IReadOnlyList<string> ResolveDomains(PanelCertificateRecord record)
        => record.AltNames
            .Prepend(record.Domain)
            .Where(static item => !string.IsNullOrWhiteSpace(item))
            .Select(static item => item.Trim())
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .ToArray();

    private static string BuildDnsRecordName(string domain)
    {
        var normalized = domain.Trim();
        if (normalized.StartsWith("*.", StringComparison.Ordinal))
        {
            normalized = normalized[2..];
        }

        return $"_acme-challenge.{normalized}";
    }

    private static string ReplaceDnsHookPlaceholders(string template, DnsHookContext context)
    {
        if (string.IsNullOrEmpty(template))
        {
            return string.Empty;
        }

        return template
            .Replace("{{certificate_id}}", context.CertificateId, StringComparison.Ordinal)
            .Replace("{{domain}}", context.Domain, StringComparison.Ordinal)
            .Replace("{{record_name}}", context.RecordName, StringComparison.Ordinal)
            .Replace("{{record_value}}", context.RecordValue, StringComparison.Ordinal)
            .Replace("{{challenge_token}}", context.ChallengeToken, StringComparison.Ordinal);
    }

    private sealed record DnsHookContext
    {
        public string CertificateId { get; init; } = string.Empty;

        public string Domain { get; init; } = string.Empty;

        public string RecordName { get; init; } = string.Empty;

        public string RecordValue { get; init; } = string.Empty;

        public string ChallengeToken { get; init; } = string.Empty;
    }

    private sealed record IssuedPanelCertificate
    {
        public string AccountKeyPem { get; init; } = string.Empty;

        public byte[] PfxBytes { get; init; } = Array.Empty<byte>();

        public string Thumbprint { get; init; } = string.Empty;

        public DateTimeOffset NotBefore { get; init; }

        public DateTimeOffset NotAfter { get; init; }

        public int TotalSteps { get; init; }
    }
}

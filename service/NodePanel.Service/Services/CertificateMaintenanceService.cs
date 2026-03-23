using System.Diagnostics;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using NodePanel.ControlPlane.Configuration;
using NodePanel.Service.Acme;
using NodePanel.Service.Runtime;

namespace NodePanel.Service.Services;

public sealed class CertificateMaintenanceService : BackgroundService
{
    private readonly CertificateStateStore _certificateStateStore;
    private readonly CertificateRenewalSignal _certificateRenewalSignal;
    private readonly ILogger<CertificateMaintenanceService> _logger;
    private readonly ManagedAcmeCertificateService _managedAcmeCertificateService;
    private readonly RuntimeConfigStore _runtimeConfigStore;

    public CertificateMaintenanceService(
        RuntimeConfigStore runtimeConfigStore,
        CertificateStateStore certificateStateStore,
        CertificateRenewalSignal certificateRenewalSignal,
        ManagedAcmeCertificateService managedAcmeCertificateService,
        ILogger<CertificateMaintenanceService> logger)
    {
        _runtimeConfigStore = runtimeConfigStore;
        _certificateStateStore = certificateStateStore;
        _certificateRenewalSignal = certificateRenewalSignal;
        _managedAcmeCertificateService = managedAcmeCertificateService;
        _logger = logger;
    }

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        var handledRenewalVersion = 0;

        while (!stoppingToken.IsCancellationRequested)
        {
            var runtime = _runtimeConfigStore.GetSnapshot();
            var previous = _certificateStateStore.GetSnapshot();
            var renewalRequest = _certificateRenewalSignal.GetSnapshot();
            var forceRenewal = renewalRequest.Version > handledRenewalVersion;

            var next = await EvaluateAsync(runtime, previous, forceRenewal, stoppingToken).ConfigureAwait(false);
            _certificateStateStore.Report(next);
            handledRenewalVersion = Math.Max(handledRenewalVersion, renewalRequest.Version);

            if (!ShouldPoll(runtime))
            {
                var configChange = _runtimeConfigStore.WaitForChangeAsync(runtime.Revision, stoppingToken);
                var renewalChange = _certificateRenewalSignal.WaitForChangeAsync(handledRenewalVersion, stoppingToken);
                await Task.WhenAny(configChange, renewalChange).ConfigureAwait(false);
                continue;
            }

            var delay = TimeSpan.FromMinutes(Math.Max(1, runtime.Config.Certificate.CheckIntervalMinutes));
            var changeTask = _runtimeConfigStore.WaitForChangeAsync(runtime.Revision, stoppingToken);
            var renewalTask = _certificateRenewalSignal.WaitForChangeAsync(handledRenewalVersion, stoppingToken);
            var pollTask = Task.Delay(delay, stoppingToken);
            await Task.WhenAny(changeTask, pollTask, renewalTask).ConfigureAwait(false);
        }
    }

    private async Task<CertificateRuntimeSnapshot> EvaluateAsync(
        NodeRuntimeSnapshot runtime,
        CertificateRuntimeSnapshot previous,
        bool forceRenewal,
        CancellationToken cancellationToken)
    {
        var config = runtime.Config;
        var certificate = config.Certificate;
        var mode = CertificateModes.Normalize(certificate.Mode);
        var baseState = new CertificateRuntimeSnapshot
        {
            AssetVersion = previous.AssetVersion,
            Mode = mode,
            PfxPath = certificate.PfxPath,
            Domain = certificate.Domain,
            LastSuccessAt = previous.LastSuccessAt
        };

        if (mode == CertificateModes.Disabled)
        {
            return baseState;
        }

        if (mode == CertificateModes.ManualPfx || mode == CertificateModes.PanelDistributed)
        {
            return InspectCurrentCertificate(certificate, baseState, preserveSuccess: true, now: DateTimeOffset.UtcNow);
        }

        if (mode != CertificateModes.AcmeExternal && mode != CertificateModes.AcmeManaged)
        {
            return baseState with
            {
                LastError = $"Unsupported certificate mode: {mode}."
            };
        }

        var now = DateTimeOffset.UtcNow;
        var current = InspectCurrentCertificate(certificate, baseState, preserveSuccess: true, now);
        if (current.Available && !forceRenewal && !IsRenewalDue(current.NotAfter, certificate, now))
        {
            return current;
        }

        var attempted = current with
        {
            LastAttemptAt = now
        };

        try
        {
            Directory.CreateDirectory(Path.GetDirectoryName(Path.GetFullPath(certificate.PfxPath)) ?? AppContext.BaseDirectory);
            var result = mode == CertificateModes.AcmeManaged
                ? await RunManagedAcmeAsync(certificate, cancellationToken).ConfigureAwait(false)
                : await RunExternalToolAsync(certificate, cancellationToken).ConfigureAwait(false);
            var refreshed = InspectCurrentCertificate(certificate, attempted, preserveSuccess: false, now: DateTimeOffset.UtcNow);
            if (!refreshed.Available)
            {
                return refreshed with
                {
                    LastError = string.IsNullOrWhiteSpace(refreshed.LastError)
                        ? $"External ACME tool finished but no valid certificate was found. {result}"
                        : $"{refreshed.LastError} {result}".Trim()
                };
            }

            _logger.LogInformation(
                "Certificate refresh succeeded for {Domain}. Force renewal: {ForceRenewal}.",
                certificate.Domain,
                forceRenewal);
            return refreshed with
            {
                LastAttemptAt = now,
                LastSuccessAt = DateTimeOffset.UtcNow,
                LastError = string.Empty
            };
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "Certificate refresh failed for {Domain}. Force renewal: {ForceRenewal}.", certificate.Domain, forceRenewal);
            return attempted with
            {
                LastError = ex.Message
            };
        }
    }

    private static bool ShouldPoll(NodeRuntimeSnapshot runtime)
        => CertificateModes.Normalize(runtime.Config.Certificate.Mode) is CertificateModes.AcmeExternal or CertificateModes.AcmeManaged ||
           runtime.InboundPlans.RequiresCertificate;

    private static bool IsRenewalDue(DateTimeOffset? notAfter, CertificateOptions config, DateTimeOffset now)
    {
        if (notAfter is null)
        {
            return true;
        }

        return now >= notAfter.Value.AddDays(-Math.Max(1, config.RenewBeforeDays));
    }

    private static CertificateRuntimeSnapshot InspectCurrentCertificate(
        CertificateOptions config,
        CertificateRuntimeSnapshot baseState,
        bool preserveSuccess,
        DateTimeOffset now)
    {
        if (string.IsNullOrWhiteSpace(config.PfxPath))
        {
            return baseState with
            {
                LastError = "PFX path is empty."
            };
        }

        if (!File.Exists(config.PfxPath))
        {
            return baseState with
            {
                LastError = $"Certificate file does not exist: {config.PfxPath}."
            };
        }

        try
        {
            using var certificate = CertificateLoader.Load(config);
            return baseState with
            {
                Available = true,
                Thumbprint = certificate.Thumbprint ?? string.Empty,
                NotBefore = certificate.NotBefore == DateTime.MinValue ? null : new DateTimeOffset(certificate.NotBefore),
                NotAfter = certificate.NotAfter == DateTime.MinValue ? null : new DateTimeOffset(certificate.NotAfter),
                LastSuccessAt = preserveSuccess ? baseState.LastSuccessAt ?? now : now,
                LastError = string.Empty
            };
        }
        catch (CryptographicException ex)
        {
            return baseState with
            {
                LastError = ex.Message
            };
        }
        catch (Exception ex)
        {
            return baseState with
            {
                LastError = ex.Message
            };
        }
    }

    private async Task<string> RunExternalToolAsync(CertificateOptions config, CancellationToken cancellationToken)
    {
        if (string.IsNullOrWhiteSpace(config.ExternalToolPath))
        {
            throw new InvalidOperationException("External certificate mode requires ExternalToolPath.");
        }

        var arguments = ReplacePlaceholders(config.ExternalArguments, config);
        var workingDirectory = ResolveWorkingDirectory(config);

        using var process = new Process
        {
            StartInfo = new ProcessStartInfo
            {
                FileName = config.ExternalToolPath,
                Arguments = arguments,
                WorkingDirectory = workingDirectory,
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                UseShellExecute = false,
                CreateNoWindow = true
            }
        };

        foreach (var variable in config.EnvironmentVariables)
        {
            process.StartInfo.Environment[variable.Name] = ReplacePlaceholders(variable.Value, config);
        }

        if (!process.Start())
        {
            throw new InvalidOperationException("Failed to start the external certificate tool.");
        }

        using var timeoutCts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        timeoutCts.CancelAfter(TimeSpan.FromSeconds(Math.Max(1, config.ExternalTimeoutSeconds)));

        var stdoutTask = process.StandardOutput.ReadToEndAsync(timeoutCts.Token);
        var stderrTask = process.StandardError.ReadToEndAsync(timeoutCts.Token);

        try
        {
            await process.WaitForExitAsync(timeoutCts.Token).ConfigureAwait(false);
            var stdout = await stdoutTask.ConfigureAwait(false);
            var stderr = await stderrTask.ConfigureAwait(false);
            if (process.ExitCode != 0)
            {
                throw new InvalidOperationException(
                    $"External certificate tool exited with code {process.ExitCode}. {SummarizeOutput(stdout, stderr)}");
            }

            return SummarizeOutput(stdout, stderr);
        }
        catch (OperationCanceledException) when (!cancellationToken.IsCancellationRequested)
        {
            try
            {
                if (!process.HasExited)
                {
                    process.Kill(entireProcessTree: true);
                }
            }
            catch
            {
            }

            throw new TimeoutException($"External certificate tool timed out after {config.ExternalTimeoutSeconds} seconds.");
        }
    }

    private static string ResolveWorkingDirectory(CertificateOptions config)
    {
        if (!string.IsNullOrWhiteSpace(config.WorkingDirectory))
        {
            return Path.GetFullPath(config.WorkingDirectory);
        }

        var certificateDirectory = Path.GetDirectoryName(Path.GetFullPath(config.PfxPath));
        if (!string.IsNullOrWhiteSpace(certificateDirectory))
        {
            return certificateDirectory;
        }

        return AppContext.BaseDirectory;
    }

    private static string ReplacePlaceholders(string template, CertificateOptions config)
    {
        if (string.IsNullOrWhiteSpace(template))
        {
            return string.Empty;
        }

        var allDomains = config.AltNames.Count == 0
            ? config.Domain
            : string.Join(",", new[] { config.Domain }.Concat(config.AltNames));

        return template
            .Replace("{{domain}}", config.Domain, StringComparison.Ordinal)
            .Replace("{{domains_csv}}", allDomains, StringComparison.Ordinal)
            .Replace("{{alt_names_csv}}", string.Join(",", config.AltNames), StringComparison.Ordinal)
            .Replace("{{email}}", config.Email, StringComparison.Ordinal)
            .Replace("{{pfx_path}}", config.PfxPath, StringComparison.Ordinal)
            .Replace("{{pfx_password}}", config.PfxPassword, StringComparison.Ordinal)
            .Replace("{{challenge_type}}", config.ChallengeType, StringComparison.Ordinal)
            .Replace("{{directory_url}}", ResolveDirectoryUrl(config), StringComparison.Ordinal)
            .Replace("{{working_directory}}", ResolveWorkingDirectory(config), StringComparison.Ordinal)
            .Replace("{{use_staging}}", config.UseStaging ? "true" : "false", StringComparison.Ordinal);
    }

    private static string ResolveDirectoryUrl(CertificateOptions config)
        => AcmeKnownDirectoryUrls.Resolve(config);

    private async Task<string> RunManagedAcmeAsync(CertificateOptions config, CancellationToken cancellationToken)
    {
        await _managedAcmeCertificateService.IssueAsync(config, cancellationToken).ConfigureAwait(false);
        return $"Managed ACME completed against {ResolveDirectoryUrl(config)}.";
    }

    private static string SummarizeOutput(string stdout, string stderr)
    {
        var combined = string.Join(
            Environment.NewLine,
            new[]
            {
                stdout?.Trim(),
                stderr?.Trim()
            }.Where(static value => !string.IsNullOrWhiteSpace(value)));

        if (string.IsNullOrWhiteSpace(combined))
        {
            return string.Empty;
        }

        return combined.Length <= 1024 ? combined : combined[..1024];
    }
}

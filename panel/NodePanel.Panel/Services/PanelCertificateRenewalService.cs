using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;

namespace NodePanel.Panel.Services;

public sealed class PanelCertificateRenewalService : BackgroundService
{
    private readonly ILogger<PanelCertificateRenewalService> _logger;
    private readonly PanelCertificateService _panelCertificateService;
    private readonly PanelQueryService _panelQueryService;

    public PanelCertificateRenewalService(
        PanelQueryService panelQueryService,
        PanelCertificateService panelCertificateService,
        ILogger<PanelCertificateRenewalService> logger)
    {
        _panelQueryService = panelQueryService;
        _panelCertificateService = panelCertificateService;
        _logger = logger;
    }

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        while (!stoppingToken.IsCancellationRequested)
        {
            try
            {
                var now = DateTimeOffset.UtcNow;
                var certificates = await _panelQueryService.GetCertificatesAsync(stoppingToken).ConfigureAwait(false);
                foreach (var certificate in certificates)
                {
                    if (!PanelCertificateService.ShouldProcess(certificate, now))
                    {
                        continue;
                    }

                    try
                    {
                        await _panelCertificateService
                            .RenewAsync(certificate.CertificateId, ignoreSchedule: false, stoppingToken)
                            .ConfigureAwait(false);
                    }
                    catch (Exception ex)
                    {
                        _logger.LogWarning(ex, "Auto renewal failed for panel certificate {CertificateId}.", certificate.CertificateId);
                    }
                }
            }
            catch (Exception ex)
            {
                _logger.LogWarning(ex, "Panel certificate renewal loop failed.");
            }

            await Task.Delay(TimeSpan.FromMinutes(1), stoppingToken).ConfigureAwait(false);
        }
    }
}

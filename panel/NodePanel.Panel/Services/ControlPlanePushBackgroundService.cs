using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;

namespace NodePanel.Panel.Services;

/// <summary>
/// Drains <see cref="ControlPlanePushQueue"/> off the request path so saving users
/// or nodes is not blocked by slow or half-open node connections.
/// </summary>
public sealed class ControlPlanePushBackgroundService : BackgroundService
{
    private const int MaxBatchSize = 64;

    private readonly ControlPlanePushService _pushService;
    private readonly ILogger<ControlPlanePushBackgroundService> _logger;

    public ControlPlanePushBackgroundService(
        ControlPlanePushService pushService,
        ILogger<ControlPlanePushBackgroundService> logger)
    {
        _pushService = pushService;
        _logger = logger;
    }

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        while (!stoppingToken.IsCancellationRequested)
        {
            IReadOnlyList<string> batch;
            try
            {
                batch = await _pushService.Queue.ReadBatchAsync(MaxBatchSize, stoppingToken).ConfigureAwait(false);
            }
            catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested)
            {
                break;
            }

            if (batch.Count == 0)
            {
                break;
            }

            try
            {
                await _pushService.PushSnapshotsAsync(batch, stoppingToken).ConfigureAwait(false);
            }
            catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested)
            {
                break;
            }
            catch (Exception ex)
            {
                _logger.LogWarning(ex, "Background control plane push failed for {NodeCount} node(s).", batch.Count);
            }
        }
    }
}

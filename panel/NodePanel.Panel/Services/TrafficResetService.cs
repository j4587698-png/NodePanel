using NodePanel.Panel.Models;

namespace NodePanel.Panel.Services;

public sealed class TrafficResetService : BackgroundService
{
    private readonly DatabaseService _db;
    private readonly PanelMutationService _panelMutationService;
    private readonly ILogger<TrafficResetService> _logger;

    public TrafficResetService(DatabaseService db, PanelMutationService panelMutationService, ILogger<TrafficResetService> logger)
    {
        _db = db;
        _panelMutationService = panelMutationService;
        _logger = logger;
    }

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        while (!stoppingToken.IsCancellationRequested)
        {
            // Hourly tick
            await Task.Delay(TimeSpan.FromHours(1), stoppingToken);
            
            try
            {
                if (_db.IsConfigured)
                {
                    await ProcessMonthlyResetsAsync(stoppingToken);
                }
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error processing scheduled traffic resets.");
            }
        }
    }

    private async Task ProcessMonthlyResetsAsync(CancellationToken cancellationToken)
    {
        var users = await _db.FSql.Select<UserEntity>().ToListAsync(cancellationToken);
        var tRecords = await _db.FSql.Select<TrafficRecordEntity>().ToListAsync(cancellationToken);
        
        foreach (var user in users)
        {
            // Strict v2board logic: one-time plans (一次性) never reset traffic.
            if (string.Equals(user.Cycle, "one_time", StringComparison.OrdinalIgnoreCase))
            {
                continue;
            }

            var tRecord = tRecords.FirstOrDefault(t => t.UserId == user.UserId);
            bool shouldReset = false;

            if (tRecord != null && tRecord.LastResetAt.HasValue)
            {
                var last = tRecord.LastResetAt.Value;
                var now = DateTimeOffset.UtcNow;
                if (now.Year > last.Year || (now.Year == last.Year && now.Month > last.Month))
                {
                    shouldReset = true;
                }
            }
            
            if (shouldReset)
            {
                _logger.LogInformation("Cron: Resetting traffic for user {UserId} for a new month cycle.", user.UserId);
                await _panelMutationService.ResetUserTrafficAsync(user.UserId, cancellationToken);
            }
        }
    }
}

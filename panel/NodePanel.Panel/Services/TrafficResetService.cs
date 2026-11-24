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

    internal async Task ProcessMonthlyResetsAsync(CancellationToken cancellationToken)
    {
        var users = await _db.FSql.Select<UserEntity>().ToListAsync(user => user.UserId, cancellationToken);
        var now = DateTimeOffset.UtcNow;
        foreach (var userId in users)
        {
            await _panelMutationService.ResetScheduledUserTrafficAsync(userId, now, cancellationToken);
        }
    }
}

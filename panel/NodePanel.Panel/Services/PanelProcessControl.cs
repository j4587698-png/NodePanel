using NodePanel.Panel.Configuration;

namespace NodePanel.Panel.Services;

public sealed class PanelProcessControl
{
    private const int RestartExitCode = 86;
    private static readonly TimeSpan RestartDelay = TimeSpan.FromSeconds(2);

    private readonly PanelOptions _options;
    private readonly ILogger<PanelProcessControl> _logger;
    private int _restartScheduled;

    public PanelProcessControl(PanelOptions options, ILogger<PanelProcessControl> logger)
    {
        ArgumentNullException.ThrowIfNull(options);
        ArgumentNullException.ThrowIfNull(logger);

        _options = options;
        _logger = logger;
    }

    public bool AutoRestartOnHttpsChange => _options.AutoRestartOnHttpsChange;

    public bool TryScheduleRestart(string reason)
    {
        if (!AutoRestartOnHttpsChange)
        {
            return false;
        }

        if (Interlocked.Exchange(ref _restartScheduled, 1) != 0)
        {
            return true;
        }

        _logger.LogWarning("Panel 进程即将重启以应用 HTTPS 监听配置变更: {Reason}", reason);
        _ = Task.Run(
            async () =>
            {
                try
                {
                    await Task.Delay(RestartDelay).ConfigureAwait(false);
                }
                catch
                {
                    // Ignore cancellation/errors during shutdown scheduling.
                }

                Environment.Exit(RestartExitCode);
            });

        return true;
    }
}

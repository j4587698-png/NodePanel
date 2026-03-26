using NodePanel.Panel.Models;

namespace NodePanel.Panel.Services;

public sealed class PanelAuthSettingsService
{
    private readonly DatabaseService _db;

    public PanelAuthSettingsService(DatabaseService db)
    {
        _db = db;
    }

    public async Task<PanelAuthSettings> GetAsync(CancellationToken cancellationToken = default)
    {
        if (!_db.IsConfigured)
        {
            return new PanelAuthSettings();
        }

        var settings = await _db.FSql.Select<SettingEntity>().ToListAsync(cancellationToken).ConfigureAwait(false);
        return PanelAuthSettings.FromSettings(
            settings.ToDictionary(static item => item.Key, static item => item.Value, StringComparer.Ordinal));
    }
}

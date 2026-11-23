using NodePanel.Panel.Models;

namespace NodePanel.Panel.Services;

public sealed class PanelAuthSettingsService
{
    private readonly PanelQueryService _panelQueryService;

    public PanelAuthSettingsService(PanelQueryService panelQueryService)
    {
        _panelQueryService = panelQueryService;
    }

    public async Task<PanelAuthSettings> GetAsync(CancellationToken cancellationToken = default)
    {
        var settings = await _panelQueryService.GetSettingsAsync(cancellationToken).ConfigureAwait(false);
        return PanelAuthSettings.FromSettings(settings);
    }
}

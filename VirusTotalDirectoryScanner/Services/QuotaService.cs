using System;
using System.Threading;
using System.Threading.Tasks;
using VirusTotalDirectoryScanner.Settings;

namespace VirusTotalDirectoryScanner.Services;

public class QuotaService : IQuotaService
{
    private readonly ISettingsService _settingsService;

    public QuotaService(ISettingsService settingsService)
    {
        _settingsService = settingsService;
    }

    public void CheckQuota()
    {
        DateTime today = DateTime.Today;
        DateTime now = DateTime.Now;
        var settings = _settingsService.CurrentSettings;

        // Reset counters if needed
        if (settings.Quota.LastUsedDate.Date != today)
        {
            settings.Quota.UsedToday = 0;
            settings.Quota.LastUsedDate = now;
            
            if (settings.Quota.LastUsedDate.Month != today.Month)
            {
                settings.Quota.UsedThisMonth = 0;
            }
            
            // We don't await save here to avoid async void/task complexity in sync check, 
            // but we will save on increment.
        }

        if (settings.Quota.PerDay > 0 && settings.Quota.UsedToday >= settings.Quota.PerDay)
        {
            throw new Exception($"Daily quota exceeded ({settings.Quota.UsedToday}/{settings.Quota.PerDay})");
        }

        if (settings.Quota.PerMonth > 0 && settings.Quota.UsedThisMonth >= settings.Quota.PerMonth)
        {
            throw new Exception($"Monthly quota exceeded ({settings.Quota.UsedThisMonth}/{settings.Quota.PerMonth})");
        }
    }

    public async Task IncrementQuotaAsync(CancellationToken ct = default)
    {
        // Re-check quota before incrementing to be safe
        CheckQuota();

        var settings = _settingsService.CurrentSettings;
        settings.Quota.UsedToday++;
        settings.Quota.UsedThisMonth++;
        settings.Quota.LastUsedDate = DateTime.Now;

        await UserSettingsStore.SaveAsync(_settingsService.UserSettingsFilePath, settings, ct);
    }
}

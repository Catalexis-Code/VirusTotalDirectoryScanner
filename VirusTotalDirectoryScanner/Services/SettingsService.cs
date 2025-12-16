using Microsoft.Extensions.Configuration;
using VirusTotalDirectoryScanner.Settings;

namespace VirusTotalDirectoryScanner.Services;

public class SettingsService
{
    public Settings.Settings CurrentSettings { get; private set; } = new();
    public string? ApiKey { get; private set; }
    public string UserSettingsFilePath => AppConfiguration.UserSettingsFilePath;

    public SettingsService()
    {
        Load();
    }

    public void Load()
    {
        var config = AppConfiguration.BuildConfiguration();
        CurrentSettings = AppConfiguration.GetAppSettings(config);
        ApiKey = AppConfiguration.GetVirusTotalApiKey(config);
    }
}

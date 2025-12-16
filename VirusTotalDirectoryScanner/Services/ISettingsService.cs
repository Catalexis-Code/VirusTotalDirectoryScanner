using VirusTotalDirectoryScanner.Settings;

namespace VirusTotalDirectoryScanner.Services;

public interface ISettingsService
{
    Settings.Settings CurrentSettings { get; }
    string? ApiKey { get; }
    string UserSettingsFilePath { get; }
    void Load();
    Task SaveAsync(Settings.Settings settings);
}

using Microsoft.Extensions.Configuration;
using VirusTotalDirectoryScanner.Settings;

namespace VirusTotalDirectoryScanner.Services;

public class SettingsService : ISettingsService
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

    public async Task SaveAsync(Settings.Settings settings)
    {
        ValidateSettings(settings);
        await UserSettingsStore.SaveAsync(UserSettingsFilePath, settings);
        CurrentSettings = settings;
    }

    private static void ValidateSettings(Settings.Settings settings)
    {
        // Validate quota settings
        if (settings.Quota.PerMinute < 0)
            throw new ArgumentException("PerMinute quota cannot be negative.", nameof(settings));
        if (settings.Quota.PerDay < 0)
            throw new ArgumentException("PerDay quota cannot be negative.", nameof(settings));
        if (settings.Quota.PerMonth < 0)
            throw new ArgumentException("PerMonth quota cannot be negative.", nameof(settings));

        // Validate general settings
        if (settings.General.MaxFileSizeBytes < 0)
            throw new ArgumentException("MaxFileSizeBytes cannot be negative.", nameof(settings));
        if (settings.General.PollingTimeoutMinutes < 0)
            throw new ArgumentException("PollingTimeoutMinutes cannot be negative.", nameof(settings));

        // Validate paths for invalid characters (if specified)
        char[] invalidPathChars = Path.GetInvalidPathChars();
        ValidatePath(settings.Paths.ScanDirectory, "ScanDirectory", invalidPathChars);
        ValidatePath(settings.Paths.CleanDirectory, "CleanDirectory", invalidPathChars);
        ValidatePath(settings.Paths.CompromisedDirectory, "CompromisedDirectory", invalidPathChars);
        ValidatePath(settings.Paths.LogFilePath, "LogFilePath", invalidPathChars);
    }

    private static void ValidatePath(string? path, string paramName, char[] invalidChars)
    {
        if (!string.IsNullOrWhiteSpace(path))
        {
            if (path.IndexOfAny(invalidChars) >= 0)
            {
                throw new ArgumentException($"{paramName} contains invalid path characters.", "settings");
            }
        }
    }
}

using Microsoft.Toolkit.Uwp.Notifications;

namespace VirusTotalDirectoryScanner.Services;

/// <summary>
/// Provides Windows Toast notifications for threat detection alerts.
/// </summary>
public class NotificationService : INotificationService
{
    /// <inheritdoc />
    public void ShowThreatDetectedNotification(string fileName, int detectionCount)
    {
        var logoPath = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "Assets", "logo.png");

        var builder = new ToastContentBuilder()
            .AddText("⚠️ Threat Detected!")
            .AddText($"File: {fileName}")
            .AddText($"Detected by {detectionCount} security vendor{(detectionCount != 1 ? "s" : "")}");

        if (File.Exists(logoPath))
        {
            builder.AddAppLogoOverride(new Uri(logoPath));
        }

        builder.Show();
    }
}

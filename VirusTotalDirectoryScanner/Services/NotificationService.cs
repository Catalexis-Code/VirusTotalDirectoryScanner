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
        new ToastContentBuilder()
            .AddText("⚠️ Threat Detected!")
            .AddText($"File: {fileName}")
            .AddText($"Detected by {detectionCount} security vendor{(detectionCount != 1 ? "s" : "")}")
            .Show();
    }
}

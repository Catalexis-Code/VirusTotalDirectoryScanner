namespace VirusTotalDirectoryScanner.Services;

/// <summary>
/// Service for sending system notifications.
/// </summary>
public interface INotificationService
{
    /// <summary>
    /// Shows a notification when a threat is detected.
    /// </summary>
    /// <param name="fileName">The name of the compromised file.</param>
    /// <param name="detectionCount">The number of engines that detected the threat.</param>
    void ShowThreatDetectedNotification(string fileName, int detectionCount);
}

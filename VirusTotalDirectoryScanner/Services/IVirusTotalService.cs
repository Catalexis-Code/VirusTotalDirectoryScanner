using System.Threading;
using System.Threading.Tasks;
using VirusTotalDirectoryScanner.Models;

namespace VirusTotalDirectoryScanner.Services;

public enum ScanPhase
{
    CalculatingChecksum,
    CheckingCache,
    Uploading,
    WaitingForAnalysis
}

public interface IVirusTotalService
{
    Task<(ScanResultStatus Status, int DetectionCount, string Hash, string? Message)> ScanFileAsync(
        string filePath, 
        Action<ScanPhase>? onPhaseChanged = null,
        CancellationToken ct = default);
}

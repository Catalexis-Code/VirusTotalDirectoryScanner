using System.Threading;
using System.Threading.Tasks;
using VirusTotalDirectoryScanner.Models;

namespace VirusTotalDirectoryScanner.Services;

public interface IVirusTotalService
{
    Task<(ScanResultStatus Status, int DetectionCount, string Hash, string? Message)> ScanFileAsync(string filePath, CancellationToken ct = default);
}

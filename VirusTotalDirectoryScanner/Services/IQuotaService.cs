using System.Threading;
using System.Threading.Tasks;

namespace VirusTotalDirectoryScanner.Services;

public interface IQuotaService
{
    void CheckQuota();
    Task IncrementQuotaAsync(CancellationToken ct = default);
}

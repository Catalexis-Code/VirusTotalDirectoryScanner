using System.Security.Cryptography;
using System.Threading.RateLimiting;
using Refit;
using VirusTotalDirectoryScanner.Models;
using VirusTotalDirectoryScanner.Settings;

namespace VirusTotalDirectoryScanner.Services;

public class VirusTotalService
{
    private readonly IVirusTotalApi _api;
    private readonly Settings.Settings _settings;
    private readonly string _userSettingsPath;
    private readonly RateLimiter _limiter;

    public VirusTotalService(string apiKey, Settings.Settings settings, string userSettingsPath)
    {
        _settings = settings;
        _userSettingsPath = userSettingsPath;

        // Initialize Rate Limiter based on settings
        int permitLimit = settings.Quota.PerMinute > 0 ? settings.Quota.PerMinute : 4;
        
        _limiter = new FixedWindowRateLimiter(new FixedWindowRateLimiterOptions
        {
            PermitLimit = permitLimit,
            Window = TimeSpan.FromMinutes(1),
            QueueProcessingOrder = QueueProcessingOrder.OldestFirst,
            QueueLimit = 100,
            AutoReplenishment = true
        });

        var httpClient = new HttpClient(new ThrottlingHandler(_limiter))
        {
            BaseAddress = new Uri("https://www.virustotal.com/api/v3")
        };
        httpClient.DefaultRequestHeaders.Add("x-apikey", apiKey);

        _api = RestService.For<IVirusTotalApi>(httpClient);
    }

    public async Task<ScanResultStatus> ScanFileAsync(string filePath, CancellationToken ct = default)
    {
        // 1. Check Quota
        CheckQuota();

        // 2. Calculate Hash
        string hash = await CalculateSha256Async(filePath, ct);

        // 3. Check if file exists (GetFileReport)
        try 
        {
            await IncrementQuotaAsync(ct);
            var report = await _api.GetFileReport(hash);
            if (report.Data != null)
            {
                return DetermineStatus(report.Data.Attributes?.LastAnalysisStats);
            }
        }
        catch (ApiException ex) when (ex.StatusCode == System.Net.HttpStatusCode.NotFound)
        {
            // File not found, proceed to upload
        }

        // 4. Upload File
        await IncrementQuotaAsync(ct);
        
        // We need to open the file stream. 
        // Since we already checked for locks in the caller, we hope it's still free.
        // But we should wrap in try-catch just in case.
        VirusTotalResponse<AnalysisDescriptor> uploadResult;
        await using (var stream = File.OpenRead(filePath))
        {
            var streamPart = new StreamPart(stream, Path.GetFileName(filePath));
            uploadResult = await _api.UploadFile(streamPart);
        }

        if (uploadResult.Data?.Id == null)
        {
            throw new Exception("Upload failed, no analysis ID returned.");
        }

        string analysisId = uploadResult.Data.Id;

        // 5. Poll for results
        while (true)
        {
            await Task.Delay(10000, ct); // Wait 10s before polling
            
            // Polling doesn't usually count towards quota in some APIs, but for VT it likely does as a request.
            // The user prompt says "Use the public API within its quota... 4 per minute".
            // So polling calls count.
            await IncrementQuotaAsync(ct);

            var analysis = await _api.GetAnalysis(analysisId);
            string? status = analysis.Data?.Attributes?.Status;

            if (status == "completed")
            {
                return DetermineStatus(analysis.Data?.Attributes?.Stats);
            }
        }
    }

    private ScanResultStatus DetermineStatus(AnalysisStats? stats)
    {
        if (stats == null) return ScanResultStatus.Unknown;
        if (stats.Malicious > 0) return ScanResultStatus.Compromised;
        return ScanResultStatus.Clean;
    }

    private async Task<string> CalculateSha256Async(string filePath, CancellationToken ct)
    {
        using var sha256 = SHA256.Create();
        await using var stream = File.OpenRead(filePath);
        byte[] hashBytes = await sha256.ComputeHashAsync(stream, ct);
        return BitConverter.ToString(hashBytes).Replace("-", "").ToLowerInvariant();
    }

    private void CheckQuota()
    {
        DateTime today = DateTime.Today;
        DateTime now = DateTime.Now;

        // Reset counters if needed
        if (_settings.Quota.LastUsedDate.Date != today)
        {
            _settings.Quota.UsedToday = 0;
            _settings.Quota.LastUsedDate = now;
            
            if (_settings.Quota.LastUsedDate.Month != today.Month)
            {
                _settings.Quota.UsedThisMonth = 0;
            }
            
            // We don't await save here to avoid async void/task complexity in sync check, 
            // but we will save on increment.
        }

        if (_settings.Quota.PerDay > 0 && _settings.Quota.UsedToday >= _settings.Quota.PerDay)
        {
            throw new Exception($"Daily quota exceeded ({_settings.Quota.UsedToday}/{_settings.Quota.PerDay})");
        }

        if (_settings.Quota.PerMonth > 0 && _settings.Quota.UsedThisMonth >= _settings.Quota.PerMonth)
        {
            throw new Exception($"Monthly quota exceeded ({_settings.Quota.UsedThisMonth}/{_settings.Quota.PerMonth})");
        }
    }

    private async Task IncrementQuotaAsync(CancellationToken ct)
    {
        // Re-check quota before incrementing to be safe
        CheckQuota();

        _settings.Quota.UsedToday++;
        _settings.Quota.UsedThisMonth++;
        _settings.Quota.LastUsedDate = DateTime.Now;

        await UserSettingsStore.SaveAsync(_userSettingsPath, _settings, ct);
    }
}

public enum ScanResultStatus
{
    Clean,
    Compromised,
    Unknown
}

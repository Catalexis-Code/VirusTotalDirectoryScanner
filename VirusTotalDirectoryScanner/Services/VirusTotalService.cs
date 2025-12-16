using System.Security.Cryptography;
using System.Threading.RateLimiting;
using Refit;
using VirusTotalDirectoryScanner.Models;
using VirusTotalDirectoryScanner.Settings;

namespace VirusTotalDirectoryScanner.Services;

public class VirusTotalService
{
    private readonly IVirusTotalApi _api;
    private readonly SettingsService _settingsService;
    private readonly RateLimiter _limiter;

    public VirusTotalService(SettingsService settingsService)
    {
        _settingsService = settingsService;
        var settings = _settingsService.CurrentSettings;
        var apiKey = _settingsService.ApiKey;

        if (string.IsNullOrWhiteSpace(apiKey))
        {
            throw new InvalidOperationException("VirusTotal API Key is missing.");
        }

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

    public async Task<(ScanResultStatus Status, int DetectionCount, string Hash, string? Message)> ScanFileAsync(string filePath, CancellationToken ct = default)
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
                var status = DetermineStatus(report.Data.Attributes?.LastAnalysisStats);
                return (status.Status, status.DetectionCount, hash, null);
            }
        }
        catch (ApiException ex) when (ex.StatusCode == System.Net.HttpStatusCode.NotFound)
        {
            // File not found, proceed to upload
        }

        // 4. Upload File
        await IncrementQuotaAsync(ct);
        
        long fileSize = new FileInfo(filePath).Length;
        
        // Hard limit check (650MB)
        if (fileSize > 681574400) 
        {
            return (ScanResultStatus.Failed, 0, hash, "File exceeds 650MB limit.");
        }

        VirusTotalResponse<AnalysisDescriptor> uploadResult;

        if (fileSize > 33554432) // 32MB
        {
            // Large file flow
            var urlResponse = await _api.GetLargeFileUploadUrl();
            if (urlResponse.Data == null) 
                return (ScanResultStatus.Failed, 0, hash, "Could not get upload URL.");

            // Use a temporary HttpClient to upload to the dynamic URL
            using var uploadClient = new HttpClient();
            uploadClient.DefaultRequestHeaders.Add("x-apikey", _settingsService.ApiKey);
            
            using var content = new MultipartFormDataContent();
            await using var fileStream = File.OpenRead(filePath);
            content.Add(new StreamContent(fileStream), "file", Path.GetFileName(filePath));
            
            var response = await uploadClient.PostAsync(urlResponse.Data, content, ct);
            if (!response.IsSuccessStatusCode)
                return (ScanResultStatus.Failed, 0, hash, $"Upload failed: {response.StatusCode}");

            var json = await response.Content.ReadAsStringAsync(ct);
            uploadResult = System.Text.Json.JsonSerializer.Deserialize<VirusTotalResponse<AnalysisDescriptor>>(json)!;
        }
        else
        {
            // Standard flow
            await using var stream = File.OpenRead(filePath);
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
            string? statusStr = analysis.Data?.Attributes?.Status;

            if (statusStr == "completed")
            {
                var status = DetermineStatus(analysis.Data?.Attributes?.Stats);
                return (status.Status, status.DetectionCount, hash, null);
            }
        }
    }

    private (ScanResultStatus Status, int DetectionCount) DetermineStatus(AnalysisStats? stats)
    {
        if (stats == null) return (ScanResultStatus.Unknown, 0);
        if (stats.Malicious > 0) return (ScanResultStatus.Compromised, stats.Malicious);
        return (ScanResultStatus.Clean, 0);
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
        var settings = _settingsService.CurrentSettings;

        // Reset counters if needed
        if (settings.Quota.LastUsedDate.Date != today)
        {
            settings.Quota.UsedToday = 0;
            settings.Quota.LastUsedDate = now;
            
            if (settings.Quota.LastUsedDate.Month != today.Month)
            {
                settings.Quota.UsedThisMonth = 0;
            }
            
            // We don't await save here to avoid async void/task complexity in sync check, 
            // but we will save on increment.
        }

        if (settings.Quota.PerDay > 0 && settings.Quota.UsedToday >= settings.Quota.PerDay)
        {
            throw new Exception($"Daily quota exceeded ({settings.Quota.UsedToday}/{settings.Quota.PerDay})");
        }

        if (settings.Quota.PerMonth > 0 && settings.Quota.UsedThisMonth >= settings.Quota.PerMonth)
        {
            throw new Exception($"Monthly quota exceeded ({settings.Quota.UsedThisMonth}/{settings.Quota.PerMonth})");
        }
    }

    private async Task IncrementQuotaAsync(CancellationToken ct)
    {
        // Re-check quota before incrementing to be safe
        CheckQuota();

        var settings = _settingsService.CurrentSettings;
        settings.Quota.UsedToday++;
        settings.Quota.UsedThisMonth++;
        settings.Quota.LastUsedDate = DateTime.Now;

        await UserSettingsStore.SaveAsync(_settingsService.UserSettingsFilePath, settings, ct);
    }
}

public enum ScanResultStatus
{
    Clean,
    Compromised,
    Unknown,
    Failed
}

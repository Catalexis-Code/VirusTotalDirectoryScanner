using System.Threading.RateLimiting;
using System.Net.Http;
using System.Text.Json;
using Refit;
using VirusTotalDirectoryScanner.Models;
using VirusTotalDirectoryScanner.Settings;

namespace VirusTotalDirectoryScanner.Services;

public class VirusTotalService : IVirusTotalService
{
    private readonly IVirusTotalApi _api;
    private readonly ISettingsService _settingsService;
    private readonly IQuotaService _quotaService;
    private readonly IHttpClientFactory _httpClientFactory;
    private readonly IFileOperationsService _fileOperationsService;

    public VirusTotalService(
        ISettingsService settingsService, 
        IQuotaService quotaService, 
        IVirusTotalApi api,
        IHttpClientFactory httpClientFactory,
        IFileOperationsService fileOperationsService)
    {
        _settingsService = settingsService;
        _quotaService = quotaService;
        _api = api;
        _httpClientFactory = httpClientFactory;
        _fileOperationsService = fileOperationsService;
    }

    public async Task<(ScanResultStatus Status, int DetectionCount, string Hash, string? Message)> ScanFileAsync(string filePath, CancellationToken ct = default)
    {
        var settings = _settingsService.CurrentSettings;

        // 1. Check Quota
        _quotaService.CheckQuota();

        // 2. Calculate Hash
        string hash = await _fileOperationsService.CalculateSha256Async(filePath, ct);

        // 3. Check if file exists (GetFileReport)
        try 
        {
            await _quotaService.IncrementQuotaAsync(ct);
            var report = await ExecuteWithRetryAsync(() => _api.GetFileReport(hash), ct);
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
        await _quotaService.IncrementQuotaAsync(ct);
        
        long fileSize = _fileOperationsService.GetFileLength(filePath);
        long maxSize = settings.General.MaxFileSizeBytes > 0 ? settings.General.MaxFileSizeBytes : 681574400;

        // Hard limit check
        if (fileSize > maxSize) 
        {
            return (ScanResultStatus.Failed, 0, hash, $"File exceeds {maxSize/1024/1024}MB limit.");
        }

        VirusTotalResponse<AnalysisDescriptor> uploadResult;

        if (fileSize > 33554432) // 32MB
        {
            // Large file flow
            var urlResponse = await ExecuteWithRetryAsync(() => _api.GetLargeFileUploadUrl(), ct);
            if (urlResponse.Data == null) 
                return (ScanResultStatus.Failed, 0, hash, "Could not get upload URL.");

            // Use a temporary HttpClient to upload to the dynamic URL
            using var uploadClient = _httpClientFactory.CreateClient("VirusTotalUpload");
            
            using var content = new MultipartFormDataContent();
            await using var fileStream = _fileOperationsService.OpenRead(filePath);
            content.Add(new StreamContent(fileStream), "file", Path.GetFileName(filePath));
            
            // Upload itself typically doesn't need 429 retry in the same way, but could benefit from robust transient error handling
            // For simplicity, we keep standard retries if implementing a policy, but here we just do basic call.
            var response = await uploadClient.PostAsync(urlResponse.Data, content, ct);
            if (!response.IsSuccessStatusCode)
                return (ScanResultStatus.Failed, 0, hash, $"Upload failed: {response.StatusCode}");

            var json = await response.Content.ReadAsStringAsync(ct);
            try 
            {
                uploadResult = JsonSerializer.Deserialize<VirusTotalResponse<AnalysisDescriptor>>(json)!;
            }
            catch (JsonException)
            {
                return (ScanResultStatus.Failed, 0, hash, "Failed to deserialize upload response.");
            }
        }
        else
        {
            // Standard flow
            await using var stream = _fileOperationsService.OpenRead(filePath);
            var streamPart = new StreamPart(stream, Path.GetFileName(filePath));
            uploadResult = await ExecuteWithRetryAsync(() => _api.UploadFile(streamPart), ct);
        }

        if (uploadResult.Data?.Id == null)
        {
            return (ScanResultStatus.Failed, 0, hash, "Upload failed, no analysis ID returned.");
        }

        string analysisId = uploadResult.Data.Id;
        DateTime startTime = DateTime.Now;
        int timeoutMinutes = settings.General.PollingTimeoutMinutes > 0 ? settings.General.PollingTimeoutMinutes : 15;

        // 5. Poll for results
        while (true)
        {
            if (DateTime.Now - startTime > TimeSpan.FromMinutes(timeoutMinutes))
            {
                return (ScanResultStatus.Failed, 0, hash, "Scan timed out pending analysis.");
            }

            await Task.Delay(10000, ct); // Wait 10s before polling
            
            await _quotaService.IncrementQuotaAsync(ct);

            VirusTotalResponse<AnalysisObject> analysis;
            try 
            {
                analysis = await ExecuteWithRetryAsync(() => _api.GetAnalysis(analysisId), ct);
            }
            catch (ApiException ex) when (ex.StatusCode == System.Net.HttpStatusCode.NotFound)
            {
                // Analysis ID not found? unexpected.
                return (ScanResultStatus.Failed, 0, hash, "Analysis ID not found during polling.");
            }

            string? statusStr = analysis.Data?.Attributes?.Status;

            if (statusStr == "completed")
            {
                var status = DetermineStatus(analysis.Data?.Attributes?.Stats);
                return (status.Status, status.DetectionCount, hash, null);
            }
            // other statuses: queued, in-progress. loop again.
        }
    }

    private async Task<T> ExecuteWithRetryAsync<T>(Func<Task<T>> action, CancellationToken ct)
    {
        int maxRetries = 3;
        int delay = 2000;

        for (int i = 0; i <= maxRetries; i++)
        {
            try
            {
                return await action();
            }
            catch (ApiException ex) when ((int)ex.StatusCode == 429 || (int)ex.StatusCode >= 500)
            {
                if (i == maxRetries) throw; // Rethrow if last attempt

                // If 429, ideally respect Retry-After header. 
                // Since this simple implementation doesn't parse headers deeply here, uses exponential backoff.
                await Task.Delay(delay, ct);
                delay *= 2;
            }
        }
        throw new InvalidOperationException("Unreachable code");
    }

    private (ScanResultStatus Status, int DetectionCount) DetermineStatus(AnalysisStats? stats)
    {
        if (stats == null) return (ScanResultStatus.Unknown, 0);
        if (stats.Malicious > 0) return (ScanResultStatus.Compromised, stats.Malicious);
        return (ScanResultStatus.Clean, 0);
    }
}

public enum ScanResultStatus
{
    Clean,
    Compromised,
    Unknown,
    Failed
}

using System.Net.Http.Headers;
using System.Text;
using System.Text.Json;
using System.Threading.RateLimiting;
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

    public async Task<(ScanResultStatus Status, int DetectionCount, string Hash, string? Message)> ScanFileAsync(
        string filePath, 
        Action<ScanPhase>? onPhaseChanged = null,
        CancellationToken ct = default)
    {
        var settings = _settingsService.CurrentSettings;

        // 1. Check Quota
        _quotaService.CheckQuota();

        // 2. Calculate Hash
        onPhaseChanged?.Invoke(ScanPhase.CalculatingChecksum);
        string hash = await _fileOperationsService.CalculateSha256Async(filePath, ct);

        // 3. Check if file exists (GetFileReport)
        onPhaseChanged?.Invoke(ScanPhase.CheckingCache);
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
        onPhaseChanged?.Invoke(ScanPhase.Uploading);
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
            var streamContent = new StreamContent(fileStream);
            
            // Manually set Content-Disposition to avoid .NET adding filename* encoding (RFC 5987)
            // which VirusTotal does not support and causes "Malformed multipart body" errors
            var fileName = Path.GetFileName(filePath);
            var safeFileName = SanitizeFileName(fileName);
            streamContent.Headers.ContentDisposition = new ContentDispositionHeaderValue("form-data")
            {
                Name = "\"file\"",
                FileName = $"\"{safeFileName}\""
            };
            streamContent.Headers.ContentType = new MediaTypeHeaderValue("application/octet-stream");
            content.Add(streamContent);
            
            // Wrap upload in retry logic for transient failures
            var response = await ExecuteUploadWithRetryAsync(
                () => uploadClient.PostAsync(urlResponse.Data, content, ct), ct);
            if (!response.IsSuccessStatusCode)
            {
                var errorBody = await response.Content.ReadAsStringAsync(ct);
                var errorMessage = ExtractApiError(errorBody);
                return (ScanResultStatus.Failed, 0, hash, $"Upload failed: {response.StatusCode}{(string.IsNullOrEmpty(errorMessage) ? "" : $" - {errorMessage}")}");
            }

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
            try
            {
                await using var stream = _fileOperationsService.OpenRead(filePath);
                var streamPart = new StreamPart(stream, Path.GetFileName(filePath));
                uploadResult = await ExecuteWithRetryAsync(() => _api.UploadFile(streamPart), ct);
            }
            catch (ApiException ex)
            {
                var errorMessage = ExtractApiError(ex.Content);
                return (ScanResultStatus.Failed, 0, hash, $"Upload failed: {ex.StatusCode}{(string.IsNullOrEmpty(errorMessage) ? "" : $" - {errorMessage}")}");
            }
        }

        if (uploadResult.Data?.Id == null)
        {
            return (ScanResultStatus.Failed, 0, hash, "Upload failed, no analysis ID returned.");
        }

        string analysisId = uploadResult.Data.Id;
        DateTime startTime = DateTime.Now;
        int timeoutMinutes = settings.General.PollingTimeoutMinutes > 0 ? settings.General.PollingTimeoutMinutes : 15;

        // 5. Poll for results
        onPhaseChanged?.Invoke(ScanPhase.WaitingForAnalysis);
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

    private async Task<HttpResponseMessage> ExecuteUploadWithRetryAsync(Func<Task<HttpResponseMessage>> action, CancellationToken ct)
    {
        int maxRetries = 3;
        int delay = 2000;

        for (int i = 0; i <= maxRetries; i++)
        {
            var response = await action();
            
            // Retry on server errors or rate limiting
            if (((int)response.StatusCode >= 500 || (int)response.StatusCode == 429) && i < maxRetries)
            {
                await Task.Delay(delay, ct);
                delay *= 2;
                continue;
            }
            
            return response;
        }
        throw new InvalidOperationException("Unreachable code");
    }

    private (ScanResultStatus Status, int DetectionCount) DetermineStatus(AnalysisStats? stats)
    {
        if (stats == null) return (ScanResultStatus.Unknown, 0);
        if (stats.Malicious > 0) return (ScanResultStatus.Compromised, stats.Malicious);
        return (ScanResultStatus.Clean, 0);
    }

    private static string? ExtractApiError(string? responseBody)
    {
        if (string.IsNullOrWhiteSpace(responseBody))
            return null;

        try
        {
            using var doc = JsonDocument.Parse(responseBody);
            var root = doc.RootElement;
            
            // VirusTotal API error format: { "error": { "message": "...", "code": "..." } }
            if (root.TryGetProperty("error", out var errorElement))
            {
                if (errorElement.TryGetProperty("message", out var messageElement))
                {
                    return messageElement.GetString();
                }
                // Fallback to code if message not available
                if (errorElement.TryGetProperty("code", out var codeElement))
                {
                    return codeElement.GetString();
                }
            }
        }
        catch (JsonException)
        {
            // If not JSON, return the raw body (truncated if too long)
            if (responseBody.Length > 150)
                return responseBody[..150] + "...";
            return responseBody;
        }

        return null;
    }

    private static string SanitizeFileName(string fileName)
    {
        // Replace characters that may cause issues in Content-Disposition header
        // Keep only printable ASCII characters, replace others with underscores
        var sb = new StringBuilder();
        foreach (char c in fileName)
        {
            if (c >= 32 && c <= 126 && c != '"' && c != '\\')
                sb.Append(c);
            else
                sb.Append('_');
        }
        return sb.ToString();
    }
}

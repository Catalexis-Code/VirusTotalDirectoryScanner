using Refit;
using VirusTotalDirectoryScanner.Models;

namespace VirusTotalDirectoryScanner.Services;

public interface IVirusTotalApi
{
    [Get("/files/{id}")]
    Task<VirusTotalResponse<FileObject>> GetFileReport(string id);

    [Multipart]
    [Post("/files")]
    Task<VirusTotalResponse<AnalysisDescriptor>> UploadFile([AliasAs("file")] StreamPart file);

    [Get("/files/upload_url")]
    Task<VirusTotalResponse<string>> GetLargeFileUploadUrl();

    [Get("/analyses/{id}")]
    Task<VirusTotalResponse<AnalysisObject>> GetAnalysis(string id);
}

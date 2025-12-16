namespace VirusTotalDirectoryScanner.Services;

public interface IFileOperationsService
{
    bool DirectoryExists(string path);
    void CreateDirectory(string path);
    string[] GetFiles(string path);
    bool FileExists(string path);
    bool IsFileLocked(string path);
    void MoveFile(string sourceFileName, string destFileName);
    void DeleteFile(string path);
    void AppendAllText(string path, string contents);
    Stream OpenRead(string path);
    long GetFileLength(string path);
    Task<string> CalculateSha256Async(string filePath, CancellationToken ct = default);
    void OpenDirectoryInExplorer(string path);
}

using System.Collections.Concurrent;
using VirusTotalDirectoryScanner.Models;
using VirusTotalDirectoryScanner.Settings;

namespace VirusTotalDirectoryScanner.Services;

public class DirectoryScannerService : IDisposable
{
    private readonly VirusTotalService _vtService;
    private readonly Settings.Settings _settings;
    private readonly Action<ScanResult> _onResultUpdated;
    private readonly Action<string> _onLog;
    private FileSystemWatcher? _watcher;
    private readonly ConcurrentQueue<string> _fileQueue = new();
    private readonly CancellationTokenSource _cts = new();
    private Task? _processingTask;

    public DirectoryScannerService(
        VirusTotalService vtService, 
        Settings.Settings settings, 
        Action<ScanResult> onResultUpdated,
        Action<string> onLog)
    {
        _vtService = vtService;
        _settings = settings;
        _onResultUpdated = onResultUpdated;
        _onLog = onLog;
    }

    public void Start()
    {
        if (string.IsNullOrWhiteSpace(_settings.Paths.ScanDirectory))
        {
            _onLog("Scan directory is not configured.");
            return;
        }

        if (!Directory.Exists(_settings.Paths.ScanDirectory))
        {
            try
            {
                Directory.CreateDirectory(_settings.Paths.ScanDirectory);
                _onLog($"Created scan directory: {_settings.Paths.ScanDirectory}");
            }
            catch (Exception ex)
            {
                _onLog($"Failed to create scan directory: {ex.Message}");
                return;
            }
        }

        _watcher = new FileSystemWatcher(_settings.Paths.ScanDirectory);
        _watcher.Created += OnFileCreated;
        _watcher.EnableRaisingEvents = true;

        _processingTask = Task.Run(ProcessQueueAsync);
        _onLog($"Started monitoring {_settings.Paths.ScanDirectory}");
        
        // Process existing files
        foreach (var file in Directory.GetFiles(_settings.Paths.ScanDirectory))
        {
            EnqueueFile(file);
        }
    }

    private void OnFileCreated(object sender, FileSystemEventArgs e)
    {
        EnqueueFile(e.FullPath);
    }

    private void EnqueueFile(string fullPath)
    {
        _fileQueue.Enqueue(fullPath);
        
        // Notify UI of pending file
        _onResultUpdated(new ScanResult 
        { 
            FileName = Path.GetFileName(fullPath), 
            FullPath = fullPath, 
            Status = ScanStatus.Pending 
        });
    }

    private async Task ProcessQueueAsync()
    {
        while (!_cts.Token.IsCancellationRequested)
        {
            if (_fileQueue.TryDequeue(out string? filePath))
            {
                await ProcessFileAsync(filePath);
            }
            else
            {
                await Task.Delay(1000, _cts.Token);
            }
        }
    }

    private async Task ProcessFileAsync(string filePath)
    {
        var fileName = Path.GetFileName(filePath);
        var result = new ScanResult 
        { 
            FileName = fileName, 
            FullPath = filePath, 
            Status = ScanStatus.Scanning 
        };
        _onResultUpdated(result);

        try
        {
            // 1. Check for lock
            if (IsFileLocked(filePath))
            {
                Log($"File is locked: {fileName}. Skipping.");
                result.Status = ScanStatus.PendingLocked;
                _onResultUpdated(result);
                return;
            }

            // 2. Scan
            Log($"Scanning file: {fileName}");
            var status = await _vtService.ScanFileAsync(filePath, _cts.Token);

            // 3. Move and Update Status
            if (status == ScanResultStatus.Clean)
            {
                result.Status = ScanStatus.Clean;
                MoveFile(filePath, _settings.Paths.CleanDirectory);
                Log($"File {fileName} is CLEAN. Moved to clean directory.");
            }
            else if (status == ScanResultStatus.Compromised)
            {
                result.Status = ScanStatus.Compromised;
                MoveFile(filePath, _settings.Paths.CompromisedDirectory);
                Log($"File {fileName} is COMPROMISED. Moved to compromised directory.");
            }
            else
            {
                Log($"File {fileName} status is UNKNOWN.");
            }
        }
        catch (Exception ex)
        {
            Log($"Error processing {fileName}: {ex.Message}");
            // Keep as scanning or set to error state if we had one
        }
        
        _onResultUpdated(result);
    }

    private bool IsFileLocked(string filePath)
    {
        try
        {
            using FileStream stream = File.Open(filePath, FileMode.Open, FileAccess.Read, FileShare.None);
            stream.Close();
        }
        catch (IOException)
        {
            return true;
        }
        return false;
    }

    private void MoveFile(string sourcePath, string? destDir)
    {
        if (string.IsNullOrWhiteSpace(destDir))
        {
            Log($"Destination directory not configured for {Path.GetFileName(sourcePath)}");
            return;
        }

        if (!Directory.Exists(destDir))
        {
            Directory.CreateDirectory(destDir);
        }

        string destPath = Path.Combine(destDir, Path.GetFileName(sourcePath));
        
        // Handle overwrite or rename? Assuming overwrite for now or unique name
        if (File.Exists(destPath))
        {
            string timestamp = DateTime.Now.ToString("yyyyMMddHHmmss");
            destPath = Path.Combine(destDir, $"{Path.GetFileNameWithoutExtension(sourcePath)}_{timestamp}{Path.GetExtension(sourcePath)}");
        }

        File.Move(sourcePath, destPath);
    }

    private void Log(string message)
    {
        _onLog(message);
        
        try
        {
            if (!string.IsNullOrWhiteSpace(_settings.Paths.LogFilePath))
            {
                string logDir = Path.GetDirectoryName(_settings.Paths.LogFilePath)!;
                if (!Directory.Exists(logDir)) Directory.CreateDirectory(logDir);
                
                File.AppendAllText(_settings.Paths.LogFilePath, $"{DateTime.Now}: {message}{Environment.NewLine}");
            }
        }
        catch
        {
            // Ignore logging errors
        }
    }

    public void Dispose()
    {
        _cts.Cancel();
        _watcher?.Dispose();
    }
}

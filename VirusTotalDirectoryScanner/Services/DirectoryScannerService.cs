using System.Collections.Concurrent;
using System.Timers;
using VirusTotalDirectoryScanner.Models;
using VirusTotalDirectoryScanner.Settings;
using Timer = System.Timers.Timer;

namespace VirusTotalDirectoryScanner.Services;

public class DirectoryScannerService : IDisposable
{
    private readonly VirusTotalService _vtService;
    private readonly SettingsService _settingsService;
    private readonly IFileOperationsService _fileOperationsService;
    
    public event EventHandler<ScanResult>? ScanResultUpdated;
    public event EventHandler<string>? LogMessage;

    private FileSystemWatcher? _watcher;
    private readonly ConcurrentQueue<string> _fileQueue = new();
    private readonly CancellationTokenSource _cts = new();
    private Task? _processingTask;
    
    private readonly ConcurrentDictionary<string, byte> _lockedFiles = new();
    private readonly Timer _lockedFileTimer;

    public DirectoryScannerService(
        VirusTotalService vtService, 
        SettingsService settingsService,
        IFileOperationsService fileOperationsService)
    {
        _vtService = vtService;
        _settingsService = settingsService;
        _fileOperationsService = fileOperationsService;
        
        _lockedFileTimer = new Timer(30000); // 30 seconds
        _lockedFileTimer.Elapsed += OnLockedFileTimerElapsed;
        _lockedFileTimer.AutoReset = true;
    }

    public void Start()
    {
        var settings = _settingsService.CurrentSettings;
        if (string.IsNullOrWhiteSpace(settings.Paths.ScanDirectory))
        {
            LogMessage?.Invoke(this, "Scan directory is not configured.");
            return;
        }

        if (!_fileOperationsService.DirectoryExists(settings.Paths.ScanDirectory))
        {
            try
            {
                _fileOperationsService.CreateDirectory(settings.Paths.ScanDirectory);
                LogMessage?.Invoke(this, $"Created scan directory: {settings.Paths.ScanDirectory}");
            }
            catch (Exception ex)
            {
                LogMessage?.Invoke(this, $"Failed to create scan directory: {ex.Message}");
                return;
            }
        }

        _watcher = new FileSystemWatcher(settings.Paths.ScanDirectory);
        _watcher.Created += OnFileCreated;
        _watcher.EnableRaisingEvents = true;

        _processingTask = Task.Run(ProcessQueueAsync);
        LogMessage?.Invoke(this, $"Started monitoring {settings.Paths.ScanDirectory}");
        
        // Process existing files
        Task.Run(() => 
        {
            try
            {
                var files = _fileOperationsService.GetFiles(settings.Paths.ScanDirectory);
                LogMessage?.Invoke(this, $"Found {files.Length} existing files.");
                foreach (var file in files)
                {
                    EnqueueFile(file);
                }
            }
            catch (Exception ex)
            {
                LogMessage?.Invoke(this, $"Error detecting existing files: {ex.Message}");
            }
        });
    }

    private void OnFileCreated(object sender, FileSystemEventArgs e)
    {
        EnqueueFile(e.FullPath);
    }

    private void EnqueueFile(string fullPath)
    {
        var settings = _settingsService.CurrentSettings;
        if (!string.IsNullOrEmpty(settings.Paths.LogFilePath) && 
            string.Equals(Path.GetFullPath(fullPath), Path.GetFullPath(settings.Paths.LogFilePath), StringComparison.OrdinalIgnoreCase))
        {
            return;
        }

        _fileQueue.Enqueue(fullPath);
        
        // Notify UI of pending file
        ScanResultUpdated?.Invoke(this, new ScanResult 
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
        ScanResultUpdated?.Invoke(this, result);

        try
        {
            // 1. Check for lock
            if (_fileOperationsService.IsFileLocked(filePath))
            {
                Log($"File is locked: {fileName}. Queuing for retry.");
                result.Status = ScanStatus.PendingLocked;
                ScanResultUpdated?.Invoke(this, result);
                
                _lockedFiles.TryAdd(filePath, 0);
                if (!_lockedFileTimer.Enabled)
                {
                    _lockedFileTimer.Start();
                    Log("Locked file timer started.");
                }
                return;
            }

            // 2. Scan
            Log($"Scanning file: {fileName}");
            var scanResult = await _vtService.ScanFileAsync(filePath, _cts.Token);
            
            result.DetectionCount = scanResult.DetectionCount;
            result.FileHash = scanResult.Hash;

            // 3. Move and Update Status
            var settings = _settingsService.CurrentSettings;
            if (scanResult.Status == ScanResultStatus.Clean)
            {
                result.Status = ScanStatus.Clean;
                MoveFile(filePath, settings.Paths.CleanDirectory);
                Log($"File {fileName} is CLEAN. Moved to clean directory.");
            }
            else if (scanResult.Status == ScanResultStatus.Compromised)
            {
                result.Status = ScanStatus.Compromised;
                MoveFile(filePath, settings.Paths.CompromisedDirectory);
                Log($"File {fileName} is COMPROMISED. Moved to compromised directory.");
            }
            else if (scanResult.Status == ScanResultStatus.Failed)
            {
                result.Status = ScanStatus.Failed;
                result.Message = scanResult.Message ?? "Unknown error";
                Log($"File {fileName} FAILED: {result.Message}");
            }
            else
            {
                Log($"File {fileName} status is UNKNOWN.");
            }
        }
        catch (Exception ex)
        {
            Log($"Error processing {fileName}: {ex.Message}");
            result.Status = ScanStatus.Failed;
            result.Message = ex.Message;
        }
        
        ScanResultUpdated?.Invoke(this, result);
    }

    private void OnLockedFileTimerElapsed(object? sender, ElapsedEventArgs e)
    {
        if (_lockedFiles.IsEmpty)
        {
            _lockedFileTimer.Stop();
            Log("Locked file timer stopped (no locked files).");
            return;
        }

        foreach (var filePath in _lockedFiles.Keys)
        {
            if (!_fileOperationsService.FileExists(filePath))
            {
                // File gone? Remove from locked list
                _lockedFiles.TryRemove(filePath, out _);
                continue;
            }

            if (!_fileOperationsService.IsFileLocked(filePath))
            {
                // Unlocked! Move back to queue
                if (_lockedFiles.TryRemove(filePath, out _))
                {
                    Log($"File unlocked: {Path.GetFileName(filePath)}. Re-queuing.");
                    _fileQueue.Enqueue(filePath);
                }
            }
        }
        
        if (_lockedFiles.IsEmpty)
        {
            _lockedFileTimer.Stop();
            Log("Locked file timer stopped.");
        }
    }

    private void MoveFile(string sourcePath, string? destDir)
    {
        if (string.IsNullOrWhiteSpace(destDir))
        {
            Log($"Destination directory not configured for {Path.GetFileName(sourcePath)}");
            return;
        }

        if (!_fileOperationsService.DirectoryExists(destDir))
        {
            _fileOperationsService.CreateDirectory(destDir);
        }

        string destPath = Path.Combine(destDir, Path.GetFileName(sourcePath));
        
        // Handle overwrite or rename? Assuming overwrite for now or unique name
        if (_fileOperationsService.FileExists(destPath))
        {
            string timestamp = DateTime.Now.ToString("yyyyMMddHHmmss");
            destPath = Path.Combine(destDir, $"{Path.GetFileNameWithoutExtension(sourcePath)}_{timestamp}{Path.GetExtension(sourcePath)}");
        }

        _fileOperationsService.MoveFile(sourcePath, destPath);
    }

    private void Log(string message)
    {
        LogMessage?.Invoke(this, message);
        
        try
        {
            var settings = _settingsService.CurrentSettings;
            if (!string.IsNullOrWhiteSpace(settings.Paths.LogFilePath))
            {
                string logDir = Path.GetDirectoryName(settings.Paths.LogFilePath)!;
                if (!_fileOperationsService.DirectoryExists(logDir)) _fileOperationsService.CreateDirectory(logDir);
                
                _fileOperationsService.AppendAllText(settings.Paths.LogFilePath, $"{DateTime.Now}: {message}{Environment.NewLine}");
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
        _lockedFileTimer.Stop();
        _lockedFileTimer.Dispose();
    }
}

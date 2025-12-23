using System.Collections.Concurrent;
using System.Timers;
using VirusTotalDirectoryScanner.Models;
using VirusTotalDirectoryScanner.Settings;
using Timer = System.Timers.Timer;

namespace VirusTotalDirectoryScanner.Services;

public class DirectoryScannerService : IDisposable
{
    private readonly IVirusTotalService _vtService;
    private readonly ISettingsService _settingsService;
    private readonly IFileOperationsService _fileOperationsService;
    private readonly IDirectoryWatcherFactory _watcherFactory;
    private readonly IRateLimitService _rateLimitService;
    
    public event EventHandler<ScanResult>? ScanResultUpdated;
    public event EventHandler<string>? LogMessage;

    private IDirectoryWatcher? _watcher;
    private readonly ConcurrentQueue<string> _fileQueue = new();
    private readonly CancellationTokenSource _cts = new();
    private Task? _processingTask;
    
    private readonly ConcurrentDictionary<string, byte> _lockedFiles = new();
    private readonly Timer _lockedFileTimer;

    public DirectoryScannerService(
        IVirusTotalService vtService, 
        ISettingsService settingsService,
        IFileOperationsService fileOperationsService,
        IDirectoryWatcherFactory watcherFactory,
        IRateLimitService rateLimitService)
    {
        _vtService = vtService;
        _settingsService = settingsService;
        _fileOperationsService = fileOperationsService;
        _watcherFactory = watcherFactory;
        _rateLimitService = rateLimitService;
        
        _lockedFileTimer = new Timer(5000); // 5 seconds
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

        _watcher = _watcherFactory.Create(settings.Paths.ScanDirectory);
        _watcher.Created += OnFileCreated;
        _watcher.Renamed += OnRenamed;
        _watcher.Changed += OnChanged;
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
        // Add a small delay to allow browser rename operations to complete
        // This helps prevent "ghost" files (intermediate GUIDs) from being picked up immediately
        Task.Run(async () =>
        {
            await Task.Delay(2000);
            
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
        // Check if file still exists (it might have been renamed/deleted during the delay)
        if (!_fileOperationsService.FileExists(filePath))
        {
             // If it's gone, notify UI to remove it (in case we sent a Pending status)
            ScanResultUpdated?.Invoke(this, new ScanResult 
            { 
                FileName = Path.GetFileName(filePath), 
                FullPath = filePath, 
                Status = ScanStatus.Removed 
            });
            return;
        }

        var fileName = Path.GetFileName(filePath);
        var result = new ScanResult 
        { 
            FileName = fileName, 
            FullPath = filePath, 
            Status = ScanStatus.Scanning 
        };
        ScanResultUpdated?.Invoke(this, result);
        
        // Skip MS Office temp files
        if (fileName.StartsWith("~$"))
        {
            result.Status = ScanStatus.Skipped;
            result.Message = "office log file";
            Log($"Skipping file {fileName}: {result.Message}");
            ScanResultUpdated?.Invoke(this, result);
            return;
        }

        // Skip browser incomplete downloads
        var extension = Path.GetExtension(fileName).ToLowerInvariant();
        if (extension == ".crdownload" || extension == ".part" || extension == ".download")
        {
            result.Status = ScanStatus.Skipped;
            result.Message = "browser download file";
            Log($"Skipping file {fileName}: {result.Message}");
            ScanResultUpdated?.Invoke(this, result);
            return;
        }

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

            CancellationTokenSource? countdownCts = null;
            void OnRateLimitHit(object? sender, TimeSpan waitTime)
            {
                countdownCts?.Cancel();
                countdownCts = new CancellationTokenSource();
                var token = countdownCts.Token;

                Task.Run(async () =>
                {
                    var remaining = waitTime;
                    while (remaining.TotalSeconds > 0 && !token.IsCancellationRequested)
                    {
                        result.Message = $"Waiting for quota: {remaining.Seconds}s";
                        ScanResultUpdated?.Invoke(this, result);
                        
                        await Task.Delay(1000, token);
                        remaining = remaining.Subtract(TimeSpan.FromSeconds(1));
                    }
                    if (!token.IsCancellationRequested)
                    {
                        result.Message = "";
                        ScanResultUpdated?.Invoke(this, result);
                    }
                }, token);
            }

            _rateLimitService.RateLimitHit += OnRateLimitHit;
            (ScanResultStatus Status, int DetectionCount, string Hash, string? Message) scanResult;
            try
            {
                scanResult = await _vtService.ScanFileAsync(filePath, _cts.Token);
            }
            finally
            {
                _rateLimitService.RateLimitHit -= OnRateLimitHit;
                countdownCts?.Cancel();
                result.Message = ""; // Clear message
                ScanResultUpdated?.Invoke(this, result);
            }
            
            result.DetectionCount = scanResult.DetectionCount;
            result.FileHash = scanResult.Hash;

            // 3. Move and Update Status
            var settings = _settingsService.CurrentSettings;
            if (scanResult.Status == ScanResultStatus.Clean)
            {
                result.Status = ScanStatus.Clean;
                await MoveFileAsync(filePath, settings.Paths.CleanDirectory, _cts.Token);
                Log($"File {fileName} is CLEAN. Moved to clean directory.");
            }
            else if (scanResult.Status == ScanResultStatus.Compromised)
            {
                result.Status = ScanStatus.Compromised;
                await MoveFileAsync(filePath, settings.Paths.CompromisedDirectory, _cts.Token);
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

    private void OnRenamed(object sender, RenamedEventArgs e)
    {
        // If the old file was locked, remove it from the locked list
        bool wasLocked = _lockedFiles.TryRemove(e.OldFullPath, out _);
        
        Log($"File renamed: {e.OldName} -> {e.Name} (WasLocked: {wasLocked})");

        // Notify UI that the old file is now this new file
        // This will update the existing row if found
        ScanResultUpdated?.Invoke(this, new ScanResult 
        { 
            FileName = e.Name, 
            FullPath = e.FullPath, 
            OriginalFullPath = e.OldFullPath, // Link to the old file
            Status = ScanStatus.Pending,
            Message = "Renamed"
        });
        
        // Enqueue the new file name for scanning (if it wasn't just a simple rename)
        // Actually, if we just updated the status to Pending above, we might want to ensure it gets processed.
        // But EnqueueFile pushes to _fileQueue which is picked up by ProcessQueueAsync.
        // We probably don't need to update UI with "Pending" above AND enqueue, but "Pending" provides immediate feedback.
        
        EnqueueFile(e.FullPath);
    }

    private void OnChanged(object sender, FileSystemEventArgs e)
    {
        // If this file is in our locked list, check if it's unlocked now
        if (_lockedFiles.ContainsKey(e.FullPath))
        {
            if (!_fileOperationsService.IsFileLocked(e.FullPath))
            {
                if (_lockedFiles.TryRemove(e.FullPath, out _))
                {
                    Log($"Locked file changed and unlocked: {e.Name}. Re-queuing.");
                    _fileQueue.Enqueue(e.FullPath);
                }
            }
        }
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
                if (_lockedFiles.TryRemove(filePath, out _))
                {
                    Log($"Locked file disappeared: {Path.GetFileName(filePath)}");
                    // Update UI to remove the "Pending (Locked)" state
                    ScanResultUpdated?.Invoke(this, new ScanResult 
                    { 
                        FileName = Path.GetFileName(filePath), 
                        FullPath = filePath, 
                        Status = ScanStatus.Removed, 
                        Message = "File disappeared" 
                    });
                }
                continue;
            }

            if (!_fileOperationsService.IsFileLocked(filePath))
            {
                // Unlocked! Move back to queue
                if (_lockedFiles.TryRemove(filePath, out _))
                {
                    Log($"File unlocked (timer): {Path.GetFileName(filePath)}. Re-queuing.");
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

    private async Task MoveFileAsync(string sourcePath, string? destDir, CancellationToken ct)
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
        
        if (_fileOperationsService.FileExists(destPath))
        {
            string sourceHash = await _fileOperationsService.CalculateSha256Async(sourcePath, ct);
            string destHash = await _fileOperationsService.CalculateSha256Async(destPath, ct);

            if (sourceHash == destHash)
            {
                Log($"File {Path.GetFileName(sourcePath)} already exists in destination with same checksum. Overwriting.");
                _fileOperationsService.DeleteFile(destPath);
            }
            else
            {
                string timestamp = DateTime.Now.ToString("yyyyMMddHHmmss");
                destPath = Path.Combine(destDir, $"{Path.GetFileNameWithoutExtension(sourcePath)}_{timestamp}{Path.GetExtension(sourcePath)}");
                Log($"File {Path.GetFileName(sourcePath)} already exists in destination with DIFFERENT checksum. Renaming to {Path.GetFileName(destPath)}.");
            }
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

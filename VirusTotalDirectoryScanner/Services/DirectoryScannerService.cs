using System.Collections.Concurrent;
using System.Timers;
using VirusTotalDirectoryScanner.Models;
using VirusTotalDirectoryScanner.Settings;
using Timer = System.Timers.Timer;

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
    
    private readonly ConcurrentDictionary<string, byte> _lockedFiles = new();
    private readonly Timer _lockedFileTimer;

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
        
        _lockedFileTimer = new Timer(30000); // 30 seconds
        _lockedFileTimer.Elapsed += OnLockedFileTimerElapsed;
        _lockedFileTimer.AutoReset = true;
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
        Task.Run(() => 
        {
            try
            {
                var files = Directory.GetFiles(_settings.Paths.ScanDirectory);
                _onLog($"Found {files.Length} existing files.");
                foreach (var file in files)
                {
                    EnqueueFile(file);
                }
            }
            catch (Exception ex)
            {
                _onLog($"Error detecting existing files: {ex.Message}");
            }
        });
    }

    private void OnFileCreated(object sender, FileSystemEventArgs e)
    {
        EnqueueFile(e.FullPath);
    }

    private void EnqueueFile(string fullPath)
    {
        if (!string.IsNullOrEmpty(_settings.Paths.LogFilePath) && 
            string.Equals(Path.GetFullPath(fullPath), Path.GetFullPath(_settings.Paths.LogFilePath), StringComparison.OrdinalIgnoreCase))
        {
            return;
        }

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
                Log($"File is locked: {fileName}. Queuing for retry.");
                result.Status = ScanStatus.PendingLocked;
                _onResultUpdated(result);
                
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
            if (scanResult.Status == ScanResultStatus.Clean)
            {
                result.Status = ScanStatus.Clean;
                MoveFile(filePath, _settings.Paths.CleanDirectory);
                Log($"File {fileName} is CLEAN. Moved to clean directory.");
            }
            else if (scanResult.Status == ScanResultStatus.Compromised)
            {
                result.Status = ScanStatus.Compromised;
                MoveFile(filePath, _settings.Paths.CompromisedDirectory);
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
        
        _onResultUpdated(result);
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
            if (!File.Exists(filePath))
            {
                // File gone? Remove from locked list
                _lockedFiles.TryRemove(filePath, out _);
                continue;
            }

            if (!IsFileLocked(filePath))
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
        _lockedFileTimer.Stop();
        _lockedFileTimer.Dispose();
    }
}

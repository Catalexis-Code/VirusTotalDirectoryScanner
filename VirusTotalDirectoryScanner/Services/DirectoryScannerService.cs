using System.Collections.Concurrent;
using System.Timers;
using VirusTotalDirectoryScanner.Models;
using VirusTotalDirectoryScanner.Settings;
using System.IO.Enumeration;
using Timer = System.Timers.Timer;

namespace VirusTotalDirectoryScanner.Services;

public class DirectoryScannerService : IDisposable
{
    private readonly IVirusTotalService _vtService;
    private readonly ISettingsService _settingsService;
    private readonly IFileOperationsService _fileOperationsService;
    private readonly IDirectoryWatcherFactory _watcherFactory;
    private readonly IRateLimitService _rateLimitService;
    private readonly INotificationService _notificationService;
    
    public event EventHandler<ScanResult>? ScanResultUpdated;
    public event EventHandler<string>? LogMessage;
    public event EventHandler<bool>? DirectoryAvailabilityChanged; // true = available, false = unavailable

    private IDirectoryWatcher? _watcher;
    private readonly ConcurrentQueue<string> _fileQueue = new();
    private readonly CancellationTokenSource _cts = new();
    private Task? _processingTask;
    
	private readonly ConcurrentDictionary<string, byte> _lockedFiles = new();
	private readonly ConcurrentDictionary<string, byte> _skipMoveFiles = new();
	private readonly Timer _lockedFileTimer;
	private readonly Timer _watcherHealthTimer;

    // Health check state
    private volatile bool _healthCheckFileDetected = false;
    private string? _currentHealthCheckFilePath = null;
    private readonly object _healthCheckLock = new();
    private bool _isDirectoryAvailable = true;
    
    // Prefix for health check files - these are automatically excluded from scanning
    internal const string HealthCheckFilePrefix = ".vt_health_check_";

    // Constants for default delays
    public const int DefaultInitialDelayMs = 2000;
    public const int DefaultQueuePollingIntervalMs = 1000;
    public const int DefaultLockedFileCheckIntervalMs = 5000;
    public const int DefaultWatcherHealthCheckIntervalMs = 300000; // 5 minutes

    // Configurable delays for testing
    internal int InitialDelayMs { get; set; } = DefaultInitialDelayMs;
    internal int QueuePollingIntervalMs { get; set; } = DefaultQueuePollingIntervalMs;
    internal int LockedFileCheckIntervalMs { get; set; } = DefaultLockedFileCheckIntervalMs;
    internal int WatcherHealthCheckIntervalMs { get; set; } = DefaultWatcherHealthCheckIntervalMs;

    public DirectoryScannerService(
        IVirusTotalService vtService, 
        ISettingsService settingsService,
        IFileOperationsService fileOperationsService,
        IDirectoryWatcherFactory watcherFactory,
        IRateLimitService rateLimitService,
        INotificationService notificationService)
    {
        _vtService = vtService;
        _settingsService = settingsService;
        _fileOperationsService = fileOperationsService;
        _watcherFactory = watcherFactory;
        _rateLimitService = rateLimitService;
        _notificationService = notificationService;
        
        _lockedFileTimer = new Timer(LockedFileCheckIntervalMs);
        _lockedFileTimer.Elapsed += OnLockedFileTimerElapsed;
        _lockedFileTimer.AutoReset = true;
        
        _watcherHealthTimer = new Timer(WatcherHealthCheckIntervalMs);
        _watcherHealthTimer.Elapsed += OnWatcherHealthCheckElapsed;
        _watcherHealthTimer.AutoReset = true;
	}

	/// <summary>
	/// Scans a file that was dropped/selected by the user.
	/// The file will NOT be moved to Clean/Compromised directories after scanning.
	/// </summary>
	public void ScanDroppedFile(string filePath)
	{
		if (!_fileOperationsService.FileExists(filePath))
		{
			LogMessage?.Invoke(this, $"Dropped file does not exist: {filePath}");
			return;
		}

		var fileName = Path.GetFileName(filePath);
		if (IsExcluded(fileName))
		{
			LogMessage?.Invoke(this, $"Dropped file is excluded: {fileName}");
			return;
		}

		// Mark this file to skip moving after scan
		_skipMoveFiles.TryAdd(filePath, 0);

		// Notify UI of pending file
		ScanResultUpdated?.Invoke(this, new ScanResult
		{
			FileName = fileName,
			FullPath = filePath,
			Status = ScanStatus.Pending,
			SkipMoveOnComplete = true
		});

		_fileQueue.Enqueue(filePath);
	}

	public void Start()
    {
        var settings = _settingsService.CurrentSettings;
        if (string.IsNullOrWhiteSpace(settings.Paths.ScanDirectory))
        {
            LogMessage?.Invoke(this, "Scan directory is not configured.");
            return;
        }

        bool directoryReady = _fileOperationsService.DirectoryExists(settings.Paths.ScanDirectory);
        
        if (!directoryReady)
        {
            LogMessage?.Invoke(this, $"Scan directory does not exist: {settings.Paths.ScanDirectory}. Waiting for directory to become available.");
            _isDirectoryAvailable = false;
            DirectoryAvailabilityChanged?.Invoke(this, false);
        }

        if (directoryReady)
        {
            SetupWatcher();
            ScanExistingFiles();
            LogMessage?.Invoke(this, $"Started monitoring {settings.Paths.ScanDirectory}");
        }

        // Sync timer intervals in case they were configured after construction
        _lockedFileTimer.Interval = LockedFileCheckIntervalMs;
        _watcherHealthTimer.Interval = WatcherHealthCheckIntervalMs;
        
        // Start the watcher health check timer - always start even if directory unavailable
        // so we can detect when it becomes available
        _watcherHealthTimer.Start();
        Log($"Watcher health check timer started (interval: {WatcherHealthCheckIntervalMs / 1000}s)");

        _processingTask = Task.Run(ProcessQueueAsync);
    }

    private void SetupWatcher()
    {
        try
        {
            if (_watcher != null)
            {
                _watcher.Dispose();
                _watcher = null;
            }

            var settings = _settingsService.CurrentSettings;
            _watcher = _watcherFactory.Create(settings.Paths.ScanDirectory!);
            _watcher.Created += OnFileCreated;
            _watcher.Renamed += OnRenamed;
            _watcher.Changed += OnChanged;
            _watcher.Error += OnWatcherError;
            _watcher.EnableRaisingEvents = true;
        }
        catch (Exception ex)
        {
            LogMessage?.Invoke(this, $"Failed to setup file watcher: {ex.Message}");
        }
    }

    private void OnWatcherError(object sender, ErrorEventArgs e)
    {
        LogMessage?.Invoke(this, $"File Watcher Error: {e.GetException().Message}. Restarting watcher...");
        SetupWatcher();
        ScanExistingFiles();
    }

    private void ScanExistingFiles()
    {
        Task.Run(() => 
        {
            try
            {
                var settings = _settingsService.CurrentSettings;
                var files = _fileOperationsService.GetFiles(settings.Paths.ScanDirectory!);
                LogMessage?.Invoke(this, $"Found {files.Length} existing files.");
                foreach (var file in files)
                {
                    if (IsExcluded(Path.GetFileName(file))) continue;
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
        // Check if this is a health check file
        var fileName = Path.GetFileName(e.FullPath);
        if (fileName.StartsWith(HealthCheckFilePrefix, StringComparison.OrdinalIgnoreCase))
        {
            lock (_healthCheckLock)
            {
                if (_currentHealthCheckFilePath != null && 
                    string.Equals(e.FullPath, _currentHealthCheckFilePath, StringComparison.OrdinalIgnoreCase))
                {
                    _healthCheckFileDetected = true;
                    Log("Health check: Watcher is functioning correctly.");
                }
            }
            return; // Don't enqueue health check files
        }
        
        EnqueueFile(e.FullPath);
    }

    private bool IsExcluded(string fileName)
    {
        // Health check files are always excluded
        if (fileName.StartsWith(HealthCheckFilePrefix, StringComparison.OrdinalIgnoreCase))
        {
            return true;
        }
        
        var settings = _settingsService.CurrentSettings;
        foreach (var pattern in settings.FileExclusions)
        {
            if (FileSystemName.MatchesSimpleExpression(pattern, fileName))
            {
                return true;
            }
        }
        return false;
    }

    private void EnqueueFile(string fullPath)
    {
        // Check exclusions immediately to prevent "Pending" state for excluded files
        if (IsExcluded(Path.GetFileName(fullPath)))
        {
             return;
        }

        // Add a small delay to allow browser rename operations to complete
        // This helps prevent "ghost" files (intermediate GUIDs) from being picked up immediately
        _ = Task.Run(async () =>
        {
            try
            {
                await Task.Delay(InitialDelayMs, _cts.Token);
                
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
            catch (OperationCanceledException)
            {
                // Service is being disposed, ignore
            }
            catch (Exception ex)
            {
                Log($"Error enqueueing file {Path.GetFileName(fullPath)}: {ex.Message}");
            }
        });
    }

    private async Task ProcessQueueAsync()
    {
        try
        {
            while (!_cts.Token.IsCancellationRequested)
            {
                if (_fileQueue.TryDequeue(out string? filePath))
                {
                    await ProcessFileAsync(filePath);
                }
                else
                {
                    await Task.Delay(QueuePollingIntervalMs, _cts.Token);
                }
            }
        }
        catch (OperationCanceledException)
        {
            // Expected when service is disposed - exit gracefully
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
		
		// Check if this file should skip moving (dropped file)
		bool skipMove = _skipMoveFiles.TryRemove(filePath, out _);
		
		var result = new ScanResult 
		{ 
			FileName = fileName, 
			FullPath = filePath, 
			Status = ScanStatus.Scanning,
			SkipMoveOnComplete = skipMove
		};
        
        // Note: Files reaching this point have already passed exclusion checks in EnqueueFile/ScanExistingFiles.
        // ScanDroppedFile also has its own exclusion check before enqueueing.

        // Get settings for move directories
        var settings = _settingsService.CurrentSettings;

        // File is ready to scan
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

            void OnRateLimitResolved(object? sender, EventArgs e)
            {
                countdownCts?.Cancel();
                result.Message = ""; 
                ScanResultUpdated?.Invoke(this, result);
            }

            _rateLimitService.RateLimitHit += OnRateLimitHit;
            _rateLimitService.RateLimitResolved += OnRateLimitResolved;

            (ScanResultStatus Status, int DetectionCount, string Hash, string? Message) scanResult;
            try
            {
                scanResult = await _vtService.ScanFileAsync(filePath, phase => 
                {
                    // Update status based on phase
                    switch (phase)
                    {
                        case ScanPhase.CalculatingChecksum:
                            result.Status = ScanStatus.CalculatingChecksum;
                             result.Message = "";
                            break;
                        case ScanPhase.CheckingCache:
                            result.Status = ScanStatus.Scanning;
                            result.Message = "Checking cache...";
                            break;
                        case ScanPhase.Uploading:
                            result.Status = ScanStatus.Uploading;
                             result.Message = "";
                            break;
                        case ScanPhase.WaitingForAnalysis:
                            result.Status = ScanStatus.Scanning;
                            result.Message = "Waiting for analysis...";
                            break;
                    }
                    ScanResultUpdated?.Invoke(this, result);
                }, _cts.Token);
            }
            finally
            {
                _rateLimitService.RateLimitHit -= OnRateLimitHit;
                _rateLimitService.RateLimitResolved -= OnRateLimitResolved;
                countdownCts?.Cancel();
                result.Message = ""; // Clear message
                ScanResultUpdated?.Invoke(this, result);
            }
            
            result.DetectionCount = scanResult.DetectionCount;
            result.FileHash = scanResult.Hash;

            // 3. Move and Update Status

			if (scanResult.Status == ScanResultStatus.Clean)
			{
				result.Status = ScanStatus.Clean;
				if (!result.SkipMoveOnComplete)
				{
					var newPath = await MoveFileAsync(filePath, settings.Paths.CleanDirectory, _cts.Token);
					if (newPath != null)
					{
						result.OriginalFullPath = filePath;
						result.FullPath = newPath;
					}
					Log($"File {fileName} is CLEAN. Moved to clean directory.");
				}
				else
				{
					Log($"File {fileName} is CLEAN. (Dropped file - not moved)");
				}
			}
			else if (scanResult.Status == ScanResultStatus.Compromised)
			{
				result.Status = ScanStatus.Compromised;
				_notificationService.ShowThreatDetectedNotification(fileName, scanResult.DetectionCount);
				if (!result.SkipMoveOnComplete)
				{
					var newPath = await MoveFileAsync(filePath, settings.Paths.CompromisedDirectory, _cts.Token);
					if (newPath != null)
					{
						result.OriginalFullPath = filePath;
						result.FullPath = newPath;
					}
					Log($"File {fileName} is COMPROMISED. Moved to compromised directory.");
				}
				else
				{
					Log($"File {fileName} is COMPROMISED. (Dropped file - not moved)");
				}
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

        // If the new name is excluded, ensure the old entry is removed and do not track the new one
        if (e.Name != null && IsExcluded(e.Name))
        {
            ScanResultUpdated?.Invoke(this, new ScanResult 
            { 
                FileName = Path.GetFileName(e.OldFullPath), 
                FullPath = e.OldFullPath, 
                Status = ScanStatus.Removed,
                Message = "Renamed to excluded file"
            });
            return;
        }

        // If the new name is null, we can't proceed
        if (e.Name == null)
            return;

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

    private async Task<string?> MoveFileAsync(string sourcePath, string? destDir, CancellationToken ct)
    {
        if (string.IsNullOrWhiteSpace(destDir))
        {
            Log($"Destination directory not configured for {Path.GetFileName(sourcePath)}");
            return null;
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
        return destPath;
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
                
                // If the log directory is inside the scan directory and scan directory doesn't exist,
                // skip writing to the log file to avoid creating the scan directory prematurely
                if (!string.IsNullOrWhiteSpace(settings.Paths.ScanDirectory))
                {
                    string scanDirFull = Path.GetFullPath(settings.Paths.ScanDirectory);
                    string logDirFull = Path.GetFullPath(logDir);
                    
                    if (logDirFull.StartsWith(scanDirFull, StringComparison.OrdinalIgnoreCase) &&
                        !_fileOperationsService.DirectoryExists(scanDirFull))
                    {
                        // Log directory is inside scan directory which doesn't exist yet - skip logging to file
                        return;
                    }
                }
                
                if (!_fileOperationsService.DirectoryExists(logDir)) _fileOperationsService.CreateDirectory(logDir);
                
                _fileOperationsService.AppendAllText(settings.Paths.LogFilePath, $"{DateTime.Now}: {message}{Environment.NewLine}");
            }
        }
        catch
        {
            // Ignore logging errors
        }
    }

    private void OnWatcherHealthCheckElapsed(object? sender, ElapsedEventArgs e)
    {
        var settings = _settingsService.CurrentSettings;
        if (string.IsNullOrWhiteSpace(settings.Paths.ScanDirectory))
        {
            return;
        }
        
        bool directoryExists = _fileOperationsService.DirectoryExists(settings.Paths.ScanDirectory);
        
        // Handle directory availability changes
        if (!directoryExists)
        {
            if (_isDirectoryAvailable)
            {
                // Directory was available but is now unavailable
                _isDirectoryAvailable = false;
                Log("Health check: Scan directory is no longer available.");
                DirectoryAvailabilityChanged?.Invoke(this, false);
            }
            else
            {
                Log("Health check: Scan directory still not available. Waiting...");
            }
            return;
        }
        
        // Directory exists - check if we need to recover
        if (!_isDirectoryAvailable)
        {
            // Directory was unavailable but is now available - auto-recover!
            _isDirectoryAvailable = true;
            Log("Health check: Scan directory is now available. Recovering...");
            DirectoryAvailabilityChanged?.Invoke(this, true);
            
            // Restart the watcher and scan existing files
            SetupWatcher();
            ScanExistingFiles();
            Log("Health check: Watcher recovered and monitoring resumed.");
            return; // Skip the normal health check this cycle
        }

        string healthCheckFilePath = Path.Combine(
            settings.Paths.ScanDirectory, 
            $"{HealthCheckFilePrefix}{Guid.NewGuid():N}");

        try
        {
            // Reset detection flag and set current health check file
            lock (_healthCheckLock)
            {
                _healthCheckFileDetected = false;
                _currentHealthCheckFilePath = healthCheckFilePath;
            }

            // Create the health check file
            _fileOperationsService.WriteAllText(healthCheckFilePath, "health_check");
            Log($"Health check: Created test file {Path.GetFileName(healthCheckFilePath)}");

            // Wait a short time for the watcher to detect the file
            // Use a shorter wait than the normal initial delay since we just want to verify detection
            Thread.Sleep(Math.Min(InitialDelayMs, 1000));

            bool detected;
            lock (_healthCheckLock)
            {
                detected = _healthCheckFileDetected;
                _currentHealthCheckFilePath = null;
            }

            if (!detected)
            {
                // Check if watcher is still enabled
                bool watcherEnabled = _watcher?.IsWatching ?? false;
                Log($"Health check FAILED: Test file was not detected. Watcher enabled: {watcherEnabled}. Restarting watcher...");
                
                // Restart the watcher
                SetupWatcher();
                
                // Also scan existing files in case any were missed
                ScanExistingFiles();
                
                Log("Health check: Watcher has been restarted.");
            }
        }
        catch (Exception ex)
        {
            Log($"Health check error: {ex.Message}");
        }
        finally
        {
            // Clean up the health check file
            try
            {
                if (_fileOperationsService.FileExists(healthCheckFilePath))
                {
                    _fileOperationsService.DeleteFile(healthCheckFilePath);
                    Log($"Health check: Cleaned up test file {Path.GetFileName(healthCheckFilePath)}");
                }
            }
            catch (Exception ex)
            {
                Log($"Health check cleanup error: {ex.Message}");
            }
            
            lock (_healthCheckLock)
            {
                _currentHealthCheckFilePath = null;
            }
        }
    }

    public void Dispose()
    {
        _cts.Cancel();
        
        // Wait for processing task to complete before disposing resources
        try
        {
            _processingTask?.Wait(TimeSpan.FromSeconds(5));
        }
        catch (AggregateException)
        {
            // Task may have been cancelled or faulted, ignore
        }
        
        _watcher?.Dispose();
        _lockedFileTimer.Stop();
        _lockedFileTimer.Dispose();
        _watcherHealthTimer.Stop();
        _watcherHealthTimer.Dispose();
        _cts.Dispose();
    }
}

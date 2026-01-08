namespace VirusTotalDirectoryScanner.Services;

public interface IDirectoryWatcher : IDisposable
{
    event FileSystemEventHandler Created;
    event RenamedEventHandler Renamed;
    event FileSystemEventHandler Changed;
    event ErrorEventHandler Error;
    bool EnableRaisingEvents { get; set; }
    
    /// <summary>
    /// Gets the path being watched.
    /// </summary>
    string Path { get; }
    
    /// <summary>
    /// Gets whether the watcher is currently enabled and watching for events.
    /// </summary>
    bool IsWatching { get; }
}

public interface IDirectoryWatcherFactory
{
    IDirectoryWatcher Create(string path);
}

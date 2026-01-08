namespace VirusTotalDirectoryScanner.Services;

public class DirectoryWatcher : IDirectoryWatcher
{
    private readonly FileSystemWatcher _watcher;

    public DirectoryWatcher(string path)
    {
        _watcher = new FileSystemWatcher(path);
        _watcher.InternalBufferSize = 65536; // 64KB
    }

    public event FileSystemEventHandler Created
    {
        add => _watcher.Created += value;
        remove => _watcher.Created -= value;
    }

    public event RenamedEventHandler Renamed
    {
        add => _watcher.Renamed += value;
        remove => _watcher.Renamed -= value;
    }

    public event FileSystemEventHandler Changed
    {
        add => _watcher.Changed += value;
        remove => _watcher.Changed -= value;
    }

    public event ErrorEventHandler Error
    {
        add => _watcher.Error += value;
        remove => _watcher.Error -= value;
    }

    public bool EnableRaisingEvents
    {
        get => _watcher.EnableRaisingEvents;
        set => _watcher.EnableRaisingEvents = value;
    }

    public string Path => _watcher.Path;
    
    public bool IsWatching => _watcher.EnableRaisingEvents;

    public void Dispose()
    {
        _watcher.Dispose();
    }
}

public class DirectoryWatcherFactory : IDirectoryWatcherFactory
{
    public IDirectoryWatcher Create(string path)
    {
        return new DirectoryWatcher(path);
    }
}

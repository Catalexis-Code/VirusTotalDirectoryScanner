namespace VirusTotalDirectoryScanner.Services;

public class DirectoryWatcher : IDirectoryWatcher
{
    private readonly FileSystemWatcher _watcher;

    public DirectoryWatcher(string path)
    {
        _watcher = new FileSystemWatcher(path);
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

    public bool EnableRaisingEvents
    {
        get => _watcher.EnableRaisingEvents;
        set => _watcher.EnableRaisingEvents = value;
    }

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

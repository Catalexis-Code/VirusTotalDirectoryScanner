namespace VirusTotalDirectoryScanner.Services;

public interface IDirectoryWatcher : IDisposable
{
    event FileSystemEventHandler Created;
    event RenamedEventHandler Renamed;
    event FileSystemEventHandler Changed;
    bool EnableRaisingEvents { get; set; }
}

public interface IDirectoryWatcherFactory
{
    IDirectoryWatcher Create(string path);
}

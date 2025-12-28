namespace VirusTotalDirectoryScanner.Services;

public interface IDirectoryWatcher : IDisposable
{
    event FileSystemEventHandler Created;
    event RenamedEventHandler Renamed;
    event FileSystemEventHandler Changed;
    event ErrorEventHandler Error;
    bool EnableRaisingEvents { get; set; }
}

public interface IDirectoryWatcherFactory
{
    IDirectoryWatcher Create(string path);
}

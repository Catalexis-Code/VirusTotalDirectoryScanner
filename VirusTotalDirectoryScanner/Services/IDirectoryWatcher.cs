namespace VirusTotalDirectoryScanner.Services;

public interface IDirectoryWatcher : IDisposable
{
    event FileSystemEventHandler Created;
    bool EnableRaisingEvents { get; set; }
}

public interface IDirectoryWatcherFactory
{
    IDirectoryWatcher Create(string path);
}

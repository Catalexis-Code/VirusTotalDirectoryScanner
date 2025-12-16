using System.IO;

namespace VirusTotalDirectoryScanner.Services;

public class FileOperationsService : IFileOperationsService
{
    public bool DirectoryExists(string path)
    {
        return Directory.Exists(path);
    }

    public void CreateDirectory(string path)
    {
        Directory.CreateDirectory(path);
    }

    public string[] GetFiles(string path)
    {
        return Directory.GetFiles(path);
    }

    public bool FileExists(string path)
    {
        return File.Exists(path);
    }

    public bool IsFileLocked(string path)
    {
        try
        {
            using FileStream stream = File.Open(path, FileMode.Open, FileAccess.Read, FileShare.None);
            stream.Close();
        }
        catch (IOException)
        {
            return true;
        }
        return false;
    }

    public void MoveFile(string sourceFileName, string destFileName)
    {
        File.Move(sourceFileName, destFileName);
    }

    public void AppendAllText(string path, string contents)
    {
        File.AppendAllText(path, contents);
    }

    public Stream OpenRead(string path)
    {
        return File.OpenRead(path);
    }

    public long GetFileLength(string path)
    {
        return new FileInfo(path).Length;
    }
}

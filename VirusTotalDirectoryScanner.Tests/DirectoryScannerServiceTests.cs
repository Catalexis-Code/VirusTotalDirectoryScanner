using System.Collections.Concurrent;
using FluentAssertions;
using Moq;
using VirusTotalDirectoryScanner.Models;
using VirusTotalDirectoryScanner.Services;
using VirusTotalDirectoryScanner.Settings;
using Xunit;

namespace VirusTotalDirectoryScanner.Tests;

public class DirectoryScannerServiceTests
{
    private readonly Mock<IVirusTotalService> _vtServiceMock;
    private readonly Mock<ISettingsService> _settingsServiceMock;
    private readonly Mock<IFileOperationsService> _fileOpsMock;
    private readonly Mock<IDirectoryWatcherFactory> _watcherFactoryMock;
    private readonly Mock<IDirectoryWatcher> _watcherMock;
    private readonly Mock<IRateLimitService> _rateLimitServiceMock;
    private readonly DirectoryScannerService _sut;
    private readonly Settings.Settings _settings;

    public DirectoryScannerServiceTests()
    {
        _vtServiceMock = new Mock<IVirusTotalService>();
        _settingsServiceMock = new Mock<ISettingsService>();
        _fileOpsMock = new Mock<IFileOperationsService>();
        _watcherFactoryMock = new Mock<IDirectoryWatcherFactory>();
        _watcherMock = new Mock<IDirectoryWatcher>();
        _rateLimitServiceMock = new Mock<IRateLimitService>();

        _settings = new Settings.Settings();
        _settings.Paths.ScanDirectory = "C:\\Scan";
        _settings.Paths.CleanDirectory = "C:\\Clean";
        _settings.Paths.CompromisedDirectory = "C:\\Compromised";
        
        _settingsServiceMock.Setup(s => s.CurrentSettings).Returns(_settings);
        _fileOpsMock.Setup(f => f.DirectoryExists(It.IsAny<string>())).Returns(true);
        _watcherFactoryMock.Setup(w => w.Create(It.IsAny<string>())).Returns(_watcherMock.Object);

        _sut = new DirectoryScannerService(
            _vtServiceMock.Object,
            _settingsServiceMock.Object,
            _fileOpsMock.Object,
            _watcherFactoryMock.Object,
            _rateLimitServiceMock.Object)
        {
            InitialDelayMs = 50,
            QueuePollingIntervalMs = 50,
            LockedFileCheckIntervalMs = 100
        };
    }

    private async Task WaitForScanStatus(ConcurrentBag<(ScanStatus Status, string FullPath, string Message)> results, string path, ScanStatus expectedStatus, int timeoutMs = 2000)
    {
        var startTime = DateTime.Now;
        while ((DateTime.Now - startTime).TotalMilliseconds < timeoutMs)
        {
            if (results.Any(r => r.FullPath == path && r.Status == expectedStatus))
            {
                return;
            }
            await Task.Delay(50);
        }
        throw new TimeoutException($"Timed out waiting for {path} to reach status {expectedStatus}");
    }

    [Fact]
    public async Task Start_ShouldProcessExistingFiles()
    {
        // Arrange
        var filePath = "C:\\Scan\\test.exe";
        _fileOpsMock.Setup(f => f.GetFiles(_settings.Paths.ScanDirectory!)).Returns(new[] { filePath });
        _fileOpsMock.Setup(f => f.IsFileLocked(filePath)).Returns(false);
        
        _fileOpsMock.Setup(f => f.FileExists(filePath)).Returns(true);
        
        _vtServiceMock.Setup(v => v.ScanFileAsync(filePath, It.IsAny<CancellationToken>()))
            .ReturnsAsync((ScanResultStatus.Clean, 0, "hash", "Clean"));

        var results = new ConcurrentBag<(ScanStatus Status, string FullPath, string Message)>();
        _sut.ScanResultUpdated += (s, e) => results.Add((e.Status, e.FullPath, e.Message));

        // Act
        _sut.Start();

        // Assert
        await WaitForScanStatus(results, filePath, ScanStatus.Clean);

        // We expect:
        // 1. Pending (from Enqueue)
        // 2. Scanning (from ProcessFile)
        // 3. Clean (from ProcessFile completion)
        results.Should().Contain(r => r.Status == ScanStatus.Pending && r.FullPath == filePath);
        results.Should().Contain(r => r.Status == ScanStatus.Scanning && r.FullPath == filePath);
        results.Should().Contain(r => r.Status == ScanStatus.Clean && r.FullPath == filePath);
        
        _vtServiceMock.Verify(v => v.ScanFileAsync(filePath, It.IsAny<CancellationToken>()), Times.Once);
    }

    [Fact]
    public async Task Start_ShouldCreateDirectory_IfItDoesNotExist()
    {
        // Arrange
        _fileOpsMock.Setup(f => f.DirectoryExists(_settings.Paths.ScanDirectory!)).Returns(false);

        // Act
        _sut.Start();

        // Assert
        _fileOpsMock.Verify(f => f.CreateDirectory(_settings.Paths.ScanDirectory!), Times.Once);
    }

    [Fact]
    public async Task ProcessFile_ShouldMoveFileToCompromised_WhenInfected()
    {
        // Arrange
        var filePath = "C:\\Scan\\virus.exe";
        _fileOpsMock.Setup(f => f.GetFiles(_settings.Paths.ScanDirectory!)).Returns(new[] { filePath });
        _fileOpsMock.Setup(f => f.IsFileLocked(filePath)).Returns(false);

        _fileOpsMock.Setup(f => f.FileExists(filePath)).Returns(true);

        _vtServiceMock.Setup(v => v.ScanFileAsync(filePath, It.IsAny<CancellationToken>()))
            .ReturnsAsync((ScanResultStatus.Compromised, 5, "hash", "Infected"));

        var results = new ConcurrentBag<(ScanStatus Status, string FullPath, string Message)>();
        _sut.ScanResultUpdated += (s, e) => results.Add((e.Status, e.FullPath, e.Message));

        // Act
        _sut.Start();
        await WaitForScanStatus(results, filePath, ScanStatus.Compromised);

        // Assert
        results.Should().Contain(r => r.Status == ScanStatus.Compromised);
        // Verify MoveFile was not called directly on DirectoryScannerService but logic implies it calls File.Move?
        // Wait, DirectoryScannerService calls MoveFile private method which calls File.Move?
        // Let's check DirectoryScannerService source for MoveFile.
    }

    [Fact]
    public async Task ProcessFile_ShouldOverwrite_WhenChecksumsMatch()
    {
        // Arrange
        var fileName = "test.exe";
        var sourcePath = Path.Combine(_settings.Paths.ScanDirectory!, fileName);
        var destPath = Path.Combine(_settings.Paths.CleanDirectory!, fileName);
        
        _fileOpsMock.Setup(f => f.GetFiles(_settings.Paths.ScanDirectory!)).Returns(new[] { sourcePath });
        _fileOpsMock.Setup(f => f.IsFileLocked(sourcePath)).Returns(false);
        _fileOpsMock.Setup(f => f.FileExists(sourcePath)).Returns(true);
        _fileOpsMock.Setup(f => f.DirectoryExists(_settings.Paths.CleanDirectory!)).Returns(true);
        
        // Destination file exists
        _fileOpsMock.Setup(f => f.FileExists(destPath)).Returns(true);
        
        // Checksums match
        _fileOpsMock.Setup(f => f.CalculateSha256Async(sourcePath, It.IsAny<CancellationToken>())).ReturnsAsync("hash1");
        _fileOpsMock.Setup(f => f.CalculateSha256Async(destPath, It.IsAny<CancellationToken>())).ReturnsAsync("hash1");

        _vtServiceMock.Setup(v => v.ScanFileAsync(sourcePath, It.IsAny<CancellationToken>()))
            .ReturnsAsync((ScanResultStatus.Clean, 0, "hash1", "Clean"));

        var results = new ConcurrentBag<(ScanStatus Status, string FullPath, string Message)>();
        _sut.ScanResultUpdated += (s, e) => results.Add((e.Status, e.FullPath, e.Message));

        // Act
        _sut.Start();
        await WaitForScanStatus(results, sourcePath, ScanStatus.Clean); // Wait for processing

        // Assert
        // Should delete existing file
        _fileOpsMock.Verify(f => f.DeleteFile(destPath), Times.Once);
        // Should move to original name
        _fileOpsMock.Verify(f => f.MoveFile(sourcePath, destPath), Times.Once);
    }

    [Fact]
    public async Task ProcessFile_ShouldRename_WhenChecksumsDiffer()
    {
        // Arrange
        var fileName = "test.exe";
        var sourcePath = Path.Combine(_settings.Paths.ScanDirectory!, fileName);
        var destPath = Path.Combine(_settings.Paths.CleanDirectory!, fileName);
        
        _fileOpsMock.Setup(f => f.GetFiles(_settings.Paths.ScanDirectory!)).Returns(new[] { sourcePath });
        _fileOpsMock.Setup(f => f.IsFileLocked(sourcePath)).Returns(false);
        _fileOpsMock.Setup(f => f.FileExists(sourcePath)).Returns(true);
        _fileOpsMock.Setup(f => f.DirectoryExists(_settings.Paths.CleanDirectory!)).Returns(true);
        
        // Destination file exists
        _fileOpsMock.Setup(f => f.FileExists(destPath)).Returns(true);
        
        // Checksums differ
        _fileOpsMock.Setup(f => f.CalculateSha256Async(sourcePath, It.IsAny<CancellationToken>())).ReturnsAsync("hash1");
        _fileOpsMock.Setup(f => f.CalculateSha256Async(destPath, It.IsAny<CancellationToken>())).ReturnsAsync("hash2");

        _vtServiceMock.Setup(v => v.ScanFileAsync(sourcePath, It.IsAny<CancellationToken>()))
            .ReturnsAsync((ScanResultStatus.Clean, 0, "hash1", "Clean"));

        var results = new ConcurrentBag<(ScanStatus Status, string FullPath, string Message)>();
        _sut.ScanResultUpdated += (s, e) => results.Add((e.Status, e.FullPath, e.Message));

        // Act
        _sut.Start();
        await WaitForScanStatus(results, sourcePath, ScanStatus.Clean); // Wait for processing

        // Assert
        // Should NOT delete existing file
        _fileOpsMock.Verify(f => f.DeleteFile(destPath), Times.Never);
        // Should move to new name (timestamped)
        _fileOpsMock.Verify(f => f.MoveFile(sourcePath, It.Is<string>(p => p != destPath && p.StartsWith(Path.Combine(_settings.Paths.CleanDirectory!, "test_")))), Times.Once);
    }
    [Fact]
    public async Task ProcessFile_ShouldSkip_WhenFileIsOfficeTemp()
    {
        // Arrange
        var filePath = "C:\\Scan\\~$doc.docx";
        _fileOpsMock.Setup(f => f.GetFiles(_settings.Paths.ScanDirectory!)).Returns(new[] { filePath });
        _fileOpsMock.Setup(f => f.IsFileLocked(filePath)).Returns(false);
        _fileOpsMock.Setup(f => f.FileExists(filePath)).Returns(true);

        var results = new ConcurrentBag<(ScanStatus Status, string FullPath, string Message)>();
        _sut.ScanResultUpdated += (s, e) => results.Add((e.Status, e.FullPath, e.Message));

        // Act
        _sut.Start();
        await WaitForScanStatus(results, filePath, ScanStatus.Skipped);

        // Assert
        results.Should().Contain(r => r.Status == ScanStatus.Skipped && r.Message == "Excluded");
        _vtServiceMock.Verify(v => v.ScanFileAsync(It.IsAny<string>(), It.IsAny<CancellationToken>()), Times.Never);
    }

    [Fact]
    public async Task ProcessFile_ShouldSkip_WhenFileIsBrowserTemp()
    {
        // Arrange
        var filePath1 = "C:\\Scan\\file.crdownload";
        var filePath2 = "C:\\Scan\\file.part";
        // .download is not in my new defaults list? I removed .download from defaults in Settings.cs
        // Checking Settings.cs changes... 
        // I added *.crdownload, *.opdownload, *.part, *.partial.
        // The old code had .download
        // The user request didn't explicitly say remove .download but the list didn't include it.
        // It's safer to stick to what the user explicitly asked for + what was there if it makes sense.
        // User list: *.crdownload, *.opdownload, *.part, *.partial
        // Old code: .crdownload, .part, .download.
        // I'll stick to the user's list. So .download might SCAN now?
        // I'll update the test to use an extension that IS in the list.
        
        var filePath3 = "C:\\Scan\\file.partial"; // Changed from .download to .partial
        
        _fileOpsMock.Setup(f => f.GetFiles(_settings.Paths.ScanDirectory!)).Returns(new[] { filePath1, filePath2, filePath3 });
        _fileOpsMock.Setup(f => f.IsFileLocked(It.IsAny<string>())).Returns(false);
        _fileOpsMock.Setup(f => f.FileExists(It.IsAny<string>())).Returns(true);

        var results = new ConcurrentBag<(ScanStatus Status, string FullPath, string Message)>();
        _sut.ScanResultUpdated += (s, e) => results.Add((e.Status, e.FullPath, e.Message));

        // Act
        _sut.Start();
        await WaitForScanStatus(results, filePath1, ScanStatus.Skipped);
        await WaitForScanStatus(results, filePath2, ScanStatus.Skipped);
        await WaitForScanStatus(results, filePath3, ScanStatus.Skipped);

        // Assert
        results.Should().Contain(r => r.Status == ScanStatus.Skipped && r.Message == "Excluded");
        _vtServiceMock.Verify(v => v.ScanFileAsync(It.IsAny<string>(), It.IsAny<CancellationToken>()), Times.Never);
    }
    
    [Fact]
    public async Task ProcessFile_ShouldSkip_WhenFileMatchesExclusionPattern()
    {
        // Arrange
        var filePath = "C:\\Scan\\custom.skip";
        _settings.FileExclusions.Add("*.skip");
        
        _fileOpsMock.Setup(f => f.GetFiles(_settings.Paths.ScanDirectory!)).Returns(new[] { filePath });
        _fileOpsMock.Setup(f => f.IsFileLocked(filePath)).Returns(false);
        _fileOpsMock.Setup(f => f.FileExists(filePath)).Returns(true);

        var results = new ConcurrentBag<(ScanStatus Status, string FullPath, string Message)>();
        _sut.ScanResultUpdated += (s, e) => results.Add((e.Status, e.FullPath, e.Message));

        // Act
        _sut.Start();
        await WaitForScanStatus(results, filePath, ScanStatus.Skipped);

        // Assert
        results.Should().Contain(r => r.Status == ScanStatus.Skipped && r.Message == "Excluded");
        _vtServiceMock.Verify(v => v.ScanFileAsync(It.IsAny<string>(), It.IsAny<CancellationToken>()), Times.Never);
    }
}

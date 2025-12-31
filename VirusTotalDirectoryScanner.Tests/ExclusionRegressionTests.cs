using System.Collections.Concurrent;
using FluentAssertions;
using Moq;
using VirusTotalDirectoryScanner.Models;
using VirusTotalDirectoryScanner.Services;
using VirusTotalDirectoryScanner.Settings;
using Xunit;

namespace VirusTotalDirectoryScanner.Tests;

public class ExclusionRegressionTests
{
    private readonly Mock<IVirusTotalService> _vtServiceMock;
    private readonly Mock<ISettingsService> _settingsServiceMock;
    private readonly Mock<IFileOperationsService> _fileOpsMock;
    private readonly Mock<IDirectoryWatcherFactory> _watcherFactoryMock;
    private readonly Mock<IDirectoryWatcher> _watcherMock;
    private readonly Mock<IRateLimitService> _rateLimitServiceMock;
    private readonly DirectoryScannerService _sut;
    private readonly Settings.Settings _settings;

    public ExclusionRegressionTests()
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
            InitialDelayMs = 10,
            QueuePollingIntervalMs = 10,
            LockedFileCheckIntervalMs = 50
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
        // Don't throw here, let assertions handle it so we can see what statuses we DID get
    }

    [Fact]
    public async Task Scan_ShouldSkip_Exclusion_WithSpaces()
    {
        // Arrange
        // The user reported "Unconfirmed 885525.crdownload" being scanned.
        // We want to test that adding "*.crdownload" as an exclusion prevents this.
        
        var fileName = "Unconfirmed 885525.crdownload";
        var filePath = Path.Combine(_settings.Paths.ScanDirectory!, fileName);
        
        // Add the exclusion as the user would have it
        _settings.FileExclusions.Add("*.crdownload");
        
        _fileOpsMock.Setup(f => f.GetFiles(_settings.Paths.ScanDirectory!)).Returns(new[] { filePath });
        _fileOpsMock.Setup(f => f.IsFileLocked(filePath)).Returns(false);
        _fileOpsMock.Setup(f => f.FileExists(filePath)).Returns(true);
        
        // If it scans, it calls this:
        _vtServiceMock.Setup(v => v.ScanFileAsync(filePath, It.IsAny<CancellationToken>()))
            .ReturnsAsync((ScanResultStatus.Clean, 0, "hash", "Clean"));

        var results = new ConcurrentBag<(ScanStatus Status, string FullPath, string Message)>();
        _sut.ScanResultUpdated += (s, e) => results.Add((e.Status, e.FullPath, e.Message));

        // Act
        _sut.Start();
        
        // Wait enough time for processing
        await Task.Delay(300);

        // Assert
        // We expect it to be SKIPPED, not SCANNED or CLEAN
        results.Should().NotContain(r => r.Status == ScanStatus.Scanning, "should not start scanning excluded file");
        results.Should().Contain(r => r.Status == ScanStatus.Skipped && r.Message == "Excluded", "should skip excluded file");
        
        _vtServiceMock.Verify(v => v.ScanFileAsync(It.IsAny<string>(), It.IsAny<CancellationToken>()), Times.Never);
    }
}

using System.IO;
using System.Collections.ObjectModel;
using FluentAssertions;
using Moq;
using VirusTotalDirectoryScanner.Models;
using VirusTotalDirectoryScanner.Services;
using VirusTotalDirectoryScanner.Settings;
using VirusTotalDirectoryScanner.ViewModels;
using Xunit;

namespace VirusTotalDirectoryScanner.Tests;

public class MainWindowViewModelTests
{
    private readonly Mock<ISettingsService> _settingsServiceMock;
    private readonly Mock<IVirusTotalService> _vtServiceMock;
    private readonly Mock<IFileOperationsService> _fileOpsMock;
    private readonly Mock<IDirectoryWatcherFactory> _watcherFactoryMock;
    private readonly Mock<IDirectoryWatcher> _watcherMock;
    private readonly Mock<IRateLimitService> _rateLimitServiceMock;
    private readonly Mock<INotificationService> _notificationServiceMock;
    private readonly MainWindowViewModel _sut;
    private readonly Settings.Settings _settings;

    public MainWindowViewModelTests()
    {
        _settingsServiceMock = new Mock<ISettingsService>();
        _vtServiceMock = new Mock<IVirusTotalService>();
        _fileOpsMock = new Mock<IFileOperationsService>();
        _watcherFactoryMock = new Mock<IDirectoryWatcherFactory>();
        _watcherMock = new Mock<IDirectoryWatcher>();
        _rateLimitServiceMock = new Mock<IRateLimitService>();
        _notificationServiceMock = new Mock<INotificationService>();
        
        _settings = new Settings.Settings();
        _settings.Paths.ScanDirectory = "C:\\Scan"; // Set ScanDirectory
        _settingsServiceMock.Setup(s => s.CurrentSettings).Returns(_settings);
        _watcherFactoryMock.Setup(w => w.Create(It.IsAny<string>())).Returns(_watcherMock.Object);

        // Let's use the real DirectoryScannerService with mocked dependencies.
        var scannerService = new DirectoryScannerService(
            _vtServiceMock.Object,
            _settingsServiceMock.Object,
            _fileOpsMock.Object,
            _watcherFactoryMock.Object,
            _rateLimitServiceMock.Object,
            _notificationServiceMock.Object);

        _sut = new MainWindowViewModel(
            () => scannerService,
            _settingsServiceMock.Object,
            _fileOpsMock.Object);
    }

    [Fact]
    public void Loaded_ShouldStartScanning_WhenApiKeyIsPresent()
    {
        // Arrange
        _settingsServiceMock.Setup(s => s.ApiKey).Returns("valid_key");
        _fileOpsMock.Setup(f => f.DirectoryExists(It.IsAny<string>())).Returns(true);

        // Act
        _sut.LoadedCommand.Execute(null);

        // Assert
        _sut.StatusText.Should().Contain("Scanning");
    }

    [Fact]
    public void Loaded_ShouldRequestSettings_WhenApiKeyIsMissing()
    {
        // Arrange
        _settingsServiceMock.Setup(s => s.ApiKey).Returns("");
        bool settingsRequested = false;
        _sut.OpenSettingsRequested += (s, e) => settingsRequested = true;

        // Act
        _sut.LoadedCommand.Execute(null);

        // Assert
        settingsRequested.Should().BeTrue();
    }

    [Fact]
    public void DeleteCompromisedFile_ShouldDeleteFileAndRemoveFromResults()
    {
        // Arrange
        var result = new ScanResult { FullPath = "C:\\test.exe", Status = ScanStatus.Compromised };
        _sut.ScanResults.Add(result);

        // Act
        _sut.DeleteCompromisedFileCommand.Execute(result);

        // Assert
        _fileOpsMock.Verify(f => f.DeleteFile("C:\\test.exe"), Times.Once);
        _sut.ScanResults.Should().NotContain(result);
    }

    [Fact]
    public void DeleteCompromisedFile_ShouldShowError_WhenDeleteFails()
    {
        // Arrange
        var result = new ScanResult { FullPath = "C:\\test.exe", Status = ScanStatus.Compromised };
        _sut.ScanResults.Add(result);
        _fileOpsMock.Setup(f => f.DeleteFile(It.IsAny<string>())).Throws(new IOException("Access denied"));

        // Act
        _sut.DeleteCompromisedFileCommand.Execute(result);

        // Assert
        _sut.ErrorMessage.Should().Contain("Failed to delete file");
        _sut.ScanResults.Should().Contain(result); // File should still be in list if delete failed
    }

    [Fact]
    public void TogglePause_ShouldToggleIsPausedAndStatusText()
    {
        // Arrange
        _settingsServiceMock.Setup(s => s.ApiKey).Returns("valid_key");
        _fileOpsMock.Setup(f => f.DirectoryExists(It.IsAny<string>())).Returns(true);
        _sut.LoadedCommand.Execute(null); // Starts scanning

        // Act & Assert (Toggle ON)
        _sut.TogglePauseCommand.Execute(null);
        _sut.IsPaused.Should().BeTrue();
        _sut.StatusText.Should().Be("Paused:");

        // Act & Assert (Toggle OFF)
        _sut.TogglePauseCommand.Execute(null);
        _sut.IsPaused.Should().BeFalse();
        _sut.StatusText.Should().Be("Scanning:");
    }
}


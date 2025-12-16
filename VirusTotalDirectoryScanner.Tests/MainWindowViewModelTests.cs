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
    private readonly MainWindowViewModel _sut;
    private readonly Settings.Settings _settings;

    public MainWindowViewModelTests()
    {
        _settingsServiceMock = new Mock<ISettingsService>();
        _vtServiceMock = new Mock<IVirusTotalService>();
        _fileOpsMock = new Mock<IFileOperationsService>();
        _watcherFactoryMock = new Mock<IDirectoryWatcherFactory>();
        _watcherMock = new Mock<IDirectoryWatcher>();
        
        _settings = new Settings.Settings();
        _settings.Paths.ScanDirectory = "C:\\Scan"; // Set ScanDirectory
        _settingsServiceMock.Setup(s => s.CurrentSettings).Returns(_settings);
        _watcherFactoryMock.Setup(w => w.Create(It.IsAny<string>())).Returns(_watcherMock.Object);

        // Let's use the real DirectoryScannerService with mocked dependencies.
        var scannerService = new DirectoryScannerService(
            _vtServiceMock.Object,
            _settingsServiceMock.Object,
            _fileOpsMock.Object,
            _watcherFactoryMock.Object);

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
        _sut.StatusText.Should().Contain("Monitoring");
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
}

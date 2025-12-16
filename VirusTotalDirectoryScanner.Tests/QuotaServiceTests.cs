using FluentAssertions;
using Moq;
using VirusTotalDirectoryScanner.Services;
using VirusTotalDirectoryScanner.Settings;
using Xunit;

namespace VirusTotalDirectoryScanner.Tests;

public class QuotaServiceTests : IDisposable
{
    private readonly Mock<ISettingsService> _settingsServiceMock;
    private readonly QuotaService _sut;
    private readonly string _tempSettingsPath;

    public QuotaServiceTests()
    {
        _settingsServiceMock = new Mock<ISettingsService>();
        _tempSettingsPath = Path.GetTempFileName();
        _settingsServiceMock.Setup(s => s.UserSettingsFilePath).Returns(_tempSettingsPath);
        
        _sut = new QuotaService(_settingsServiceMock.Object);
    }

    public void Dispose()
    {
        if (File.Exists(_tempSettingsPath))
        {
            try { File.Delete(_tempSettingsPath); } catch { }
        }
    }

    [Fact]
    public void CheckQuota_ShouldThrowException_WhenDailyQuotaExceeded()
    {
        // Arrange
        var settings = new Settings.Settings();
        settings.Quota.PerDay = 10;
        settings.Quota.UsedToday = 10;
        settings.Quota.LastUsedDate = DateTime.Today;

        _settingsServiceMock.Setup(s => s.CurrentSettings).Returns(settings);

        // Act
        Action act = () => _sut.CheckQuota();

        // Assert
        act.Should().Throw<Exception>().WithMessage("*Daily quota exceeded*");
    }

    [Fact]
    public void CheckQuota_ShouldThrowException_WhenMonthlyQuotaExceeded()
    {
        // Arrange
        var settings = new Settings.Settings();
        settings.Quota.PerMonth = 100;
        settings.Quota.UsedThisMonth = 100;
        settings.Quota.LastUsedDate = DateTime.Today;

        _settingsServiceMock.Setup(s => s.CurrentSettings).Returns(settings);

        // Act
        Action act = () => _sut.CheckQuota();

        // Assert
        act.Should().Throw<Exception>().WithMessage("*Monthly quota exceeded*");
    }

    [Fact]
    public void CheckQuota_ShouldResetDailyCounters_WhenDateChanged()
    {
        // Arrange
        var settings = new Settings.Settings();
        settings.Quota.PerDay = 10;
        settings.Quota.UsedToday = 5;
        settings.Quota.LastUsedDate = DateTime.Today.AddDays(-1);

        _settingsServiceMock.Setup(s => s.CurrentSettings).Returns(settings);

        // Act
        _sut.CheckQuota();

        // Assert
        settings.Quota.UsedToday.Should().Be(0);
        settings.Quota.LastUsedDate.Date.Should().Be(DateTime.Today);
    }

    [Fact]
    public async Task IncrementQuotaAsync_ShouldIncrementCounters_AndSave()
    {
        // Arrange
        var settings = new Settings.Settings();
        settings.Quota.UsedToday = 0;
        settings.Quota.UsedThisMonth = 0;
        settings.Quota.LastUsedDate = DateTime.Today;

        _settingsServiceMock.Setup(s => s.CurrentSettings).Returns(settings);

        // Act
        await _sut.IncrementQuotaAsync();

        // Assert
        settings.Quota.UsedToday.Should().Be(1);
        settings.Quota.UsedThisMonth.Should().Be(1);
        
        // Verify file was written (integration aspect)
        File.Exists(_tempSettingsPath).Should().BeTrue();
        var content = await File.ReadAllTextAsync(_tempSettingsPath);
        content.Should().Contain("\"UsedToday\": 1");
    }
}

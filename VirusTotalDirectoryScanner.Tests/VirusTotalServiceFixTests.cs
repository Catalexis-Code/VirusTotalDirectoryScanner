using FluentAssertions;
using Moq;
using Refit;
using System.Net;
using System.Text.Json;
using VirusTotalDirectoryScanner.Models;
using VirusTotalDirectoryScanner.Services;
using VirusTotalDirectoryScanner.Settings;
using Xunit;

namespace VirusTotalDirectoryScanner.Tests;

public class VirusTotalServiceFixTests
{
    private readonly Mock<IVirusTotalApi> _vtApiMock;
    private readonly Mock<ISettingsService> _settingsServiceMock;
    private readonly Mock<IQuotaService> _quotaServiceMock;
    private readonly Mock<IHttpClientFactory> _httpClientFactoryMock;
    private readonly Mock<IFileOperationsService> _fileOpsMock;
    private readonly Settings.Settings _settings;
    private readonly VirusTotalService _sut;

    public VirusTotalServiceFixTests()
    {
        _vtApiMock = new Mock<IVirusTotalApi>();
        _settingsServiceMock = new Mock<ISettingsService>();
        _quotaServiceMock = new Mock<IQuotaService>();
        _httpClientFactoryMock = new Mock<IHttpClientFactory>();
        _fileOpsMock = new Mock<IFileOperationsService>();

        _settings = new Settings.Settings();
        _settingsServiceMock.Setup(s => s.CurrentSettings).Returns(_settings);

        _sut = new VirusTotalService(
            _settingsServiceMock.Object,
            _quotaServiceMock.Object,
            _vtApiMock.Object,
            _httpClientFactoryMock.Object,
            _fileOpsMock.Object);
    }

    [Fact]
    public async Task ScanFileAsync_ShouldRetryOn429_AndSucceed()
    {
        // Arrange
        var filePath = "C:\\Scan\\test.exe";
        var hash = "test_hash";
        
        _fileOpsMock.Setup(f => f.CalculateSha256Async(filePath, It.IsAny<CancellationToken>())).ReturnsAsync(hash);
        _fileOpsMock.Setup(f => f.GetFileLength(filePath)).Returns(100);

        int callCount = 0;
        _vtApiMock.Setup(a => a.GetFileReport(hash))
            .Returns(async () => 
            {
                callCount++;
                if (callCount <= 2)
                {
                    // Throw 429
                    var exception = await ApiException.Create(
                        null!, 
                        HttpMethod.Get, 
                        new HttpResponseMessage(HttpStatusCode.TooManyRequests), 
                        new RefitSettings());
                    throw exception;
                }
                
                return new VirusTotalResponse<FileObject> { 
                    Data = new FileObject { 
                        Attributes = new VirusTotalDirectoryScanner.Models.FileAttributes { 
                            LastAnalysisStats = new AnalysisStats { Malicious = 0 } 
                        } 
                    } 
                };
            });

        // Act
        var result = await _sut.ScanFileAsync(filePath);

        // Assert
        result.Status.Should().Be(ScanResultStatus.Clean);
        callCount.Should().Be(3); // 2 failures + 1 success
    }

    [Fact]
    public async Task ScanFileAsync_ShouldRespectMaxFileSizeConfig()
    {
        // Arrange
        var filePath = "C:\\Scan\\huge.iso";
        var hash = "huge_hash";
        long limit = 1024 * 1024; // 1MB
        
        // Ensure General is initialized
        if (_settings.General == null) _settings.General = new GeneralSettings();
        _settings.General.MaxFileSizeBytes = limit;
        
        _fileOpsMock.Setup(f => f.GetFileLength(filePath)).Returns(limit + 1); // 1 byte over
        _fileOpsMock.Setup(f => f.CalculateSha256Async(filePath, It.IsAny<CancellationToken>())).ReturnsAsync(hash);

        // Mock GetFileReport to throw NotFound so we fall through to Upload check (where size limit is checked)
        var notFoundEx = await ApiException.Create(null!, HttpMethod.Get, new HttpResponseMessage(HttpStatusCode.NotFound), new RefitSettings());
        _vtApiMock.Setup(a => a.GetFileReport(hash)).ThrowsAsync(notFoundEx);

        // Act
        var result = await _sut.ScanFileAsync(filePath);

        // Assert
        result.Status.Should().Be(ScanResultStatus.Failed);
        result.Message.Should().Contain("limit");
    }
}

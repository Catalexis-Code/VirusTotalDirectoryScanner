using FluentAssertions;
using Moq;
using Refit;
using System.Net;
using VirusTotalDirectoryScanner.Models;
using VirusTotalDirectoryScanner.Services;
using VirusTotalDirectoryScanner.Settings;
using Xunit;

namespace VirusTotalDirectoryScanner.Tests;

public class VirusTotalServiceTests
{
    private readonly Mock<ISettingsService> _settingsServiceMock;
    private readonly Mock<IQuotaService> _quotaServiceMock;
    private readonly Mock<IVirusTotalApi> _apiMock;
    private readonly VirusTotalService _service;

    public VirusTotalServiceTests()
    {
        _settingsServiceMock = new Mock<ISettingsService>();
        _quotaServiceMock = new Mock<IQuotaService>();
        _apiMock = new Mock<IVirusTotalApi>();

        _settingsServiceMock.Setup(s => s.ApiKey).Returns("dummy_key");
        _settingsServiceMock.Setup(s => s.CurrentSettings).Returns(new Settings.Settings());

        _service = new VirusTotalService(_settingsServiceMock.Object, _quotaServiceMock.Object, _apiMock.Object);
    }

    [Fact]
    public async Task ScanFileAsync_ShouldReturnClean_WhenFileIsClean()
    {
        // Arrange
        var tempFile = Path.GetTempFileName();
        try
        {
            File.WriteAllText(tempFile, "clean file content");
            
            var report = new VirusTotalResponse<FileObject>
            {
                Data = new FileObject
                {
                    Attributes = new VirusTotalDirectoryScanner.Models.FileAttributes
                    {
                        LastAnalysisStats = new AnalysisStats { Malicious = 0 }
                    }
                }
            };

            _apiMock.Setup(x => x.GetFileReport(It.IsAny<string>()))
                .ReturnsAsync(report);

            // Act
            var result = await _service.ScanFileAsync(tempFile);

            // Assert
            result.Status.Should().Be(ScanResultStatus.Clean);
        }
        finally
        {
            if (File.Exists(tempFile)) File.Delete(tempFile);
        }
    }

    [Fact]
    public async Task ScanFileAsync_ShouldUploadFile_WhenFileUnknown()
    {
        // Arrange
        var tempFile = Path.GetTempFileName();
        try
        {
            File.WriteAllText(tempFile, "unknown file content");

            // Mock GetFileReport to throw NotFound
            var apiException = await ApiException.Create(
                new HttpRequestMessage(), 
                HttpMethod.Get, 
                new HttpResponseMessage(HttpStatusCode.NotFound), 
                new RefitSettings());
            
            _apiMock.Setup(x => x.GetFileReport(It.IsAny<string>()))
                .ThrowsAsync(apiException);

            // Mock UploadFile
            var uploadResponse = new VirusTotalResponse<AnalysisDescriptor>
            {
                Data = new AnalysisDescriptor { Id = "analysis_id" }
            };
            _apiMock.Setup(x => x.UploadFile(It.IsAny<StreamPart>()))
                .ReturnsAsync(uploadResponse);

            // Mock GetAnalysis
            var analysisResponse = new VirusTotalResponse<AnalysisObject>
            {
                Data = new AnalysisObject
                {
                    Attributes = new AnalysisAttributes
                    {
                        Status = "completed",
                        Stats = new AnalysisStats { Malicious = 0 }
                    }
                }
            };
            _apiMock.Setup(x => x.GetAnalysis("analysis_id"))
                .ReturnsAsync(analysisResponse);

            // Act
            var result = await _service.ScanFileAsync(tempFile);

            // Assert
            result.Status.Should().Be(ScanResultStatus.Clean);
            _apiMock.Verify(x => x.UploadFile(It.IsAny<StreamPart>()), Times.Once);
        }
        finally
        {
            if (File.Exists(tempFile)) File.Delete(tempFile);
        }
    }
}

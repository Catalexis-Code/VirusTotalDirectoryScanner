using FluentAssertions;
using Moq;
using Moq.Protected;
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
    private readonly Mock<IHttpClientFactory> _httpClientFactoryMock;
    private readonly Mock<IFileOperationsService> _fileOperationsServiceMock;
    private readonly VirusTotalService _service;

    public VirusTotalServiceTests()
    {
        _settingsServiceMock = new Mock<ISettingsService>();
        _quotaServiceMock = new Mock<IQuotaService>();
        _apiMock = new Mock<IVirusTotalApi>();
        _httpClientFactoryMock = new Mock<IHttpClientFactory>();
        _fileOperationsServiceMock = new Mock<IFileOperationsService>();

        _settingsServiceMock.Setup(s => s.ApiKey).Returns("dummy_key");
        _settingsServiceMock.Setup(s => s.CurrentSettings).Returns(new Settings.Settings());

        // Default file operations behavior for existing tests
        _fileOperationsServiceMock.Setup(x => x.GetFileLength(It.IsAny<string>())).Returns(100); // Small file by default
        _fileOperationsServiceMock.Setup(x => x.OpenRead(It.IsAny<string>()))
            .Returns((string path) => File.OpenRead(path)); // Delegate to real file system for existing tests that create temp files

        _service = new VirusTotalService(
            _settingsServiceMock.Object, 
            _quotaServiceMock.Object, 
            _apiMock.Object,
            _httpClientFactoryMock.Object,
            _fileOperationsServiceMock.Object);
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

    [Fact]
    public async Task ScanFileAsync_ShouldUseLargeFileUpload_WhenFileIsLarge()
    {
        // Arrange
        var filePath = "large_file.exe";
        
        // Mock file size > 32MB
        _fileOperationsServiceMock.Setup(x => x.GetFileLength(filePath)).Returns(34000000);
        _fileOperationsServiceMock.Setup(x => x.OpenRead(filePath)).Returns(() => new MemoryStream(new byte[10])); // Dummy content

        // Mock GetFileReport to throw NotFound
        var apiException = await ApiException.Create(
            new HttpRequestMessage(), 
            HttpMethod.Get, 
            new HttpResponseMessage(HttpStatusCode.NotFound), 
            new RefitSettings());
        
        _apiMock.Setup(x => x.GetFileReport(It.IsAny<string>()))
            .ThrowsAsync(apiException);

        // Mock GetLargeFileUploadUrl
        var uploadUrl = "https://www.virustotal.com/api/v3/files/upload_url";
        _apiMock.Setup(x => x.GetLargeFileUploadUrl())
            .ReturnsAsync(new VirusTotalResponse<string> { Data = uploadUrl });

        // Mock HttpClient for upload
        var handlerMock = new Mock<HttpMessageHandler>();
        handlerMock.Protected()
            .Setup<Task<HttpResponseMessage>>(
                "SendAsync",
                ItExpr.Is<HttpRequestMessage>(req => req.Method == HttpMethod.Post && req.RequestUri.ToString() == uploadUrl),
                ItExpr.IsAny<CancellationToken>()
            )
            .ReturnsAsync(new HttpResponseMessage
            {
                StatusCode = HttpStatusCode.OK,
                Content = new StringContent("{\"data\": {\"id\": \"analysis_id\", \"type\": \"analysis\"}}")
            });

        var httpClient = new HttpClient(handlerMock.Object);
        _httpClientFactoryMock.Setup(x => x.CreateClient("VirusTotalUpload")).Returns(httpClient);

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
        var result = await _service.ScanFileAsync(filePath);

        // Assert
        result.Status.Should().Be(ScanResultStatus.Clean);
        _apiMock.Verify(x => x.GetLargeFileUploadUrl(), Times.Once);
        _httpClientFactoryMock.Verify(x => x.CreateClient("VirusTotalUpload"), Times.Once);
    }
}

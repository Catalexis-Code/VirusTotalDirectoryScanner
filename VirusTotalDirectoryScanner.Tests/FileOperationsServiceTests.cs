using System.IO;
using System.Threading.Tasks;
using FluentAssertions;
using VirusTotalDirectoryScanner.Services;
using Xunit;

namespace VirusTotalDirectoryScanner.Tests;

public class FileOperationsServiceTests
{
    [Fact]
    public async Task CalculateSha256Async_ShouldReturnCorrectHash()
    {
        // Arrange
        var service = new FileOperationsService();
        var tempFile = Path.GetTempFileName();
        var content = "Hello World";
        await File.WriteAllTextAsync(tempFile, content);
        
        // echo -n "Hello World" | sha256sum
        // a591a6d40bf420404a011733cfb7b190d62c65bf0bcda32b57b277d9ad9f146e
        var expectedHash = "a591a6d40bf420404a011733cfb7b190d62c65bf0bcda32b57b277d9ad9f146e";

        try
        {
            // Act
            var hash = await service.CalculateSha256Async(tempFile);

            // Assert
            hash.Should().Be(expectedHash);
        }
        finally
        {
            if (File.Exists(tempFile)) File.Delete(tempFile);
        }
    }
}

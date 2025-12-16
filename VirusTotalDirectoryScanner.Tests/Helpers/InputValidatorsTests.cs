using FluentAssertions;
using VirusTotalDirectoryScanner.Helpers;
using Xunit;

namespace VirusTotalDirectoryScanner.Tests.Helpers;

public class InputValidatorsTests
{
    [Theory]
    [InlineData("123", true)]
    [InlineData("0", true)]
    [InlineData("1", true)]
    [InlineData("abc", false)]
    [InlineData("12a", false)]
    [InlineData("a12", false)]
    [InlineData("", false)]
    [InlineData(null, false)]
    [InlineData(" ", false)]
    [InlineData("-1", false)]
    [InlineData("1.5", false)]
    public void IsNumeric_ShouldReturnExpectedResult(string? input, bool expected)
    {
        // Act
        var result = InputValidators.IsNumeric(input);

        // Assert
        result.Should().Be(expected);
    }
}

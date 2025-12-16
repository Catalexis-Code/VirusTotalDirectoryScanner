using System.Text.RegularExpressions;

namespace VirusTotalDirectoryScanner.Helpers;

public static class InputValidators
{
    public static bool IsNumeric(string? text)
    {
        if (string.IsNullOrEmpty(text))
        {
            return false;
        }
        return Regex.IsMatch(text, "^[0-9]+$");
    }
}

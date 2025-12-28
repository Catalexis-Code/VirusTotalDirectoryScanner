using System;
using System.Globalization;
using Avalonia.Data.Converters;

namespace VirusTotalDirectoryScanner.Helpers;

public class SelectedIndexToVisibleConverter : IValueConverter
{
    public object? Convert(object? value, Type targetType, object? parameter, CultureInfo culture)
    {
        if (value is int selectedIndex && parameter is string targetIndexStr && int.TryParse(targetIndexStr, out int targetIndex))
        {
            return selectedIndex == targetIndex;
        }
        return false;
    }

    public object? ConvertBack(object? value, Type targetType, object? parameter, CultureInfo culture)
    {
        throw new NotImplementedException();
    }
}

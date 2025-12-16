using Avalonia.Controls;
using Avalonia.Interactivity;
using Avalonia.Markup.Xaml;
using VirusTotalDirectoryScanner.Settings;

namespace VirusTotalDirectoryScanner;

public sealed partial class SettingsWindow : Window
{
	public SettingsWindow()
	{
		InitializeComponent();
	}

	private void InitializeComponent()
		=> AvaloniaXamlLoader.Load(this);

	private void Cancel_Click(object? sender, RoutedEventArgs e)
		=> Close(false);

	private void ToggleApiKey_Click(object? sender, RoutedEventArgs e)
	{
		if (DataContext is SettingsDialogViewModel vm)
		{
			vm.ToggleApiKeyVisibility();
		}
	}

	private async void Save_Click(object? sender, RoutedEventArgs e)
	{
		if (DataContext is not SettingsDialogViewModel vm)
		{
			Close(false);
			return;
		}

		bool saved = await vm.SaveAsync();
		if (saved)
		{
			Close(true);
		}
	}
}

using System;
using System.Threading.Tasks;
using Avalonia.Controls;
using Avalonia.Interactivity;
using Avalonia.Markup.Xaml;
using AppSettings = VirusTotalDirectoryScanner.Settings.Settings;
using VirusTotalDirectoryScanner.Settings;

namespace VirusTotalDirectoryScanner;

public sealed partial class MainWindow : Window
{
	private TextBlock? _statusText;

	public MainWindow()
	{
		InitializeComponent();
		_statusText = this.FindControl<TextBlock>("StatusText");
		LoadConfigurationSummary();
		Opened += MainWindow_Opened;
	}

	private void InitializeComponent()
		=> AvaloniaXamlLoader.Load(this);

	private void LoadConfigurationSummary()
	{
		try
		{
			SetStatus("Loading configuration…");

			var config = AppConfiguration.BuildConfiguration();
			string? apiKey = AppConfiguration.GetVirusTotalApiKey(config);
			AppSettings settings = AppConfiguration.GetAppSettings(config);

			bool apiKeyFound = !string.IsNullOrWhiteSpace(apiKey);
			bool scanPathConfigured = !string.IsNullOrWhiteSpace(settings.Paths.ScanDirectory);

			SetStatus($"API key: {(apiKeyFound ? "found" : "missing")}; Scan path: {(scanPathConfigured ? "configured" : "missing")}");
		}
		catch (Exception ex)
		{
			SetStatus($"Failed to load configuration: {ex.Message}");
		}
	}

	private async void MainWindow_Opened(object? sender, EventArgs e)
	{
		var config = AppConfiguration.BuildConfiguration();
		string? apiKey = AppConfiguration.GetVirusTotalApiKey(config);

		if (string.IsNullOrWhiteSpace(apiKey) || apiKey == "REPLACE_WITH_REAL_KEY")
		{
			await OpenSettingsDialog();
		}
	}

	private async void OpenSettings_Click(object? sender, RoutedEventArgs e)
	{
		await OpenSettingsDialog();
	}

	private async Task OpenSettingsDialog()
	{
		try
		{
			var config = AppConfiguration.BuildConfiguration();
			var settings = AppConfiguration.GetAppSettings(config);
			string apiKey = AppConfiguration.GetVirusTotalApiKey(config) ?? string.Empty;

			var vm = SettingsDialogViewModel.From(settings, apiKey, AppConfiguration.UserSettingsFilePath);
			var dialog = new SettingsWindow
			{
				DataContext = vm
			};

			bool? saved = await dialog.ShowDialog<bool?>(this);
			if (saved is true)
			{
				LoadConfigurationSummary();
			}
		}
		catch (Exception ex)
		{
			SetStatus($"Failed to open settings: {ex.Message}");
		}
	}

	private void SetStatus(string text)
	{
		if (_statusText is not null)
		{
			_statusText.Text = text;
		}
	}
}

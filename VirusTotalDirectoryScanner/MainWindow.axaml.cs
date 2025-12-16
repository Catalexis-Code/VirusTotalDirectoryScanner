using System;
using System.Threading.Tasks;
using System.Collections.ObjectModel;
using System.Linq;
using Avalonia.Controls;
using Avalonia.Interactivity;
using Avalonia.Markup.Xaml;
using AppSettings = VirusTotalDirectoryScanner.Settings.Settings;
using VirusTotalDirectoryScanner.Settings;
using VirusTotalDirectoryScanner.Models;

namespace VirusTotalDirectoryScanner;

public sealed partial class MainWindow : Window
{
	private TextBlock? _statusText;
	private DataGrid? _filesGrid;
	private ObservableCollection<ScanResult> _scanResults = new();

	public MainWindow()
	{
		InitializeComponent();
		_statusText = this.FindControl<TextBlock>("StatusText");
		_filesGrid = this.FindControl<DataGrid>("FilesGrid");
		if (_filesGrid != null)
		{
			_filesGrid.ItemsSource = _scanResults;
		}
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

	public void AddFile(string filePath, ScanStatus status)
	{
		var fileName = System.IO.Path.GetFileName(filePath);
		var result = new ScanResult
		{
			FileName = fileName,
			FullPath = filePath,
			Status = status
		};
		// Insert at top
		_scanResults.Insert(0, result);
	}

	public void UpdateFileStatus(string filePath, ScanStatus newStatus)
	{
		var item = _scanResults.FirstOrDefault(r => r.FullPath == filePath);
		if (item != null)
		{
			item.Status = newStatus;
		}
	}
}

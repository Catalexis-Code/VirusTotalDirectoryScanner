using System;
using System.Diagnostics;
using System.Threading.Tasks;
using System.Collections.ObjectModel;
using System.Linq;
using Avalonia.Controls;
using Avalonia.Interactivity;
using Avalonia.Markup.Xaml;
using Avalonia.Threading;
using AppSettings = VirusTotalDirectoryScanner.Settings.Settings;
using VirusTotalDirectoryScanner.Settings;
using VirusTotalDirectoryScanner.Models;
using VirusTotalDirectoryScanner.Services;

namespace VirusTotalDirectoryScanner;

public sealed partial class MainWindow : Window
{
	private TextBlock? _statusText;
	private DataGrid? _filesGrid;
	private ObservableCollection<ScanResult> _scanResults = new();
	private DirectoryScannerService? _scannerService;

	public MainWindow()
	{
		InitializeComponent();
		_statusText = this.FindControl<TextBlock>("StatusText");
		_filesGrid = this.FindControl<DataGrid>("FilesGrid");
		if (_filesGrid != null)
		{
			_filesGrid.ItemsSource = _scanResults;
		}
		
		// Defer loading until opened so we can show dialog if needed
		Opened += MainWindow_Opened;
	}

	private void InitializeComponent()
		=> AvaloniaXamlLoader.Load(this);

	private void StartScanning()
	{
		_scannerService?.Dispose();
		_scannerService = null;

		try
		{
			var config = AppConfiguration.BuildConfiguration();
			string? apiKey = AppConfiguration.GetVirusTotalApiKey(config);
			AppSettings settings = AppConfiguration.GetAppSettings(config);

			if (string.IsNullOrWhiteSpace(apiKey) || string.IsNullOrWhiteSpace(settings.Paths.ScanDirectory))
			{
				SetStatus("Configuration missing. Please check settings.");
				return;
			}

			var vtService = new VirusTotalService(apiKey, settings, AppConfiguration.UserSettingsFilePath);
			
			_scannerService = new DirectoryScannerService(
				vtService, 
				settings, 
				OnScanResultUpdated,
				OnLogMessage);
			
			_scannerService.Start();
			SetStatus("Monitoring active.");
		}
		catch (Exception ex)
		{
			SetStatus($"Error starting scanner: {ex.Message}");
		}
	}

	private void OnScanResultUpdated(ScanResult result)
	{
		Dispatcher.UIThread.InvokeAsync(() =>
		{
			var existing = _scanResults.FirstOrDefault(r => r.FullPath == result.FullPath);
			if (existing != null)
			{
				existing.Status = result.Status;
                existing.DetectionCount = result.DetectionCount;
                existing.FileHash = result.FileHash;
                existing.Message = result.Message;
			}
			else
			{
				_scanResults.Insert(0, result);
			}
		});
	}

	private void OnLogMessage(string message)
	{
		Dispatcher.UIThread.InvokeAsync(() =>
		{
			// Optionally show last log in status or a separate log view
			// For now just update status if it's significant? 
			// Actually, let's keep status for general state and maybe show errors there.
			if (message.StartsWith("Error") || message.Contains("exceeded"))
			{
				SetStatus(message);
			}
		});
	}

	private async void MainWindow_Opened(object? sender, EventArgs e)
	{
		var config = AppConfiguration.BuildConfiguration();
		string? apiKey = AppConfiguration.GetVirusTotalApiKey(config);

		if (string.IsNullOrWhiteSpace(apiKey) || apiKey == "REPLACE_WITH_REAL_KEY")
		{
			await OpenSettingsDialog();
		}
		
		StartScanning();
	}

	private async void OpenSettings_Click(object? sender, RoutedEventArgs e)
	{
		await OpenSettingsDialog();
	}

	private void Clear_Click(object? sender, RoutedEventArgs e)
	{
		_scanResults.Clear();
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
				StartScanning(); // Restart with new settings
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
	
	protected override void OnClosed(EventArgs e)
	{
		_scannerService?.Dispose();
		base.OnClosed(e);
	}

    private void OpenReport_Click(object sender, RoutedEventArgs e)
    {
        if (sender is Control control && control.DataContext is ScanResult result)
        {
            if (!string.IsNullOrEmpty(result.Url))
            {
                OpenUrl(result.Url);
            }
            else
            {
                SetStatus("Report URL not available (missing hash).");
            }
        }
    }

    private void OpenUrl(string url)
    {
        try
        {
            Process.Start(new ProcessStartInfo
            {
                FileName = url,
                UseShellExecute = true
            });
        }
        catch (Exception ex)
        {
            SetStatus($"Failed to open link: {ex.Message}");
        }
    }
}

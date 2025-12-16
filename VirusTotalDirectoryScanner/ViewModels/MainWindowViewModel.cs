using System.Collections.ObjectModel;
using System.Diagnostics;
using System.IO;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using VirusTotalDirectoryScanner.Models;
using VirusTotalDirectoryScanner.Services;
using Avalonia.Threading;

namespace VirusTotalDirectoryScanner.ViewModels;

public partial class MainWindowViewModel : ObservableObject
{
    private readonly Func<DirectoryScannerService> _scannerFactory;
    private readonly ISettingsService _settingsService;
    private readonly IFileOperationsService _fileOperationsService;
    private DirectoryScannerService? _scannerService;

    [ObservableProperty]
    private string _statusText = "Ready";

    [ObservableProperty]
    private bool _isMonitoring;

    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(HasError))]
    private string _errorMessage = string.Empty;

    public bool HasError => !string.IsNullOrEmpty(ErrorMessage);

    [ObservableProperty]
    private string _scanDirectoryName = "None";

    [ObservableProperty]
    private string _scanDirectoryPath = "";

    [ObservableProperty]
    private ObservableCollection<ScanResult> _scanResults = new();

    public event EventHandler? OpenSettingsRequested;
    public event EventHandler? RequestDirectorySelect;

    public MainWindowViewModel(
        Func<DirectoryScannerService> scannerFactory,
        ISettingsService settingsService,
        IFileOperationsService fileOperationsService)
    {
        _scannerFactory = scannerFactory;
        _settingsService = settingsService;
        _fileOperationsService = fileOperationsService;
    }

    [RelayCommand]
    private async Task Loaded()
    {
        if (string.IsNullOrWhiteSpace(_settingsService.ApiKey) || _settingsService.ApiKey == "REPLACE_WITH_REAL_KEY")
        {
            await OpenSettings();
        }
        
        StartScanning();
    }

    [RelayCommand]
    private async Task OpenSettings()
    {
        OpenSettingsRequested?.Invoke(this, EventArgs.Empty);
        await Task.CompletedTask;
    }

    [RelayCommand]
    private void BrowseDirectory()
    {
        RequestDirectorySelect?.Invoke(this, EventArgs.Empty);
    }

    [RelayCommand]
    private void OpenDirectory()
    {
        if (!string.IsNullOrWhiteSpace(ScanDirectoryPath))
        {
            _fileOperationsService.OpenDirectoryInExplorer(ScanDirectoryPath);
        }
    }

    public void OnSettingsSaved()
    {
        StartScanning();
    }

    [RelayCommand]
    private void StartScanning()
    {
        StopScanning();
        ErrorMessage = string.Empty;

        try
        {
            // Reload settings in case they changed
            _settingsService.Load();
            var settings = _settingsService.CurrentSettings;

            if (string.IsNullOrWhiteSpace(_settingsService.ApiKey) || string.IsNullOrWhiteSpace(settings.Paths.ScanDirectory))
            {
                StatusText = "Configuration missing";
                ErrorMessage = "Configuration missing. Please check settings.";
                IsMonitoring = false;
                return;
            }

            ScanDirectoryPath = settings.Paths.ScanDirectory;
            try
            {
                ScanDirectoryName = new DirectoryInfo(ScanDirectoryPath).Name;
            }
            catch
            {
                ScanDirectoryName = ScanDirectoryPath;
            }

            _scannerService = _scannerFactory();
            _scannerService.ScanResultUpdated += OnScanResultUpdated;
            _scannerService.LogMessage += OnLogMessage;
            
            _scannerService.Start();
            StatusText = "Monitoring:";
            IsMonitoring = true;
        }
        catch (Exception ex)
        {
            StatusText = "Stopped";
            ErrorMessage = $"Error starting scanner: {ex.Message}";
            IsMonitoring = false;
        }
    }

    private void StopScanning()
    {
        IsMonitoring = false;
        if (_scannerService != null)
        {
            _scannerService.ScanResultUpdated -= OnScanResultUpdated;
            _scannerService.LogMessage -= OnLogMessage;
            _scannerService.Dispose();
            _scannerService = null;
        }
    }

    private void OnScanResultUpdated(object? sender, ScanResult result)
    {
        Dispatcher.UIThread.InvokeAsync(() =>
        {
            var existing = ScanResults.FirstOrDefault(r => r.FullPath == result.FullPath);
            if (existing != null)
            {
                existing.Status = result.Status;
                existing.DetectionCount = result.DetectionCount;
                existing.FileHash = result.FileHash;
                existing.Message = result.Message;
            }
            else
            {
                ScanResults.Insert(0, result);
            }
        });
    }

    private void OnLogMessage(object? sender, string message)
    {
        Dispatcher.UIThread.InvokeAsync(() =>
        {
            if (message.StartsWith("Error") || message.Contains("exceeded"))
            {
                ErrorMessage = message;
            }
        });
    }

    [RelayCommand]
    private void Clear()
    {
        ScanResults.Clear();
        ErrorMessage = string.Empty;
    }

    [RelayCommand]
    private void OpenReport(ScanResult? result)
    {
        if (result != null)
        {
            if (!string.IsNullOrEmpty(result.Url))
            {
                OpenUrl(result.Url);
            }
            else
            {
                ErrorMessage = "Report URL not available (missing hash).";
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
            ErrorMessage = $"Failed to open link: {ex.Message}";
        }
    }
}

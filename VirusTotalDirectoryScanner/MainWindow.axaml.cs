using Avalonia.Controls;
using Avalonia.Markup.Xaml;
using VirusTotalDirectoryScanner.Settings;
using VirusTotalDirectoryScanner.ViewModels;
using VirusTotalDirectoryScanner.Services;
using Avalonia.Platform.Storage;

namespace VirusTotalDirectoryScanner;

public sealed partial class MainWindow : Window
{
    private readonly ISettingsService _settingsService;

    public MainWindow(ISettingsService settingsService)
    {
        _settingsService = settingsService;
        InitializeComponent();
        Opened += (s, e) => 
        {
            if (DataContext is MainWindowViewModel vm)
            {
                vm.LoadedCommand.Execute(null);
            }
        };
    }

    private void InitializeComponent()
        => AvaloniaXamlLoader.Load(this);

    protected override void OnDataContextChanged(EventArgs e)
    {
        base.OnDataContextChanged(e);
        if (DataContext is MainWindowViewModel vm)
        {
            vm.OpenSettingsRequested += Vm_OpenSettingsRequested;
            vm.RequestDirectorySelect += Vm_RequestDirectorySelect;
        }
    }

    private async void Vm_RequestDirectorySelect(object? sender, EventArgs e)
    {
        if (DataContext is MainWindowViewModel vm)
        {
            var folders = await StorageProvider.OpenFolderPickerAsync(new FolderPickerOpenOptions
            {
                Title = "Select Folder to Monitor",
                AllowMultiple = false
            });

            if (folders.Count > 0)
            {
                var path = folders[0].Path.LocalPath;
                
                var settings = _settingsService.CurrentSettings;
                settings.Paths.ScanDirectory = path;
                await _settingsService.SaveAsync(settings);
                
                vm.OnSettingsSaved();
            }
        }
    }

    private async void Vm_OpenSettingsRequested(object? sender, EventArgs e)
    {
        if (DataContext is MainWindowViewModel vm)
        {
            await OpenSettingsDialog(vm);
        }
    }

    private async Task OpenSettingsDialog(MainWindowViewModel vm)
    {
        try
        {
            var config = AppConfiguration.BuildConfiguration();
            var settings = AppConfiguration.GetAppSettings(config);
            string apiKey = AppConfiguration.GetVirusTotalApiKey(config) ?? string.Empty;

            var settingsVm = SettingsDialogViewModel.From(settings, apiKey, AppConfiguration.UserSettingsFilePath);
            var dialog = new SettingsWindow
            {
                DataContext = settingsVm
            };

            bool? saved = await dialog.ShowDialog<bool?>(this);
            if (saved is true)
            {
                vm.OnSettingsSaved();
            }
        }
        catch
        {
            // Ignore errors for now
        }
    }
}

using Avalonia.Controls;
using Avalonia.Markup.Xaml;
using VirusTotalDirectoryScanner.Settings;
using VirusTotalDirectoryScanner.ViewModels;

namespace VirusTotalDirectoryScanner;

public sealed partial class MainWindow : Window
{
    public MainWindow()
    {
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

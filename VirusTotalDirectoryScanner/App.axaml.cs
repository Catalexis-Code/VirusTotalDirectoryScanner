using Avalonia;
using Avalonia.Controls.ApplicationLifetimes;
using Avalonia.Markup.Xaml;
using Microsoft.Extensions.DependencyInjection;
using VirusTotalDirectoryScanner.Services;
using VirusTotalDirectoryScanner.ViewModels;

namespace VirusTotalDirectoryScanner;

public sealed partial class App : Application
{
    public IServiceProvider? Services { get; private set; }

    public override void Initialize()
    {
        AvaloniaXamlLoader.Load(this);
    }

    public override void OnFrameworkInitializationCompleted()
    {
        var collection = new ServiceCollection();
        ConfigureServices(collection);
        Services = collection.BuildServiceProvider();

        if (ApplicationLifetime is IClassicDesktopStyleApplicationLifetime desktop)
        {
            var mainWindow = Services.GetRequiredService<MainWindow>();
            mainWindow.DataContext = Services.GetRequiredService<MainWindowViewModel>();
            desktop.MainWindow = mainWindow;
        }

        base.OnFrameworkInitializationCompleted();
    }

    private void ConfigureServices(IServiceCollection services)
    {
        services.AddSingleton<SettingsService>();
        services.AddSingleton<VirusTotalService>();
        services.AddTransient<DirectoryScannerService>();
        services.AddSingleton<Func<DirectoryScannerService>>(sp => () => sp.GetRequiredService<DirectoryScannerService>());
        
        services.AddTransient<MainWindowViewModel>();
        services.AddTransient<MainWindow>();
    }
}

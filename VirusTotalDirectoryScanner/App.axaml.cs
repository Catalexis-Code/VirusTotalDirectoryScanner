using Avalonia;
using Avalonia.Controls.ApplicationLifetimes;
using Avalonia.Markup.Xaml;
using Microsoft.Extensions.DependencyInjection;
using VirusTotalDirectoryScanner.Services;
using VirusTotalDirectoryScanner.ViewModels;
using Refit;
using System.Threading.RateLimiting;
using System.Net.Http;
using System;

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
        services.AddSingleton<ISettingsService, SettingsService>();
        services.AddSingleton<IQuotaService, QuotaService>();
        services.AddSingleton<IFileOperationsService, FileOperationsService>();
        services.AddSingleton<IDirectoryWatcherFactory, DirectoryWatcherFactory>();
        
        services.AddSingleton<IVirusTotalApi>(sp =>
        {
            var settingsService = sp.GetRequiredService<ISettingsService>();
            var settings = settingsService.CurrentSettings;
            var apiKey = settingsService.ApiKey;

            if (string.IsNullOrWhiteSpace(apiKey))
            {
                throw new InvalidOperationException("VirusTotal API Key is missing.");
            }

            int permitLimit = settings.Quota.PerMinute > 0 ? settings.Quota.PerMinute : 4;
            
            var limiter = new FixedWindowRateLimiter(new FixedWindowRateLimiterOptions
            {
                PermitLimit = permitLimit,
                Window = TimeSpan.FromMinutes(1),
                QueueProcessingOrder = QueueProcessingOrder.OldestFirst,
                QueueLimit = 100,
                AutoReplenishment = true
            });

            var httpClient = new HttpClient(new ThrottlingHandler(limiter))
            {
                BaseAddress = new Uri("https://www.virustotal.com/api/v3")
            };
            httpClient.DefaultRequestHeaders.Add("x-apikey", apiKey);

            return RestService.For<IVirusTotalApi>(httpClient);
        });

        services.AddSingleton<IVirusTotalService, VirusTotalService>();
        services.AddTransient<DirectoryScannerService>();
        services.AddSingleton<Func<DirectoryScannerService>>(sp => () => sp.GetRequiredService<DirectoryScannerService>());
        
        services.AddTransient<MainWindowViewModel>();
        services.AddTransient<MainWindow>();
    }
}

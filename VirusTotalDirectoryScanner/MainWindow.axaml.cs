using Avalonia.Controls;
using Avalonia.Markup.Xaml;
using Microsoft.Extensions.Configuration;
using AppSettings = VirusTotalDirectoryScanner.Settings.Settings;

namespace VirusTotalDirectoryScanner;

public sealed partial class MainWindow : Window
{
	private TextBlock? _statusText;

	public MainWindow()
	{
		InitializeComponent();
		_statusText = this.FindControl<TextBlock>("StatusText");
		LoadConfigurationSummary();
	}

	private void InitializeComponent()
		=> AvaloniaXamlLoader.Load(this);

	private void LoadConfigurationSummary()
	{
		try
		{
			SetStatus("Loading configuration…");

			IConfiguration config = new ConfigurationBuilder()
				.SetBasePath(AppDomain.CurrentDomain.BaseDirectory)
				.AddJsonFile("appsettings.json", optional: true, reloadOnChange: true)
				.AddUserSecrets<App>(optional: true)
				.Build();

			string? apiKey = config["VirusTotalApiKey"];

			AppSettings settings = new();
			config.Bind(settings);

			bool apiKeyFound = !string.IsNullOrWhiteSpace(apiKey);
			bool scanPathConfigured = !string.IsNullOrWhiteSpace(settings.Paths.ScanDirectory);

			SetStatus($"API key: {(apiKeyFound ? "found" : "missing")}; Scan path: {(scanPathConfigured ? "configured" : "missing")}");
		}
		catch (Exception ex)
		{
			SetStatus($"Failed to load configuration: {ex.Message}");
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

using Microsoft.Extensions.Configuration;
using VirusTotalDirectoryScanner.Settings;

// Build configuration
IConfiguration config = new ConfigurationBuilder()
	 .SetBasePath(AppDomain.CurrentDomain.BaseDirectory)
	 .AddJsonFile("appsettings.json", optional: true, reloadOnChange: true)
	 .AddUserSecrets<Program>()
	 .Build();

// Read settings
string? apiKey = config["VirusTotalApiKey"];

VirusTotalDirectoryScannerSettings settings = new();
config.Bind(settings);

int quotaPerMinute = settings.QuotaPerMinute;
int quotaPerDay = settings.QuotaPerDay;
int quotaPerMonth = settings.QuotaPerMonth;

Console.WriteLine($"API Key found: {!string.IsNullOrEmpty(apiKey)}");
Console.WriteLine($"Quota: {quotaPerMinute}/min, {quotaPerDay}/day, {quotaPerMonth}/month");

Console.WriteLine($"Paths configured: {!string.IsNullOrWhiteSpace(settings.Paths.ScanDirectory)}");


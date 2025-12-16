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

Settings settings = new();
config.Bind(settings);

int quotaPerMinute = settings.Quota.PerMinute;
int quotaPerDay = settings.Quota.PerDay;
int quotaPerMonth = settings.Quota.PerMonth;

Console.WriteLine($"API Key found: {!string.IsNullOrEmpty(apiKey)}");
Console.WriteLine($"Quota: {quotaPerMinute}/min, {quotaPerDay}/day, {quotaPerMonth}/month");

Console.WriteLine($"Paths configured: {!string.IsNullOrWhiteSpace(settings.Paths.ScanDirectory)}");


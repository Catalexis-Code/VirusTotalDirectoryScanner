using Microsoft.Extensions.Configuration;

// Build configuration
IConfiguration config = new ConfigurationBuilder()
	 .SetBasePath(AppDomain.CurrentDomain.BaseDirectory)
	 .AddJsonFile("appsettings.json", optional: true, reloadOnChange: true)
	 .AddUserSecrets<Program>()
	 .Build();

// Read settings
string? apiKey = config["VirusTotalApiKey"];
int quotaPerMinute = config.GetValue<int>("QuotaPerMinute");
int quotaPerDay = config.GetValue<int>("QuotaPerDay");
int quotaPerMonth = config.GetValue<int>("QuotaPerMonth");

Console.WriteLine($"API Key found: {!string.IsNullOrEmpty(apiKey)}");
Console.WriteLine($"Quota: {quotaPerMinute}/min, {quotaPerDay}/day, {quotaPerMonth}/month");


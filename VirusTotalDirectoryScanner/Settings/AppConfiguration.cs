using System.Reflection;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Configuration.UserSecrets;

namespace VirusTotalDirectoryScanner.Settings;

internal static class AppConfiguration
{
	public const string VirusTotalApiKeyConfigKey = "VirusTotalApiKey";

	public static string UserSettingsFilePath
		=> Path.Combine(
			Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData),
			"VirusTotalDirectoryScanner",
			"settings.json");

	public static string? UserSecretsId
		=> Assembly.GetExecutingAssembly()
			.GetCustomAttribute<UserSecretsIdAttribute>()
			?.UserSecretsId;

	public static string? UserSecretsFilePath
	{
		get
		{
			string? userSecretsId = UserSecretsId;
			if (string.IsNullOrWhiteSpace(userSecretsId))
			{
				return null;
			}

			// Matches dotnet user-secrets storage locations.
			if (OperatingSystem.IsWindows())
			{
				string appData = Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData);
				return Path.Combine(appData, "Microsoft", "UserSecrets", userSecretsId, "secrets.json");
			}

			// Linux / macOS
			string home = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
			if (OperatingSystem.IsMacOS())
			{
				return Path.Combine(home, "Library", "Application Support", "Microsoft", "UserSecrets", userSecretsId, "secrets.json");
			}

			// Default for Linux/Unix
			return Path.Combine(home, ".microsoft", "usersecrets", userSecretsId, "secrets.json");
		}
	}

	public static IConfigurationRoot BuildConfiguration()
	{
		var builder = new ConfigurationBuilder()
			.SetBasePath(AppDomain.CurrentDomain.BaseDirectory)
			.AddJsonFile("appsettings.json", optional: true, reloadOnChange: false)
			.AddJsonFile(UserSettingsFilePath, optional: true, reloadOnChange: false)
			.AddUserSecrets<App>(optional: true);

		return builder.Build();
	}

	public static Settings GetAppSettings(IConfiguration config)
	{
		Settings settings = new();
		config.Bind(settings);
		return settings;
	}

	public static string? GetVirusTotalApiKey(IConfiguration config)
		=> config[VirusTotalApiKeyConfigKey];
}

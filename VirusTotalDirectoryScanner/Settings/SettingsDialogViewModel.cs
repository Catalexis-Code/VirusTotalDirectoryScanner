using System.ComponentModel;
using System.Runtime.CompilerServices;

namespace VirusTotalDirectoryScanner.Settings;

internal sealed class SettingsDialogViewModel : INotifyPropertyChanged
{
	private string _apiKey = string.Empty;
	private char _apiKeyPasswordChar = '*';
	private string? _scanDirectory;
	private string? _cleanDirectory;
	private string? _compromisedDirectory;
	private string? _logFilePath;
	private int _quotaPerMinute;
	private int _quotaPerDay;
	private int _quotaPerMonth;
	private string? _errorMessage;

	public event PropertyChangedEventHandler? PropertyChanged;

	public string ApiKey
	{
		get => _apiKey;
		set => SetProperty(ref _apiKey, value);
	}

	public char ApiKeyPasswordChar
	{
		get => _apiKeyPasswordChar;
		set => SetProperty(ref _apiKeyPasswordChar, value);
	}

	public void ToggleApiKeyVisibility()
	{
		ApiKeyPasswordChar = ApiKeyPasswordChar == '*' ? '\0' : '*';
	}

	public string? ScanDirectory
	{
		get => _scanDirectory;
		set => SetProperty(ref _scanDirectory, value);
	}

	public string? CleanDirectory
	{
		get => _cleanDirectory;
		set => SetProperty(ref _cleanDirectory, value);
	}

	public string? CompromisedDirectory
	{
		get => _compromisedDirectory;
		set => SetProperty(ref _compromisedDirectory, value);
	}

	public string? LogFilePath
	{
		get => _logFilePath;
		set => SetProperty(ref _logFilePath, value);
	}

	public int QuotaPerMinute
	{
		get => _quotaPerMinute;
		set => SetProperty(ref _quotaPerMinute, value);
	}

	public int QuotaPerDay
	{
		get => _quotaPerDay;
		set => SetProperty(ref _quotaPerDay, value);
	}

	public int QuotaPerMonth
	{
		get => _quotaPerMonth;
		set => SetProperty(ref _quotaPerMonth, value);
	}

	public string UserSettingsFilePath { get; }
	public string? UserSecretsFilePath { get; }

	public string? ErrorMessage
	{
		get => _errorMessage;
		private set => SetProperty(ref _errorMessage, value);
	}

	private SettingsDialogViewModel(string userSettingsFilePath, string? userSecretsFilePath)
	{
		UserSettingsFilePath = userSettingsFilePath;
		UserSecretsFilePath = userSecretsFilePath;
	}

	public static SettingsDialogViewModel From(Settings settings, string apiKey, string userSettingsFilePath)
	{
		return new SettingsDialogViewModel(userSettingsFilePath, AppConfiguration.UserSecretsFilePath)
		{
			ApiKey = apiKey,
			ScanDirectory = settings.Paths.ScanDirectory,
			CleanDirectory = settings.Paths.CleanDirectory,
			CompromisedDirectory = settings.Paths.CompromisedDirectory,
			LogFilePath = settings.Paths.LogFilePath,
			QuotaPerMinute = settings.Quota.PerMinute,
			QuotaPerDay = settings.Quota.PerDay,
			QuotaPerMonth = settings.Quota.PerMonth
		};
	}

	public Settings ToSettings()
	{
		return new Settings
		{
			Quota = new QuotaSettings
			{
				PerMinute = QuotaPerMinute,
				PerDay = QuotaPerDay,
				PerMonth = QuotaPerMonth
			},
			Paths = new PathsSettings
			{
				ScanDirectory = ScanDirectory,
				CleanDirectory = CleanDirectory,
				CompromisedDirectory = CompromisedDirectory,
				LogFilePath = LogFilePath
			}
		};
	}

	public async Task<bool> SaveAsync(CancellationToken cancellationToken = default)
	{
		try
		{
			ErrorMessage = null;

			Settings settings = ToSettings();
			await UserSettingsStore.SaveAsync(UserSettingsFilePath, settings, cancellationToken);

			if (!string.IsNullOrWhiteSpace(UserSecretsFilePath))
			{
				await UserSecretsStore.SaveSecretAsync(
					UserSecretsFilePath,
					AppConfiguration.VirusTotalApiKeyConfigKey,
					string.IsNullOrWhiteSpace(ApiKey) ? null : ApiKey,
					cancellationToken);
			}

			return true;
		}
		catch (Exception ex)
		{
			ErrorMessage = ex.Message;
			return false;
		}
	}

	private void SetProperty<T>(ref T field, T value, [CallerMemberName] string? propertyName = null)
	{
		if (EqualityComparer<T>.Default.Equals(field, value))
		{
			return;
		}

		field = value;
		PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(propertyName));
	}
}

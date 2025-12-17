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
	private int _usedToday;
	private int _usedThisMonth;
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
		set 
		{ 
			if (SetProperty(ref _scanDirectory, value))
			{
				if (!string.IsNullOrWhiteSpace(value))
				{
					if (string.IsNullOrWhiteSpace(CleanDirectory))
					{
						CleanDirectory = Path.Combine(value, "Clean");
					}
					if (string.IsNullOrWhiteSpace(CompromisedDirectory))
					{
						CompromisedDirectory = Path.Combine(value, "Compromised");
					}
					if (string.IsNullOrWhiteSpace(LogFilePath))
					{
						LogFilePath = Path.Combine(value, "virus-total-scanner-log.txt");
					}
				}
			}
		}
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

	public int UsedToday
	{
		get => _usedToday;
		set => SetProperty(ref _usedToday, value);
	}

	public int UsedThisMonth
	{
		get => _usedThisMonth;
		set => SetProperty(ref _usedThisMonth, value);
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
			QuotaPerMonth = settings.Quota.PerMonth,
			UsedToday = settings.Quota.UsedToday,
			UsedThisMonth = settings.Quota.UsedThisMonth
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
				PerMonth = QuotaPerMonth,
				UsedToday = UsedToday,
				UsedThisMonth = UsedThisMonth
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

	private bool SetProperty<T>(ref T field, T value, [CallerMemberName] string? propertyName = null)
	{
		if (EqualityComparer<T>.Default.Equals(field, value))
		{
			return false;
		}

		field = value;
		PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(propertyName));
		return true;
	}
}

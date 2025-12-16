namespace VirusTotalDirectoryScanner.Settings;

public sealed class Settings
{
	public QuotaSettings Quota { get; set; } = new();

	public PathsSettings Paths { get; set; } = new();
}

public sealed class QuotaSettings
{
	public int PerMinute { get; set; }
	public int PerDay { get; set; }
	public int PerMonth { get; set; }
}

public sealed class PathsSettings
{
	public string? ScanDirectory { get; set; }
	public string? CleanDirectory { get; set; }
	public string? CompromisedDirectory { get; set; }
	public string? LogFilePath { get; set; }
}

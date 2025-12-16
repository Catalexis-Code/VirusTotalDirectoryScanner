namespace VirusTotalDirectoryScanner.Settings;

public sealed class VirusTotalDirectoryScannerSettings
{
	public int QuotaPerMinute { get; set; }
	public int QuotaPerDay { get; set; }
	public int QuotaPerMonth { get; set; }

	public PathsSettings Paths { get; set; } = new();
}

public sealed class PathsSettings
{
	public string? ScanDirectory { get; set; }
	public string? CleanDirectory { get; set; }
	public string? CompromisedDirectory { get; set; }
	public string? LogFilePath { get; set; }
}

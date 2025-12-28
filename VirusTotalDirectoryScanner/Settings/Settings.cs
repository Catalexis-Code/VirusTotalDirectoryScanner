namespace VirusTotalDirectoryScanner.Settings;

public sealed class Settings
{
	public QuotaSettings Quota { get; set; } = new();
	public GeneralSettings General { get; set; } = new();

	public PathsSettings Paths { get; set; } = new();

	public List<string> FileExclusions { get; set; } = new()
	{
		// Chromium family (Edge, Chrome, Brave, Vivaldi)
		"*.crdownload",
		// Opera
		"*.opdownload",
		// Firefox
		"*.part",
		// Legacy Internet Explorer or EdgeHTML
		"*.partial",
		// Microsoft Office lock files
		// Word
		"~$*.doc", "~$*.docx", "~$*.dot", "~$*.dotx", "~$*.docm", "~$*.dotm",
		// Excel
		"~$*.xls", "~$*.xlsx", "~$*.xlsm", "~$*.xlt", "~$*.xltx", "~$*.xltm",
		// PowerPoint
		"~$*.ppt", "~$*.pptx", "~$*.pptm", "~$*.pot", "~$*.potx", "~$*.potm",
		// Visio
		"~$*.vsd", "~$*.vsdx",
		// Publisher
		"~$*.pub",
		// Project
		"~$*.mpp",
		// Access lock files
		"*.laccdb", "*.ldb"
	};
}

public sealed class QuotaSettings
{
	public int PerMinute { get; set; }
	public int PerDay { get; set; }
	public int PerMonth { get; set; }

	// Usage tracking
	public int UsedToday { get; set; }
	public int UsedThisMonth { get; set; }
	public DateTime LastUsedDate { get; set; }
}

public sealed class GeneralSettings
{
	public long MaxFileSizeBytes { get; set; } = 681574400; // Default ~650MB
	public int PollingTimeoutMinutes { get; set; } = 15;
}


public sealed class PathsSettings
{
	public string? ScanDirectory { get; set; }
	public string? CleanDirectory { get; set; }
	public string? CompromisedDirectory { get; set; }
	public string? LogFilePath { get; set; }
}

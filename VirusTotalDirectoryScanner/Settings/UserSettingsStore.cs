using System.Text.Json;

namespace VirusTotalDirectoryScanner.Settings;

internal static class UserSettingsStore
{
	private static readonly JsonSerializerOptions SerializerOptions = new()
	{
		WriteIndented = true
	};

	public static async Task SaveAsync(string filePath, Settings settings, CancellationToken cancellationToken = default)
	{
		string? directory = Path.GetDirectoryName(filePath);
		if (!string.IsNullOrWhiteSpace(directory))
		{
			Directory.CreateDirectory(directory);
		}

		await using FileStream stream = File.Create(filePath);
		await JsonSerializer.SerializeAsync(stream, settings, SerializerOptions, cancellationToken);
	}
}

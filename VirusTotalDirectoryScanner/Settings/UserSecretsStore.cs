using System.Text.Json;
using System.Text.Json.Nodes;

namespace VirusTotalDirectoryScanner.Settings;

internal static class UserSecretsStore
{
	public static async Task SaveSecretAsync(string filePath, string key, string? value, CancellationToken cancellationToken = default)
	{
		string? directory = Path.GetDirectoryName(filePath);
		if (!string.IsNullOrWhiteSpace(directory))
		{
			Directory.CreateDirectory(directory);
		}

		JsonObject root;
		if (File.Exists(filePath))
		{
			string existing = await File.ReadAllTextAsync(filePath, cancellationToken);
			root = JsonNode.Parse(existing) as JsonObject ?? new JsonObject();
		}
		else
		{
			root = new JsonObject();
		}

		if (string.IsNullOrWhiteSpace(value))
		{
			root.Remove(key);
		}
		else
		{
			root[key] = value;
		}

		var options = new JsonSerializerOptions { WriteIndented = true };
		string json = root.ToJsonString(options);
		await File.WriteAllTextAsync(filePath, json, cancellationToken);
	}
}

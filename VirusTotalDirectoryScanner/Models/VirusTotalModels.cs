using System.Text.Json.Serialization;

namespace VirusTotalDirectoryScanner.Models;

public class VirusTotalResponse<T>
{
    [JsonPropertyName("data")]
    public T? Data { get; set; }
    
    [JsonPropertyName("error")]
    public VirusTotalError? Error { get; set; }
}

public class VirusTotalError
{
    [JsonPropertyName("code")]
    public string? Code { get; set; }
    
    [JsonPropertyName("message")]
    public string? Message { get; set; }
}

public class FileObject
{
    [JsonPropertyName("id")]
    public string? Id { get; set; }
    
    [JsonPropertyName("type")]
    public string? Type { get; set; }
    
    [JsonPropertyName("attributes")]
    public FileAttributes? Attributes { get; set; }
}

public class FileAttributes
{
    [JsonPropertyName("last_analysis_stats")]
    public AnalysisStats? LastAnalysisStats { get; set; }
    
    [JsonPropertyName("last_analysis_results")]
    public Dictionary<string, AnalysisResultDetail>? LastAnalysisResults { get; set; }
}

public class AnalysisStats
{
    [JsonPropertyName("harmless")]
    public int Harmless { get; set; }
    
    [JsonPropertyName("type-unsupported")]
    public int TypeUnsupported { get; set; }
    
    [JsonPropertyName("suspicious")]
    public int Suspicious { get; set; }
    
    [JsonPropertyName("confirmed-timeout")]
    public int ConfirmedTimeout { get; set; }
    
    [JsonPropertyName("timeout")]
    public int Timeout { get; set; }
    
    [JsonPropertyName("failure")]
    public int Failure { get; set; }
    
    [JsonPropertyName("malicious")]
    public int Malicious { get; set; }
    
    [JsonPropertyName("undetected")]
    public int Undetected { get; set; }
}

public class AnalysisResultDetail
{
    [JsonPropertyName("category")]
    public string? Category { get; set; }
    
    [JsonPropertyName("result")]
    public string? Result { get; set; }
    
    [JsonPropertyName("method")]
    public string? Method { get; set; }
    
    [JsonPropertyName("engine_name")]
    public string? EngineName { get; set; }
}

public class AnalysisDescriptor
{
    [JsonPropertyName("id")]
    public string? Id { get; set; }
    
    [JsonPropertyName("type")]
    public string? Type { get; set; }
}

public class AnalysisObject
{
    [JsonPropertyName("id")]
    public string? Id { get; set; }
    
    [JsonPropertyName("type")]
    public string? Type { get; set; }
    
    [JsonPropertyName("attributes")]
    public AnalysisAttributes? Attributes { get; set; }
}

public class AnalysisAttributes
{
    [JsonPropertyName("status")]
    public string? Status { get; set; } // queued, in-progress, completed
    
    [JsonPropertyName("stats")]
    public AnalysisStats? Stats { get; set; }
}

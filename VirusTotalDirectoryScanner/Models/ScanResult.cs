using System;
using System.ComponentModel;
using System.Runtime.CompilerServices;

namespace VirusTotalDirectoryScanner.Models;

public enum ScanStatus
{
    Pending,
    PendingLocked,
    Scanning,
    Clean,
    Compromised,
    Failed
}

public class ScanResult : INotifyPropertyChanged
{
    private ScanStatus _status;
    private int _detectionCount;
    private string _fileHash = string.Empty;
    private string _message = string.Empty;

    public string FileName { get; set; } = string.Empty;
    public string FullPath { get; set; } = string.Empty;
    
    public string Message
    {
        get => _message;
        set
        {
            if (_message != value)
            {
                _message = value;
                OnPropertyChanged();
                OnPropertyChanged(nameof(StatusDisplay));
            }
        }
    }
    
    public ScanStatus Status 
    { 
        get => _status; 
        set 
        {
            if (_status != value)
            {
                _status = value;
                OnPropertyChanged();
                OnPropertyChanged(nameof(StatusDisplay));
                OnPropertyChanged(nameof(IsScanning));
                OnPropertyChanged(nameof(IsCompromised));
                OnPropertyChanged(nameof(IsClean));
                OnPropertyChanged(nameof(IsOther));
            }
        }
    }

    public int DetectionCount
    {
        get => _detectionCount;
        set
        {
            if (_detectionCount != value)
            {
                _detectionCount = value;
                OnPropertyChanged();
                OnPropertyChanged(nameof(StatusDisplay));
            }
        }
    }

    public string FileHash
    {
        get => _fileHash;
        set
        {
            if (_fileHash != value)
            {
                _fileHash = value;
                OnPropertyChanged();
                OnPropertyChanged(nameof(Url));
            }
        }
    }

    public string Url => !string.IsNullOrEmpty(FileHash) 
        ? $"https://www.virustotal.com/gui/file/{FileHash}" 
        : string.Empty;

    public bool IsScanning => Status == ScanStatus.Scanning;
    public bool IsCompromised => Status == ScanStatus.Compromised;
    public bool IsClean => Status == ScanStatus.Clean;
    public bool IsOther => !IsScanning && !IsClean && !IsCompromised;

    public string StatusDisplay => Status switch
    {
        ScanStatus.Pending => "Pending",
        ScanStatus.PendingLocked => "Pending (Locked)",
        ScanStatus.Scanning => "Scanning...",
        ScanStatus.Clean => "Clean",
        ScanStatus.Compromised => $"Compromised ({DetectionCount})",
        ScanStatus.Failed => $"Failed: {Message}",
        _ => Status.ToString()
    };

    public event PropertyChangedEventHandler? PropertyChanged;

    protected void OnPropertyChanged([CallerMemberName] string? propertyName = null)
    {
        PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(propertyName));
    }
}

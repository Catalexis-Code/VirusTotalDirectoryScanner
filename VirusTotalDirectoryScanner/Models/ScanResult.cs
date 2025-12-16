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
    Compromised
}

public class ScanResult : INotifyPropertyChanged
{
    private ScanStatus _status;

    public string FileName { get; set; } = string.Empty;
    public string FullPath { get; set; } = string.Empty;
    
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
            }
        }
    }

    public string StatusDisplay => Status switch
    {
        ScanStatus.Pending => "Pending",
        ScanStatus.PendingLocked => "Pending (Locked)",
        ScanStatus.Scanning => "Scanning...",
        ScanStatus.Clean => "Clean",
        ScanStatus.Compromised => "Compromised",
        _ => Status.ToString()
    };

    public event PropertyChangedEventHandler? PropertyChanged;

    protected void OnPropertyChanged([CallerMemberName] string? propertyName = null)
    {
        PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(propertyName));
    }
}

using System;
using System.Linq;
using System.Text.RegularExpressions;
using Avalonia.Controls;
using Avalonia.Input;
using Avalonia.Interactivity;
using Avalonia.Markup.Xaml;
using Avalonia.VisualTree;
using Avalonia.Platform.Storage;
using VirusTotalDirectoryScanner.Helpers;
using VirusTotalDirectoryScanner.Settings;

namespace VirusTotalDirectoryScanner;

public sealed partial class SettingsWindow : Window
{
    public SettingsWindow()
    {
        InitializeComponent();
    }

    private void InitializeComponent()
        => AvaloniaXamlLoader.Load(this);

    protected override void OnOpened(EventArgs e)
    {
        base.OnOpened(e);

        // Attach input validation to all NumericUpDown controls
        foreach (var numericUpDown in this.GetVisualDescendants().OfType<NumericUpDown>())
        {
            numericUpDown.AddHandler(TextInputEvent, OnNumericInput, RoutingStrategies.Tunnel);
        }

        if (DataContext is SettingsDialogViewModel vm)
        {
            if (string.IsNullOrWhiteSpace(vm.ApiKey) || vm.ApiKey == "REPLACE_WITH_REAL_KEY")
            {
                var textBox = this.FindControl<TextBox>("ApiKeyTextBox");
                textBox?.Focus();
            }
        }
    }

    private void Cancel_Click(object? sender, RoutedEventArgs e)
        => Close(false);

    private void ToggleApiKey_Click(object? sender, RoutedEventArgs e)
    {
        if (DataContext is SettingsDialogViewModel vm)
        {
            vm.ToggleApiKeyVisibility();
        }
    }

    private void OpenRegistrationUrl_Click(object? sender, RoutedEventArgs e)
    {
        try
        {
            System.Diagnostics.Process.Start(new System.Diagnostics.ProcessStartInfo
            {
                FileName = "https://www.virustotal.com/gui/join-us",
                UseShellExecute = true
            });
        }
        catch
        {
            // Best effort
        }
    }

    private async void Save_Click(object? sender, RoutedEventArgs e)
    {
        if (DataContext is not SettingsDialogViewModel vm)
        {
            Close(false);
            return;
        }

        bool saved = await vm.SaveAsync();
        if (saved)
        {
            Close(true);
        }
    }

    private void OnNumericInput(object? sender, TextInputEventArgs e)
    {
        if (!InputValidators.IsNumeric(e.Text))
        {
            e.Handled = true;
        }
    }

    private void AddExclusion_Click(object? sender, RoutedEventArgs e)
    {
        if (DataContext is SettingsDialogViewModel vm)
        {
            vm.AddExclusion();
            this.FindControl<TextBox>("ExclusionTextBox")?.Focus();
        }
    }

    private void RemoveExclusion_Click(object? sender, RoutedEventArgs e)
    {
        if (DataContext is SettingsDialogViewModel vm &&
            sender is Button button &&
            button.Tag is string pattern)
        {
            RemoveExclusionWithFocusLogic(vm, pattern);
        }
    }

    private void ExclusionsListBox_KeyDown(object? sender, KeyEventArgs e)
    {
        if (e.Key == Key.Delete || e.Key == Key.Back)
        {
            var listBox = this.FindControl<ListBox>("ExclusionsListBox");
            if (DataContext is SettingsDialogViewModel vm && listBox?.SelectedItem is string pattern)
            {
                RemoveExclusionWithFocusLogic(vm, pattern);
                e.Handled = true;
            }
        }
    }

    private void RemoveExclusionWithFocusLogic(SettingsDialogViewModel vm, string pattern)
    {
        var listBox = this.FindControl<ListBox>("ExclusionsListBox");
        if (listBox == null)
        {
            vm.RemoveExclusion(pattern);
            return;
        }

        int selectedIndex = listBox.SelectedIndex;
        if (selectedIndex == -1)
        {
            selectedIndex = vm.Exclusions.IndexOf(pattern);
        }

        vm.RemoveExclusion(pattern);

        if (vm.Exclusions.Count > 0)
        {
            int newIndex = Math.Min(selectedIndex, vm.Exclusions.Count - 1);
            if (newIndex < 0) newIndex = 0;
            listBox.SelectedIndex = newIndex;
            listBox.Focus();
        }
    }

    private void NewExclusionPattern_KeyDown(object? sender, KeyEventArgs e)
    {
        if (e.Key == Key.Enter)
        {
            if (DataContext is SettingsDialogViewModel vm)
            {
                vm.AddExclusion();
                this.FindControl<TextBox>("ExclusionTextBox")?.Focus();
            }
        }
    }

    // New method to handle folder selection
    private async void SelectFolder_Click(object? sender, RoutedEventArgs e)
    {
        if (sender is not Button button || button.Tag is not string tag)
            return;

        var storage = this.StorageProvider;
        var options = new FolderPickerOpenOptions
        {
            Title = "Select Folder",
            AllowMultiple = false
        };
        var result = await storage.OpenFolderPickerAsync(options);
        var folder = result?.FirstOrDefault();
        if (folder == null)
            return;

        string? path = folder.Path?.AbsolutePath ?? folder.TryGetLocalPath();
        if (string.IsNullOrEmpty(path))
            return;

        if (DataContext is SettingsDialogViewModel vm)
        {
            switch (tag)
            {
                case "ScanDirectory":
                    vm.ScanDirectory = path;
                    break;
                case "CleanDirectory":
                    vm.CleanDirectory = path;
                    break;
                case "CompromisedDirectory":
                    vm.CompromisedDirectory = path;
                    break;
            }
        }
    }

    // New method to handle file selection (log file)
    private async void SelectFile_Click(object? sender, RoutedEventArgs e)
    {
        if (sender is not Button button || button.Tag is not string tag)
            return;

        var storage = this.StorageProvider;
        var options = new FilePickerOpenOptions
        {
            Title = "Select Log File",
            AllowMultiple = false,
            FileTypeFilter = new[]
            {
                new FilePickerFileType("Log Files")
                {
                    Patterns = new[] { "*.log" }
                }
            }
        };
        var result = await storage.OpenFilePickerAsync(options);
        var file = result?.FirstOrDefault();
        if (file == null)
            return;

        string? path = file.Path?.AbsolutePath ?? file.TryGetLocalPath();
        if (string.IsNullOrEmpty(path))
            return;

        if (DataContext is SettingsDialogViewModel vm && tag == "LogFilePath")
        {
            vm.LogFilePath = path;
        }
    }
}

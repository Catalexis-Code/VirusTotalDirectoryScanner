using System;
using Avalonia.Controls;
using Avalonia.Interactivity;
using Avalonia.Markup.Xaml;
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
}

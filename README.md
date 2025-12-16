# VirusTotalDirectoryScanner

**VirusTotalDirectoryScanner** is a robust desktop application built with **.NET 10** and **Avalonia UI** that automates the process of scanning files for malware. It monitors a specific directory, automatically uploads new files to [VirusTotal](https://www.virustotal.com/), and sorts them into "Clean" or "Compromised" folders based on the scan results.

## 🚀 Features

*   **Real-time Directory Monitoring**: Automatically detects new files added to a watched folder.
*   **VirusTotal API Integration**: Seamlessly uploads and scans files using the VirusTotal v3 API.
*   **Automated Sorting**:
    *   **Clean**: Files with no detections are moved to a safe directory.
    *   **Compromised**: Files with detections are isolated in a separate directory.
*   **Smart Quota Management**: Built-in rate limiting to respect your VirusTotal API quotas (requests per minute, day, and month).
*   **Modern UI**: Clean and responsive user interface built with Avalonia UI.
*   **Configurable**: Easy management of API keys, directory paths, and scan settings.

## 🛠️ Tech Stack

*   **Framework**: [.NET 10.0](https://dotnet.microsoft.com/)
*   **UI Framework**: [Avalonia UI](https://avaloniaui.net/) (v11.x)
*   **MVVM**: [CommunityToolkit.Mvvm](https://github.com/CommunityToolkit/dotnet)
*   **API Client**: [Refit](https://github.com/reactiveui/refit)
*   **Dependency Injection**: Microsoft.Extensions.DependencyInjection
*   **Testing**: xUnit, FluentAssertions, Moq

## 📋 Prerequisites

*   **.NET 10.0 SDK** installed on your machine.
*   A valid **VirusTotal API Key** (Get one [here](https://www.virustotal.com/gui/join-us)).

## 🏃 Getting Started

### 1. Clone the Repository

```bash
git clone https://github.com/yourusername/VirusTotalDirectoryScanner.git
cd VirusTotalDirectoryScanner
```

### 2. Configuration

The application requires a VirusTotal API Key to function. You can configure this securely using .NET User Secrets during development or via the Settings UI in the application.

**Using User Secrets (Recommended for Dev):**

```bash
cd VirusTotalDirectoryScanner
dotnet user-secrets init
dotnet user-secrets set "VirusTotal:ApiKey" "YOUR_API_KEY_HERE"
```

**Using the UI:**
1. Run the application.
2. Click on the **Settings** button.
3. Enter your API Key and configure the directories.

### 3. Build and Run

```bash
dotnet build
dotnet run --project VirusTotalDirectoryScanner
```

## 📖 Usage

1.  **Configure Directories**:
    *   **Scan Directory**: The folder where you will drop files to be scanned.
    *   **Clean Directory**: Where safe files will be moved.
    *   **Compromised Directory**: Where malicious files will be moved.
2.  **Start Scanning**: Click the "Start" button on the main dashboard.
3.  **Drop Files**: Place any file into the **Scan Directory**.
4.  **Monitor**: Watch the application log as it detects, uploads, and sorts your files.

## 📂 Project Structure

*   `VirusTotalDirectoryScanner/`: Main application project.
    *   `Services/`: Core logic (Scanning, API, File Ops).
    *   `ViewModels/`: MVVM ViewModels.
    *   `Views/`: Avalonia UI Views (`.axaml`).
    *   `Models/`: Data models and DTOs.
*   `VirusTotalDirectoryScanner.Tests/`: Unit tests using xUnit.

## 🧪 Running Tests

To run the unit tests:

```bash
dotnet test
```

## 🤝 Contributing

Contributions are welcome! Please follow the guidelines in [agents.md](agents.md) for coding standards and architectural patterns.

1.  Fork the repository.
2.  Create a feature branch (`git checkout -b feature/amazing-feature`).
3.  Commit your changes (`git commit -m 'Add some amazing feature'`).
4.  Push to the branch (`git push origin feature/amazing-feature`).
5.  Open a Pull Request.

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

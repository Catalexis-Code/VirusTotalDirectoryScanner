# Agent Guidelines & Best Practices

This document outlines the technical stack, coding standards, and best practices for the **VirusTotalDirectoryScanner** project. All AI agents and developers should adhere to these guidelines.

## 1. Tech Stack

*   **Framework**: .NET 10.0
*   **UI Framework**: Avalonia UI (v11.x)
*   **MVVM Library**: CommunityToolkit.Mvvm
*   **Dependency Injection**: Microsoft.Extensions.DependencyInjection
*   **HTTP Client**: Refit (for VirusTotal API)
*   **Configuration**: Microsoft.Extensions.Configuration (appsettings.json, User Secrets)
*   **Testing**: xUnit, FluentAssertions, Moq

## 2. Code Style & Formatting

*   **Indentation**: **MUST use Tabs** (not spaces). Ensure your editor configuration reflects this.
*   **C# Version**: Use the latest C# features available in .NET 10.
*   **Nullable Reference Types**: Enabled (`<Nullable>enable</Nullable>`). Handle potential nulls explicitly.
*   **File Scoped Namespaces**: Use `namespace VirusTotalDirectoryScanner;` instead of block-scoped namespaces.
*   **Naming Conventions**:
    *   Classes/Methods/Properties: `PascalCase`
    *   Private Fields: `_camelCase`
    *   Local Variables/Parameters: `camelCase`
    *   Interfaces: `IPascalCase`

## 3. Architecture & Patterns

### MVVM (Model-View-ViewModel)
*   Use `CommunityToolkit.Mvvm` source generators.
*   Inherit ViewModels from `ObservableObject`.
*   Use `[ObservableProperty]` for properties to automatically generate `INotifyPropertyChanged` code.
*   Use `[RelayCommand]` for commands.
*   Keep code-behind (`.axaml.cs`) minimal. Logic should reside in the ViewModel.

### Dependency Injection
*   Register services in `App.axaml.cs` or a dedicated bootstrapper.
*   Use Constructor Injection for dependencies in ViewModels and Services.
*   Prefer interfaces (`IFileOperationsService`, `IVirusTotalService`) over concrete implementations.

### API Integration
*   Use `Refit` interfaces for defining API endpoints (e.g., `IVirusTotalApi`).
*   Handle API limits and throttling using `System.Threading.RateLimiting` or custom throttling handlers.

## 4. Testing Guidelines

*   **Framework**: xUnit
*   **Assertions**: Use `FluentAssertions` (e.g., `result.Should().BeTrue()`).
*   **Mocking**: Use `Moq` for mocking dependencies.
*   **Structure**: Tests should be placed in the `VirusTotalDirectoryScanner.Tests` project.
*   **Naming**: `MethodName_StateUnderTesting_ExpectedBehavior`.

## 5. Specific Implementation Details

*   **VirusTotal API**: Respect quota limits. The `QuotaService` and `ThrottlingHandler` are critical.
*   **File Operations**: Use `IFileOperationsService` for file system access to allow for easier testing and mocking.
*   **Settings**: Persist user settings using `ISettingsService`.

## 6. General Best Practices

*   **Async/Await**: Use `async` and `await` for all I/O-bound operations. Avoid `.Result` or `.Wait()`.
*   **Error Handling**: Use try-catch blocks where appropriate, especially around file I/O and network requests. Log errors if a logging service is available.
*   **Clean Code**: Keep methods small and focused. Follow SOLID principles.

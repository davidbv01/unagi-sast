# 🛡️ Unagi SAST - Static Application Security Testing for VS Code

Unagi is a comprehensive Static Application Security Testing (SAST) extension for Visual Studio Code that helps developers identify and fix security vulnerabilities in their code in real-time.

## ✨ Features

- **Real-time Security Scanning**: Automatically scan files as you code
- **Multi-language Support**: JavaScript, TypeScript, Python, Java, PHP, and more
- **Comprehensive Rule Engine**: Detects SQL injection, XSS, hardcoded secrets, weak crypto, and other vulnerabilities
- **Multiple Output Formats**: Problems panel, output channel, inline decorations, or HTML reports
- **Configurable Rules**: Enable/disable specific security rules based on your needs
- **Workspace Scanning**: Scan entire workspace or selected files
- **Risk Assessment**: Calculate security risk scores for your projects

### Supported Vulnerability Types

- 🔍 **SQL Injection** - Detects unsafe SQL query construction
- 🌐 **Cross-Site Scripting (XSS)** - Identifies unsafe HTML content insertion
- 🔐 **Hardcoded Secrets** - Finds API keys, passwords, and other secrets in code
- 🔒 **Weak Cryptography** - Detects use of deprecated hash algorithms
- ⚡ **Command Injection** - Identifies unsafe command execution
- 📁 **Path Traversal** - Detects unsafe file path construction
- 🛡️ **Authentication & Authorization** - Security control issues

## Requirements

If you have any requirements or dependencies, add a section describing those and how to install and configure them.

## Extension Settings

Include if your extension adds any VS Code settings through the `contributes.configuration` extension point.

For example:

This extension contributes the following settings:

* `myExtension.enable`: Enable/disable this extension.
* `myExtension.thing`: Set to `blah` to do something.

## 🚀 Installation

1. Download and install the extension from the VS Code marketplace
2. Reload VS Code
3. Open a supported project (JavaScript, TypeScript, Python, etc.)
4. Start coding - Unagi will automatically scan your files!

## 📖 Usage

### Commands

- **`Unagi: Scan Actual File`** - Scan the currently active file
- **`Unagi: Scan Workspace`** - Scan all supported files in the workspace
- **`Unagi: Scan Selected File`** - Scan a specific file from the explorer
- **`Unagi: Clear Results`** - Clear all scan results

### Automatic Scanning

Unagi can automatically scan files when:
- ✅ Files are saved (configurable)
- ✅ Files are opened (configurable)
- ✅ Content changes (debounced)

### Context Menu Integration

Right-click on files in the explorer or editor to access scanning commands directly.

## ⚙️ Configuration

Access settings via `File > Preferences > Settings > Extensions > Unagi SAST`

### Available Settings

| Setting | Default | Description |
|---------|---------|-------------|
| `unagi.enabledRules` | `[]` | Specific rules to enable (empty = all enabled) |
| `unagi.excludePatterns` | `["**/node_modules/**", "**/dist/**", "**/build/**"]` | File patterns to exclude |
| `unagi.includePatterns` | `["**/*.js", "**/*.ts", "**/*.py", ...]` | File patterns to include |
| `unagi.minimumSeverity` | `["low", "medium", "high", "critical"]` | Severity levels to display |
| `unagi.outputFormat` | `"problems"` | Output format: problems/output/inline/file |
| `unagi.autoScanOnSave` | `true` | Auto-scan when files are saved |
| `unagi.autoScanOnOpen` | `false` | Auto-scan when files are opened |

### Example Configuration

```json
{
  "unagi.excludePatterns": [
    "**/node_modules/**",
    "**/test/**",
    "**/*.min.js"
  ],
  "unagi.minimumSeverity": ["medium", "high", "critical"],
  "unagi.outputFormat": "problems",
  "unagi.autoScanOnSave": true
}
```

## 📁 Project Structure

The Unagi SAST extension follows a modular architecture for maintainability and extensibility:

```
src/
├── extension.ts                 # Main extension entry point
├── types/
│   └── index.ts                # TypeScript interfaces and enums
├── config/
│   └── ConfigurationManager.ts # Extension configuration management
├── triggers/
│   ├── CommandTrigger.ts       # Manual command triggers
│   └── AutoTrigger.ts          # Automatic scan triggers
├── scanners/
│   ├── ScanOrchestrator.ts     # Coordinates scanning operations
│   └── SecurityRuleEngine.ts  # Security rule definitions and matching
├── output/
│   └── OutputManager.ts        # Result display and reporting
├── utils/
│   └── index.ts                # Utility functions
└── test/
    └── extension.test.ts       # Unit tests
```

### Architecture Overview

1. **Extension Entry Point** (`extension.ts`)
   - Initializes all components
   - Registers commands and event listeners
   - Manages extension lifecycle

2. **Configuration Layer** (`config/`)
   - Manages user settings
   - Provides configuration to other components
   - Handles configuration changes

3. **Trigger Layer** (`triggers/`)
   - **CommandTrigger**: Handles manual scan commands
   - **AutoTrigger**: Manages automatic scanning on file events

4. **Scanner Layer** (`scanners/`)
   - **ScanOrchestrator**: Coordinates scanning operations
   - **SecurityRuleEngine**: Contains security rules and pattern matching

5. **Output Layer** (`output/`)
   - **OutputManager**: Handles result display in various formats
   - Supports Problems Panel, Output Channel, HTML reports

6. **Utilities** (`utils/`)
   - File handling utilities
   - String manipulation helpers
   - Security-related utility functions

7. **Type Definitions** (`types/`)
   - Vulnerability interfaces
   - Configuration types
   - Enums for severity levels and vulnerability types

## 🔧 Development

### Building the Extension

```bash
npm install
npm run compile
```

### Running Tests

```bash
npm test
```

### Packaging

```bash
npm run package
```

## 🐛 Known Issues

- Large files (>1MB) may take longer to scan
- Some complex regex patterns might have false positives
- Auto-scan on change is debounced to prevent performance issues

## 📝 Release Notes

### 0.0.1

- Initial release
- Basic security rule engine
- Multi-language support
- Problems panel integration
- Configurable scanning options

---

## 🤝 Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## 📄 License

This extension is licensed under the MIT License.

## Following extension guidelines

Ensure that you've read through the extensions guidelines and follow the best practices for creating your extension.

* [Extension Guidelines](https://code.visualstudio.com/api/references/extension-guidelines)

## Working with Markdown

You can author your README using Visual Studio Code. Here are some useful editor keyboard shortcuts:

* Split the editor (`Cmd+\` on macOS or `Ctrl+\` on Windows and Linux).
* Toggle preview (`Shift+Cmd+V` on macOS or `Shift+Ctrl+V` on Windows and Linux).
* Press `Ctrl+Space` (Windows, Linux, macOS) to see a list of Markdown snippets.

## For more information

* [Visual Studio Code's Markdown Support](http://code.visualstudio.com/docs/languages/markdown)
* [Markdown Syntax Reference](https://help.github.com/articles/markdown-basics/)

**Enjoy!**

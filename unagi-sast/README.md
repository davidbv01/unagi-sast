# Unagi-SAST Extension

A Visual Studio Code extension that performs Static Application Security Testing (SAST) to identify potential vulnerabilities in your code and provides recommendations for fixing them.

## Features

- Real-time security scanning of your code
- Integration with ESLint security rules
- Integration with Semgrep for advanced pattern matching
- Detailed security recommendations
- Custom sidebar view for security scan results

## Requirements

- Visual Studio Code 1.85.0 or higher
- Node.js 14.x or higher
- Python 3.x (for Semgrep)

## Installation

1. Install the extension from the VS Code marketplace
2. Install Semgrep globally:
   ```bash
   pip install semgrep
   ```

## Usage

1. Open any file you want to scan for vulnerabilities
2. Use the command palette (Ctrl+Shift+P or Cmd+Shift+P) and search for "Unagi-SAST: Scan Current File for Vulnerabilities"
3. View the results in the output panel and the Security Scan Results sidebar

## Security Rules

The extension checks for various security vulnerabilities including:

- SQL Injection
- Cross-Site Scripting (XSS)
- Command Injection
- Path Traversal
- Insecure Cryptographic Algorithms
- Hardcoded Credentials
- And more...

## Contributing

Feel free to submit issues and enhancement requests!

## License

MIT

## Release Notes

### 0.0.1

Initial release of Unagi-SAST
- Basic SAST functionality
- ESLint security rules integration
- Semgrep integration
- Results view

## Extension Settings

Include if your extension adds any VS Code settings through the `contributes.configuration` extension point.

For example:

This extension contributes the following settings:

* `myExtension.enable`: Enable/disable this extension.
* `myExtension.thing`: Set to `blah` to do something.

## Known Issues

Calling out known issues can help limit users opening duplicate issues against your extension.

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

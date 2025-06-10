# 🛡️ Unagi SAST Extension Development Guide

## Quick Start

1. **Clone and Setup**
   ```bash
   git clone <repository-url>
   cd unagi
   npm install
   ```

2. **Development**
   ```bash
   npm run watch  # Start TypeScript compilation in watch mode
   ```

3. **Testing**
   - Press `F5` in VS Code to open a new Extension Development Host
   - Test commands in the Command Palette (`Ctrl+Shift+P`)

## Architecture Deep Dive

### Core Components

#### 1. Extension Entry Point (`extension.ts`)
- Manages extension lifecycle (activate/deactivate)
- Initializes all components
- Registers commands and event listeners

#### 2. Configuration Management (`config/ConfigurationManager.ts`)
- Singleton pattern for configuration access
- Handles VS Code workspace settings
- Provides type-safe configuration retrieval

#### 3. Trigger System (`triggers/`)
- **CommandTrigger**: Manual user-initiated scans
- **AutoTrigger**: Event-driven automatic scans
- Debounced scanning to prevent performance issues

#### 4. Scanning Engine (`scanners/`)
- **ScanOrchestrator**: High-level scanning coordination
- **SecurityRuleEngine**: Pattern matching and rule evaluation
- Progress reporting and error handling

#### 5. Output Management (`output/OutputManager.ts`)
- Multiple output formats (Problems, Output Channel, HTML)
- Diagnostic collection for VS Code Problems panel
- Status bar integration
- Report generation

### Security Rules

Rules are defined in `SecurityRuleEngine.ts` with the following structure:

```typescript
{
  id: 'unique-rule-id',
  name: 'Human readable name',
  description: 'Detailed description',
  severity: Severity.HIGH,
  type: VulnerabilityType.SQL_INJECTION,
  pattern: /regex-pattern/,
  languages: ['javascript', 'typescript'],
  enabled: true
}
```

### Adding New Rules

1. Define the rule in `SecurityRuleEngine.loadSecurityRules()`
2. Add appropriate recommendation in `getRecommendation()`
3. Test with sample vulnerable code
4. Update documentation

### Testing Strategy

- Unit tests for individual components
- Integration tests for full scanning workflow
- Manual testing with sample vulnerable code
- Performance testing with large codebases

## Extension Points

### Custom Rules
Extend `SecurityRuleEngine` to add custom security rules for specific frameworks or patterns.

### Output Formats
Implement new output formats by extending `OutputManager.displayResults()`.

### Language Support
Add new language support by:
1. Adding language ID to supported languages
2. Creating language-specific rules
3. Testing with sample code

## Performance Considerations

- **Debouncing**: Auto-scan triggers are debounced (2s default)
- **Exclusion Patterns**: Use to skip large directories (node_modules, dist)
- **Progressive Scanning**: Large workspaces are scanned with progress reporting
- **Lazy Loading**: Components are initialized only when needed

## Debugging

1. **Enable Developer Tools**: `Help > Toggle Developer Tools`
2. **Extension Host Logs**: Check the Extension Development Host console
3. **Output Channel**: View "Unagi SAST" output channel
4. **VS Code Logs**: Use `Developer: Show Logs` command

## Contributing Guidelines

1. Follow TypeScript strict mode
2. Add JSDoc comments for public methods
3. Include unit tests for new features
4. Update README for user-facing changes
5. Test with multiple file types and sizes

## Release Process

1. Update version in `package.json`
2. Update `CHANGELOG.md`
3. Run tests: `npm test`
4. Build: `npm run compile`
5. Package: `vsce package`
6. Publish: `vsce publish`

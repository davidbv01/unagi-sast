# 🛡️ Unagi SAST

Unagi SAST is a modern Static Application Security Testing (SAST) tool for deep code analysis and vulnerability detection in Python applications. It combines advanced static analysis, taint tracking, and AI-powered verification to help you find and fix security issues before they reach production.

---

## 🚀 Presentation

Unagi SAST is designed for:
- **Developers** who want to catch vulnerabilities early
- **Security engineers** seeking automated code review
- **Teams** integrating security into their CI/CD pipeline

**Key Features:**
- AST-based static analysis using Tree-sitter
- Taint flow and data flow analysis
- Pattern-based and AI-powered vulnerability detection (OpenAI LLM integration)
- Extensible YAML-based rule system
- VSCode extension for seamless workflow

Supported vulnerability types include:
- SQL Injection
- Command Injection
- Path Traversal
- Insecure Deserialization
- Hardcoded Secrets
- ...and more

---

## 🧪 How to Test Unagi SAST

### 1. Prerequisites
- [VSCode](https://code.visualstudio.com/)
- [Node.js](https://nodejs.org/)
- Python code to analyze (see examples below)

### 2. Installation
```bash
# Clone the repository
$ git clone <repository-url>
$ cd unagi-sast

# Install dependencies
$ npm install

# Build the extension
$ npm run build
```

### 3. Running & Testing in VSCode
1. Open the project in VSCode.
2. Press `F5` to launch a new Extension Development Host.
3. Open a Python file (or use the samples in `test/`).
4. Open the Command Palette (`Ctrl+Shift+P`) and run:
   - **Unagi: Scan Current File** – Scan the open file
   - **Unagi: Scan Workspace** – Scan all Python files in the workspace

#### Example: Vulnerable vs. Safe Code

<details>
<summary>Vulnerable Example (test/vulnerable_code.py)</summary>

```python
import os

def vulnerable_function():
    name = input("Enter your name: ")
    debug = name.lower()
    test = debug
    os.system(test)

vulnerable_function()
```
</details>

<details>
<summary>Safe Example (test/safe_code.py)</summary>

```python
import os

def vulnerable_function():
    user_input = input("Enter your name: ") 
    if not user_input.isalnum():  # Simple validation: only alphanumeric characters
        return
    os.system("echo " + user_input)         

vulnerable_function()
```
</details>

### 4. Interpreting Results
- Vulnerabilities and recommendations will appear in the Problems panel and the Unagi SAST output channel.
- Detailed taint analysis and data flow information is available for detected issues.

---

## 🛠️ Development & Contribution Guide

### Quick Start
```bash
# Start TypeScript in watch mode for live development
$ npm run watch
```
- Press `F5` in VSCode to open a new Extension Development Host for live testing.

### Project Structure
- `src/` – Main source code
  - `ai/` – AI-powered verification logic
  - `analysis/` – Analysis logic and rule system
    - `rules/` – YAML rules for sources, sinks, sanitizers, and patterns
  - `config/` – Configuration management
  - `core/` – Orchestration and command handling
  - `output/` – Output and reporting logic
  - `parser/` – AST parsing logic
  - `rules/` – Security rule engine
  - `types/` – Type definitions
  - `utils/` – Utility functions
- `test_data/` – Example Python files for testing

### Architecture Highlights
- **Extension Entry**: `src/extension.ts` manages lifecycle and command registration
- **Scan Engine**: `ScanOrchestrator` and `SecurityRuleEngine` coordinate analysis
- **Taint Analysis**: Tracks data from sources to sinks, checking for sanitization (see `TAINT_ANALYSIS.md`)
- **Custom Rules**: Add new rules in YAML or extend `SecurityRuleEngine`

### Adding New Rules
1. Define the rule in `SecurityRuleEngine.loadSecurityRules()` or YAML
2. Add recommendations in `getRecommendation()`
3. Test with sample code
4. Update documentation

### Testing & Debugging
- Use unit and integration tests for new features
- Manual test with `test/vulnerable_code.py` and `test/safe_code.py`
- View logs in the Unagi SAST output channel and VSCode developer tools

### Performance & Best Practices
- Debounced auto-scans to avoid performance issues
- Exclude large folders (e.g., `node_modules`) via settings
- Lazy loading for efficiency

### Contributing
- Follow TypeScript strict mode
- Add JSDoc for public methods
- Include tests for new features
- Update documentation for user-facing changes

---

## 📚 Further Reading
- [TAINT_ANALYSIS.md](./TAINT_ANALYSIS.md) – Deep dive into taint analysis
- [DEVELOPMENT.md](./DEVELOPMENT.md) – Full development guide
- [PIPELINE.md](./PIPELINE.md) – Analysis pipeline details

---

## 📝 License
See [LICENSE.md](./LICENSE.md)

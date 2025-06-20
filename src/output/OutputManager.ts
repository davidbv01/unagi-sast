import * as vscode from 'vscode';
import { ScanResult, Vulnerability, Severity } from '../types';
import { AnalysisResult } from '../rules/SecurityRuleEngine';
import * as fs from 'fs';

export class OutputManager {
  private outputChannel: vscode.OutputChannel;
  private diagnosticCollection: vscode.DiagnosticCollection;
  private statusBarItem: vscode.StatusBarItem;
  private folderPath: string;
  private filePath: string;

  constructor(folderPath: string) {
    this.outputChannel = vscode.window.createOutputChannel('Unagi SAST');
    this.diagnosticCollection = vscode.languages.createDiagnosticCollection('unagi');
    this.statusBarItem = vscode.window.createStatusBarItem(vscode.StatusBarAlignment.Left, 100);
    this.statusBarItem.show();  
    this.folderPath = folderPath;
    fs.mkdirSync(this.folderPath, { recursive: true });
    this.filePath = this.folderPath + '/sast-results.json';
  }

  public async displayResults(result: ScanResult): Promise<void> {
  
    // Clear previous results
    this.diagnosticCollection.clear();

    // Create diagnostics for all detected items
    const allDiagnostics: vscode.Diagnostic[] = [];
    
    // Convert vulnerabilities to diagnostics (highest priority - errors)
    result.vulnerabilities.forEach(vuln => {
      allDiagnostics.push(this.createDiagnostic(vuln));
    });

    // Convert sources to diagnostics (information level with specific styling)
    result.sources.forEach((source: any) => {
      allDiagnostics.push(this.createSourceDiagnostic(source));
    });

    // Convert sinks to diagnostics (warning level with specific styling)
    result.sinks.forEach((sink: any) => {
      allDiagnostics.push(this.createSinkDiagnostic(sink));
    }); 

    // Convert sanitizers to diagnostics (hint level with specific styling)
      result.sanitizers.forEach((sanitizer: any) => {
      allDiagnostics.push(this.createSanitizerDiagnostic(sanitizer));
    });

    // Update diagnostics collection
    const uri = vscode.Uri.file(result.file);
    this.diagnosticCollection.set(uri, allDiagnostics);

    // Update status bar
    this.updateStatusBar(result);
    // Display inline results with enhanced summary
    this.displayInline(result);
  }

  private displayInline(result: ScanResult): void {
    const summary = `Scan complete: ${result.vulnerabilities.length} vulnerabilities, ${result.sources.length} sources, ${result.sinks.length} sinks, ${result.sanitizers.length} sanitizers`;
    vscode.window.showInformationMessage(summary);
  }

  private updateStatusBar(result: ScanResult | ScanResult[]): void {
    const totalVulnerabilities = Array.isArray(result) 
      ? result.reduce((sum, r) => sum + r.vulnerabilities.length, 0)
      : result.vulnerabilities.length;
    
    this.statusBarItem.text = `$(shield) Unagi: ${totalVulnerabilities} issues`;
    this.statusBarItem.tooltip = `Found ${totalVulnerabilities} security vulnerabilities`;
  }

  public clearResults(): void {
    this.diagnosticCollection.clear();
    this.outputChannel.clear();
    this.statusBarItem.text = '🛡️ Unagi: Ready';
    this.statusBarItem.color = undefined;
  }

  public dispose(): void {
    this.outputChannel.dispose();
    this.diagnosticCollection.dispose();
    this.statusBarItem.dispose();
  }

  private createDiagnostic(vulnerability: Vulnerability): vscode.Diagnostic {
    const range = new vscode.Range(
      vulnerability.line - 1,
      0,
      vulnerability.line - 1,
      100
    );
    
    const diagnostic = new vscode.Diagnostic(
      range,
      vulnerability.message,
      this.getSeverity(vulnerability.severity)
    );
    
    diagnostic.source = 'Unagi SAST';
    diagnostic.code = vulnerability.type;
    return diagnostic;
  }

  private getSeverity(severity: Severity): vscode.DiagnosticSeverity {
    switch (severity) {
      case Severity.CRITICAL:
        return vscode.DiagnosticSeverity.Error;
      case Severity.HIGH:
        return vscode.DiagnosticSeverity.Error;
      case Severity.MEDIUM:
        return vscode.DiagnosticSeverity.Warning;
      case Severity.LOW:
        return vscode.DiagnosticSeverity.Information;
      default:
        return vscode.DiagnosticSeverity.Information;
    }
  }

  private createSourceDiagnostic(source: any): vscode.Diagnostic {
    // Use precise positioning if available, otherwise default to line-based
    const startLine = (source.line || 1) - 1; // Convert to 0-based
    const startColumn = source.column || 0;
    const endLine = source.endLine ? (source.endLine - 1) : startLine;
    const endColumn = source.endColumn || (startColumn + 10); // Default to +10 chars if no end column
    
    const range = new vscode.Range(
      startLine,
      startColumn,
      endLine,
      endColumn
    );
    
    const diagnostic = new vscode.Diagnostic(
      range,
      `📥 SOURCE: ${source.description}`,
      vscode.DiagnosticSeverity.Information
    );
    
    diagnostic.source = 'Unagi SAST - Source';
    diagnostic.code = `source-${source.id}`;
    diagnostic.tags = [vscode.DiagnosticTag.Unnecessary]; // This adds a faded styling
    return diagnostic;
  }

  private createSinkDiagnostic(sink: any): vscode.Diagnostic {
    // Use precise positioning if available, otherwise default to line-based
    const startLine = (sink.line || 1) - 1; // Convert to 0-based
    const startColumn = sink.column || 0;
    const endLine = sink.endLine ? (sink.endLine - 1) : startLine;
    const endColumn = sink.endColumn || (startColumn + 10); // Default to +10 chars if no end column
    
    const range = new vscode.Range(
      startLine,
      startColumn,
      endLine,
      endColumn
    );
    
    const diagnostic = new vscode.Diagnostic(
      range,
      `📤 SINK: ${sink.description}`,
      vscode.DiagnosticSeverity.Warning
    );
    
    diagnostic.source = 'Unagi SAST - Sink';
    diagnostic.code = `sink-${sink.id}`;
    return diagnostic;
  }

  private createSanitizerDiagnostic(sanitizer: any): vscode.Diagnostic {
    // Use precise positioning if available, otherwise default to line-based
    const startLine = (sanitizer.line || 1) - 1; // Convert to 0-based
    const startColumn = sanitizer.column || 0;
    const endLine = sanitizer.endLine ? (sanitizer.endLine - 1) : startLine;
    const endColumn = sanitizer.endColumn || (startColumn + 10); // Default to +10 chars if no end column
    
    const range = new vscode.Range(
      startLine,
      startColumn,
      endLine,
      endColumn
    );
    
    const diagnostic = new vscode.Diagnostic(
      range,
      `🛡️ SANITIZER: ${sanitizer.description}`,
      vscode.DiagnosticSeverity.Hint
    );
    
    diagnostic.source = 'Unagi SAST - Sanitizer';
    diagnostic.code = `sanitizer-${sanitizer.id}`;
    return diagnostic;
  }

  public async saveAnalysisResultToTempFile(analysisResult: AnalysisResult): Promise<boolean> {
    return new Promise((resolve) => {
      fs.writeFile(this.filePath, JSON.stringify(analysisResult, null, 2), 'utf8', (err) => {
        if (err) {
          console.error('[ERROR] Failed to write analysis result to fixed path:', err);
          resolve(false);
        } else {
          resolve(true);
        }
      });
    });
  }

  public async createReport(): Promise<void> {
    if (!fs.existsSync(this.filePath)) {
      vscode.window.showInformationMessage('No analysis report available. Please run a scan first.');
      return;
    }
    let analysisResult: AnalysisResult;
    try {
      const fileContent = fs.readFileSync(this.filePath, 'utf8');
      analysisResult = JSON.parse(fileContent);
    } catch (err) {
      vscode.window.showErrorMessage('Failed to read the last analysis result.');
      return;
    }
    const html = this.generateHtmlReport(analysisResult);
    const panel = vscode.window.createWebviewPanel(
      'unagiSastReport',
      'Unagi SAST Report',
      vscode.ViewColumn.One,
      { enableScripts: true }
    );
    panel.webview.html = html;
  }

  private generateHtmlReport(analysisResult: AnalysisResult): string {
    const { vulnerabilities, sources, sinks, sanitizers } = analysisResult;
    return `
      <!DOCTYPE html>
      <html lang="en">
      <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>Unagi SAST Report</title>
        <style>
          body { font-family: 'Segoe UI', Arial, sans-serif; background: #181818; color: #eee; margin: 0; padding: 0; }
          .container { max-width: 900px; margin: 32px auto; background: #232323; border-radius: 12px; box-shadow: 0 2px 16px #0008; padding: 32px; }
          h1 { color: #ffb300; }
          h2 { color: #90caf9; margin-top: 2em; }
          table { width: 100%; border-collapse: collapse; margin-top: 1em; }
          th, td { padding: 10px; border-bottom: 1px solid #333; }
          th { background: #222; color: #ffb300; }
          tr:nth-child(even) { background: #20232a; }
          .severity-critical { color: #ff1744; font-weight: bold; }
          .severity-high { color: #ff9100; font-weight: bold; }
          .severity-medium { color: #ffd600; font-weight: bold; }
          .severity-low { color: #00e676; font-weight: bold; }
          .severity-info { color: #29b6f6; font-weight: bold; }
          .section { margin-bottom: 2em; }
        </style>
      </head>
      <body>
        <div class="container">
          <h1>Unagi SAST Security Report</h1>
          <div class="section">
            <h2>Vulnerabilities (${vulnerabilities.length})</h2>
            ${vulnerabilities.length === 0 ? '<p>No vulnerabilities found.</p>' : `
              <table>
                <tr><th>Type</th><th>Severity</th><th>Message</th><th>Line</th><th>Description</th></tr>
                ${vulnerabilities.map(vuln => `
                  <tr>
                    <td>${vuln.type}</td>
                    <td class="severity-${vuln.severity ? vuln.severity.toLowerCase() : 'info'}">${vuln.severity ?? ''}</td>
                    <td>${vuln.message}</td>
                    <td>${vuln.line ?? ''}</td>
                    <td>${vuln.description ?? ''}</td>
                  </tr>
                `).join('')}
              </table>
            `}
          </div>
          <div class="section">
            <h2>Sources (${sources.length})</h2>
            ${sources.length === 0 ? '<p>No sources found.</p>' : `
              <table>
                <tr><th>ID</th><th>Type</th><th>Pattern</th><th>Description</th><th>Severity</th><th>Line</th><th>Column</th><th>EndLine</th><th>EndColumn</th></tr>
                ${sources.map((src: any) => `
                  <tr>
                    <td>${src.id ?? ''}</td>
                    <td>${src.type ?? ''}</td>
                    <td>${src.pattern ?? ''}</td>
                    <td>${src.description ?? ''}</td>
                    <td class="severity-${src.severity ? src.severity.toLowerCase() : 'info'}">${src.severity ?? ''}</td>
                    <td>${src.line ?? ''}</td>
                    <td>${src.column ?? ''}</td>
                    <td>${src.endLine ?? ''}</td>
                    <td>${src.endColumn ?? ''}</td>
                  </tr>
                `).join('')}
              </table>
            `}
          </div>
          <div class="section">
            <h2>Sinks (${sinks.length})</h2>
            ${sinks.length === 0 ? '<p>No sinks found.</p>' : `
              <table>
                <tr><th>ID</th><th>Type</th><th>Pattern</th><th>Description</th><th>Vulnerability Type</th><th>Severity</th><th>Line</th><th>Column</th><th>EndLine</th><th>EndColumn</th></tr>
                ${sinks.map((sink: any) => `
                  <tr>
                    <td>${sink.id ?? ''}</td>
                    <td>${sink.type ?? ''}</td>
                    <td>${sink.pattern ?? ''}</td>
                    <td>${sink.description ?? ''}</td>
                    <td>${sink.vulnerabilityType ?? ''}</td>
                    <td class="severity-${sink.severity ? sink.severity.toLowerCase() : 'info'}">${sink.severity ?? ''}</td>
                    <td>${sink.line ?? ''}</td>
                    <td>${sink.column ?? ''}</td>
                    <td>${sink.endLine ?? ''}</td>
                    <td>${sink.endColumn ?? ''}</td>
                  </tr>
                `).join('')}
              </table>
            `}
          </div>
          <div class="section">
            <h2>Sanitizers (${sanitizers.length})</h2>
            ${sanitizers.length === 0 ? '<p>No sanitizers found.</p>' : `
              <table>
                <tr><th>ID</th><th>Type</th><th>Pattern</th><th>Description</th><th>Effectiveness</th><th>Line</th><th>Column</th><th>EndLine</th><th>EndColumn</th></tr>
                ${sanitizers.map((san: any) => `
                  <tr>
                    <td>${san.id ?? ''}</td>
                    <td>${san.type ?? ''}</td>
                    <td>${san.pattern ?? ''}</td>
                    <td>${san.description ?? ''}</td>
                    <td>${san.effectiveness !== undefined ? (san.effectiveness * 100).toFixed(0) + '%' : ''}</td>
                    <td>${san.line ?? ''}</td>
                    <td>${san.column ?? ''}</td>
                    <td>${san.endLine ?? ''}</td>
                    <td>${san.endColumn ?? ''}</td>
                  </tr>
                `).join('')}
              </table>
            `}
          </div>
        </div>
      </body>
      </html>
    `;
  }
}
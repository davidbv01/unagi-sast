import * as vscode from 'vscode';
import { ScanResult, Vulnerability, Severity } from '../types';

export class OutputManager {
  private outputChannel: vscode.OutputChannel;
  private diagnosticCollection: vscode.DiagnosticCollection;
  private statusBarItem: vscode.StatusBarItem;

  constructor() {
    console.log('📊 Initializing Output Manager...');
    this.outputChannel = vscode.window.createOutputChannel('Unagi SAST');
    this.diagnosticCollection = vscode.languages.createDiagnosticCollection('unagi');
    this.statusBarItem = vscode.window.createStatusBarItem(vscode.StatusBarAlignment.Left, 100);
    this.statusBarItem.show();
    console.log('✅ Output Manager initialized');
  }

  public async displayResults(result: ScanResult): Promise<void> {
    console.log(`📝 Processing scan results for ${result.file}`);
    console.log(`📊 Found ${result.vulnerabilities.length} vulnerabilities, ${result.sources.length} sources, ${result.sinks.length} sinks, ${result.sanitizers.length} sanitizers`);
    
    // Log detailed information about detected items
    if (result.sources.length > 0) {
      console.log(`📥 Sources detected:`);
      result.sources.forEach((source: any, index: number) => {
        console.log(`  ${index + 1}. ${source.type} - ${source.description} (Line: ${source.line}, Columns: ${source.column}-${source.endColumn})`);
      });
    }
    
    if (result.sinks.length > 0) {
      console.log(`📤 Sinks detected:`);
      result.sinks.forEach((sink: any, index: number) => {
        console.log(`  ${index + 1}. ${sink.type} - ${sink.description} (Line: ${sink.line}, Columns: ${sink.column}-${sink.endColumn})`);
      });
    }
    
    if (result.sanitizers.length > 0) {
      console.log(`🛡️ Sanitizers detected:`);
      result.sanitizers.forEach((sanitizer: any, index: number) => {
        console.log(`  ${index + 1}. ${sanitizer.type} - ${sanitizer.description} (Line: ${sanitizer.line}, Columns: ${sanitizer.column}-${sanitizer.endColumn})`);
      });
    }
    
    // Clear previous results
    this.diagnosticCollection.clear();
    console.log('🧹 Cleared previous diagnostic results');

    // Create diagnostics for all detected items
    const allDiagnostics: vscode.Diagnostic[] = [];
    
    // Convert vulnerabilities to diagnostics (highest priority - errors)
    result.vulnerabilities.forEach(vuln => {
      console.log(`🔍 Processing vulnerability: ${vuln.type} (${vuln.severity})`);
      allDiagnostics.push(this.createDiagnostic(vuln));
    });

    // Convert sources to diagnostics (information level with specific styling)
    result.sources.forEach((source: any) => {
      console.log(`📥 Processing source: ${source.type} (Line: ${source.line}, Columns: ${source.column}-${source.endColumn})`);
      allDiagnostics.push(this.createSourceDiagnostic(source));
    });

    // Convert sinks to diagnostics (warning level with specific styling)
    result.sinks.forEach((sink: any) => {
      console.log(`📤 Processing sink: ${sink.type} (Line: ${sink.line}, Columns: ${sink.column}-${sink.endColumn})`);
      allDiagnostics.push(this.createSinkDiagnostic(sink));
    });

    // Convert sanitizers to diagnostics (hint level with specific styling)
    result.sanitizers.forEach((sanitizer: any) => {
      console.log(`🛡️ Processing sanitizer: ${sanitizer.type} (Line: ${sanitizer.line}, Columns: ${sanitizer.column}-${sanitizer.endColumn})`);
      allDiagnostics.push(this.createSanitizerDiagnostic(sanitizer));
    });

    // Update diagnostics collection
    const uri = vscode.Uri.file(result.file);
    this.diagnosticCollection.set(uri, allDiagnostics);
    console.log(`📌 Updated diagnostics for ${result.file} (${allDiagnostics.length} total items)`);

    // Update status bar
    this.updateStatusBar(result);
    console.log('📊 Updated status bar');

    // Display inline results with enhanced summary
    this.displayInline(result);
    console.log('✅ Results display completed');
  }

  private displayInProblemsPanel(result: ScanResult): void {
    const diagnostics: vscode.Diagnostic[] = result.vulnerabilities.map(vuln => {
      const range = new vscode.Range(
        new vscode.Position(vuln.line - 1, vuln.column),
        new vscode.Position(vuln.line - 1, vuln.column + 10)
      );
      
      const diagnostic = new vscode.Diagnostic(
        range,
        `${vuln.message}: ${vuln.description}`,
        this.severityToDiagnosticSeverity(vuln.severity)
      );
      
      diagnostic.code = vuln.rule;
      diagnostic.source = 'Unagi SAST';
      
      return diagnostic;
    });
    
    const uri = vscode.Uri.file(result.file);
    this.diagnosticCollection.set(uri, diagnostics);
  }

  private displayMultipleInProblemsPanel(results: ScanResult[]): void {
    // Clear existing diagnostics
    this.diagnosticCollection.clear();
    
    for (const result of results) {
      this.displayInProblemsPanel(result);
    }
  }

  private displayInline(result: ScanResult): void {
    console.log('🎯 Displaying inline results...');
    const summary = `Scan complete: ${result.vulnerabilities.length} vulnerabilities, ${result.sources.length} sources, ${result.sinks.length} sinks, ${result.sanitizers.length} sanitizers`;
    vscode.window.showInformationMessage(summary);
    console.log('✅ Inline results displayed');
  }

  private logWorkspaceSummary(results: ScanResult[]): void {
    const totalVulnerabilities = results.reduce((total, result) => total + result.vulnerabilities.length, 0);
    const totalFiles = results.length;
    const totalLines = results.reduce((total, result) => total + result.linesScanned, 0);
    
    this.outputChannel.clear();
    this.outputChannel.appendLine('=== Unagi SAST Workspace Scan Summary ===');
    this.outputChannel.appendLine(`Files Scanned: ${totalFiles}`);
    this.outputChannel.appendLine(`Total Lines: ${totalLines}`);
    this.outputChannel.appendLine(`Vulnerabilities Found: ${totalVulnerabilities}`);
    this.outputChannel.appendLine('');
    
    // Group by severity
    const bySeverity = results.flatMap(r => r.vulnerabilities)
      .reduce((acc, vuln) => {
        acc[vuln.severity] = (acc[vuln.severity] || 0) + 1;
        return acc;
      }, {} as Record<string, number>);
    
    Object.entries(bySeverity).forEach(([severity, count]) => {
      this.outputChannel.appendLine(`${severity.toUpperCase()}: ${count}`);
    });
    
    this.outputChannel.show();
  }

  private updateStatusBar(result: ScanResult | ScanResult[]): void {
    const totalVulnerabilities = Array.isArray(result) 
      ? result.reduce((sum, r) => sum + r.vulnerabilities.length, 0)
      : result.vulnerabilities.length;
    
    this.statusBarItem.text = `$(shield) Unagi: ${totalVulnerabilities} issues`;
    this.statusBarItem.tooltip = `Found ${totalVulnerabilities} security vulnerabilities`;
  }

  private severityToDiagnosticSeverity(severity: Severity): vscode.DiagnosticSeverity {
    switch (severity) {
      case Severity.CRITICAL:
      case Severity.HIGH:
        return vscode.DiagnosticSeverity.Error;
      case Severity.MEDIUM:
        return vscode.DiagnosticSeverity.Warning;
      case Severity.LOW:
      case Severity.INFO:
        return vscode.DiagnosticSeverity.Information;
      default:
        return vscode.DiagnosticSeverity.Information;
    }
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
}
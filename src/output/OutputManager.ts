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
    console.log(`📊 Found ${result.vulnerabilities.length} vulnerabilities`);
    
    // Clear previous results
    this.diagnosticCollection.clear();
    console.log('🧹 Cleared previous diagnostic results');

    // Convert vulnerabilities to diagnostics
    const diagnostics = result.vulnerabilities.map(vuln => {
      console.log(`🔍 Processing vulnerability: ${vuln.type} (${vuln.severity})`);
      return this.createDiagnostic(vuln);
    });

    // Update diagnostics collection
    const uri = vscode.Uri.file(result.file);
    this.diagnosticCollection.set(uri, diagnostics);
    console.log(`📌 Updated diagnostics for ${result.file}`);

    // Update status bar
    this.updateStatusBar(result);
    console.log('📊 Updated status bar');

    // Display inline results
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
    vscode.window.showInformationMessage(
      `Scan complete: ${result.vulnerabilities.length} issues found`
    );
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
}

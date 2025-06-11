import * as vscode from 'vscode';
import { ScanResult, Vulnerability, OutputFormat, Severity } from '../types';
import { configManager } from '../config/ConfigurationManager';

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

  public async displayWorkspaceResults(results: ScanResult[]): Promise<void> {
    const totalVulnerabilities = results.reduce((total, result) => total + result.vulnerabilities.length, 0);
    
    // Update status bar
    this.updateStatusBar(results);
    
    // Display all results in problems panel
    this.displayMultipleInProblemsPanel(results);
    
    // Log summary to output channel
    this.logWorkspaceSummary(results);
    
    // Show notification
    if (totalVulnerabilities > 0) {
      vscode.window.showWarningMessage(
        `Unagi: Found ${totalVulnerabilities} security issues across ${results.length} files.`,
        'View Problems'
      ).then(selection => {
        if (selection === 'View Problems') {
          vscode.commands.executeCommand('workbench.panel.markers.view.focus');
        }
      });
    } else {
      vscode.window.showInformationMessage('Unagi: No security issues found in workspace.');
    }
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

  private displayInOutputChannel(result: ScanResult): void {
    this.outputChannel.clear();
    this.outputChannel.appendLine(`=== Unagi SAST Scan Results ===`);
    this.outputChannel.appendLine(`File: ${result.file}`);
    this.outputChannel.appendLine(`Scan Time: ${result.scanTime}ms`);
    this.outputChannel.appendLine(`Lines Scanned: ${result.linesScanned}`);
    this.outputChannel.appendLine(`Vulnerabilities Found: ${result.vulnerabilities.length}`);
    this.outputChannel.appendLine('');
    
    if (result.vulnerabilities.length === 0) {
      this.outputChannel.appendLine('✅ No security issues found.');
    } else {
      result.vulnerabilities.forEach((vuln, index) => {
        this.outputChannel.appendLine(`${index + 1}. ${vuln.severity.toUpperCase()}: ${vuln.message}`);
        this.outputChannel.appendLine(`   Line ${vuln.line}: ${vuln.description}`);
        this.outputChannel.appendLine(`   Recommendation: ${vuln.recommendation}`);
        this.outputChannel.appendLine('');
      });
    }
    
    this.outputChannel.show();
  }

  private displayInline(result: ScanResult): void {
    console.log('🎯 Displaying inline results...');
    vscode.window.showInformationMessage(
      `Scan complete: ${result.vulnerabilities.length} issues found`
    );
    console.log('✅ Inline results displayed');
  }

  private async generateReportFile(results: ScanResult[]): Promise<void> {
    const workspaceFolder = vscode.workspace.workspaceFolders?.[0];
    if (!workspaceFolder) {
      return;
    }

    const reportContent = this.generateHTMLReport(results);
    const reportPath = vscode.Uri.joinPath(workspaceFolder.uri, 'unagi-security-report.html');
    
    await vscode.workspace.fs.writeFile(reportPath, Buffer.from(reportContent));
    
    vscode.window.showInformationMessage(
      'Security report generated successfully!',
      'Open Report'
    ).then(selection => {
      if (selection === 'Open Report') {
        vscode.env.openExternal(reportPath);
      }
    });
  }

  private generateHTMLReport(results: ScanResult[]): string {
    const totalVulnerabilities = results.reduce((total, result) => total + result.vulnerabilities.length, 0);
    const timestamp = new Date().toISOString();
    
    return `
<!DOCTYPE html>
<html>
<head>
    <title>Unagi SAST Security Report</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; }
        .header { background: #f5f5f5; padding: 20px; border-radius: 5px; }
        .summary { display: flex; gap: 20px; margin: 20px 0; }
        .stat { background: #e3f2fd; padding: 15px; border-radius: 5px; flex: 1; text-align: center; }
        .vulnerability { border-left: 4px solid #ff9800; margin: 10px 0; padding: 10px; background: #fff3e0; }
        .critical { border-left-color: #f44336; background: #ffebee; }
        .high { border-left-color: #ff9800; background: #fff3e0; }
        .medium { border-left-color: #ff5722; background: #fce4ec; }
        .low { border-left-color: #4caf50; background: #e8f5e9; }
    </style>
</head>
<body>
    <div class="header">
        <h1>🛡️ Unagi SAST Security Report</h1>
        <p>Generated on: ${timestamp}</p>
    </div>
    
    <div class="summary">
        <div class="stat">
            <h3>${results.length}</h3>
            <p>Files Scanned</p>
        </div>
        <div class="stat">
            <h3>${totalVulnerabilities}</h3>
            <p>Issues Found</p>
        </div>
    </div>
    
    ${results.map(result => `
        <h2>📄 ${result.file}</h2>
        <p>Scan Time: ${result.scanTime}ms | Lines: ${result.linesScanned}</p>
        
        ${result.vulnerabilities.length === 0 ? 
          '<p>✅ No security issues found in this file.</p>' :
          result.vulnerabilities.map(vuln => `
            <div class="vulnerability ${vuln.severity}">
                <h4>${vuln.severity.toUpperCase()}: ${vuln.message}</h4>
                <p><strong>Line ${vuln.line}:</strong> ${vuln.description}</p>
                <p><strong>Recommendation:</strong> ${vuln.recommendation}</p>
            </div>
          `).join('')
        }
    `).join('')}
</body>
</html>`;
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

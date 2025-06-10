import * as vscode from 'vscode';
import { ScanResult, Vulnerability, OutputFormat, Severity } from '../types';
import { configManager } from '../config/ConfigurationManager';

export class OutputManager {
  private outputChannel: vscode.OutputChannel;
  private diagnosticCollection: vscode.DiagnosticCollection;
  private statusBarItem: vscode.StatusBarItem;

  constructor() {
    this.outputChannel = vscode.window.createOutputChannel('Unagi SAST');
    this.diagnosticCollection = vscode.languages.createDiagnosticCollection('unagi');
    this.statusBarItem = vscode.window.createStatusBarItem(vscode.StatusBarAlignment.Left, 100);
    this.statusBarItem.show();
  }

  public async displayResults(result: ScanResult): Promise<void> {
    const config = configManager.getScanConfiguration();
    
    // Update status bar
    this.updateStatusBar(result.vulnerabilities.length);
    
    switch (config.outputFormat) {
      case OutputFormat.PROBLEMS_PANEL:
        this.displayInProblemsPanel(result);
        break;
      case OutputFormat.OUTPUT_CHANNEL:
        this.displayInOutputChannel(result);
        break;
      case OutputFormat.INLINE:
        this.displayInline(result);
        break;
      case OutputFormat.REPORT_FILE:
        await this.generateReportFile([result]);
        break;
    }
  }

  public async displayWorkspaceResults(results: ScanResult[]): Promise<void> {
    const totalVulnerabilities = results.reduce((total, result) => total + result.vulnerabilities.length, 0);
    
    // Update status bar
    this.updateStatusBar(totalVulnerabilities);
    
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
    // This would show decorations in the editor
    // Implementation depends on specific requirements
    vscode.window.showInformationMessage(
      `Scan complete: ${result.vulnerabilities.length} issues found`
    );
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

  private updateStatusBar(vulnerabilityCount: number): void {
    if (vulnerabilityCount === 0) {
      this.statusBarItem.text = '🛡️ Unagi: Clean';
      this.statusBarItem.color = undefined;
    } else {
      this.statusBarItem.text = `🚨 Unagi: ${vulnerabilityCount} issues`;
      this.statusBarItem.color = new vscode.ThemeColor('statusBarItem.warningForeground');
    }
    this.statusBarItem.tooltip = `Click to view security issues`;
    this.statusBarItem.command = 'workbench.panel.markers.view.focus';
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
}

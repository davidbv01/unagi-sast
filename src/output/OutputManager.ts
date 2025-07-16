import * as vscode from 'vscode';
import { ScanResult, Severity, DataFlowVulnerability, PatternVulnerability, Source, AnalysisResult, WorkspaceScanResult } from '../types';
import * as fs from 'fs';

const DIAGNOSTIC_COLLECTION_NAME = 'unagi';
const STATUS_BAR_PRIORITY = 100;
const SAST_RESULTS_FILENAME = '/sast-results.json';
const WORKSPACE_RESULTS_FILENAME = '/sast-results.json';

/**
 * Manages output, diagnostics, and reporting for Unagi SAST scans.
 */
export class OutputManager {
  private static diagnosticCollection = vscode.languages.createDiagnosticCollection(DIAGNOSTIC_COLLECTION_NAME);
  private static statusBarItem = vscode.window.createStatusBarItem(vscode.StatusBarAlignment.Left, STATUS_BAR_PRIORITY);
  
  private readonly folderPath: string;
  private readonly filePath: string;

  /**
   * Creates a new OutputManager instance.
   * @param folderPath The folder path for output and reports.
   */
  constructor(folderPath: string) {
    OutputManager.statusBarItem.show();
    this.folderPath = folderPath;
    fs.mkdirSync(this.folderPath, { recursive: true });
    this.filePath = this.folderPath + SAST_RESULTS_FILENAME;
  }

  /**
   * Handles single scan results by displaying diagnostics and saving to file.
   * @param result The scan result to process.
   * @param analysisResult The complete analysis result to save.
   * @returns Promise<boolean> True if saving was successful, false otherwise.
   */
  public async handleScanResults(result: ScanResult, analysisResult: AnalysisResult): Promise<boolean> {
    // Display the results
    OutputManager.diagnosticCollection.clear();
    const allDiagnostics: vscode.Diagnostic[] = [];
    
    // Filter out false positives (isVulnerable: false) before creating diagnostics
    const confirmedPatternVulns = result.patternVulnerabilities.filter(vuln => vuln.isVulnerable);
    const confirmedDataFlowVulns = result.dataFlowVulnerabilities.filter(vuln => vuln.isVulnerable);
    
    confirmedPatternVulns.forEach(vuln => {
      allDiagnostics.push(this.createPatternDiagnostic(vuln));
    });
    
    confirmedDataFlowVulns.forEach(dfv => {
      allDiagnostics.push(this.createDataFlowDiagnostic(dfv));
    });
    
    const uri = vscode.Uri.file(result.file);
    OutputManager.diagnosticCollection.set(uri, allDiagnostics);
    
    // Update result for status bar and inline display (filtered counts)
    const filteredResult = {
      ...result,
      patternVulnerabilities: confirmedPatternVulns,
      dataFlowVulnerabilities: confirmedDataFlowVulns
    };
    
    this.updateStatusBar(filteredResult);
    this.displayInline(filteredResult);

    // Save the analysis result (include ALL vulnerabilities, both confirmed and false positives)
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

  /**
   * Handles workspace scan results by displaying diagnostics and saving to file.
   * @param results The scan results for the workspace.
   */
  public async handleWorkspaceScanResults(results: WorkspaceScanResult[]): Promise<void> {
    try {
      // Filter out false positives from results before processing
      const filteredResults = results.map(result => ({
        ...result,
        patternVulnerabilities: result.patternVulnerabilities.filter(vuln => vuln.isVulnerable),
        dataFlowVulnerabilities: result.dataFlowVulnerabilities.filter(vuln => vuln.isVulnerable)
      }));

      // Save workspace results (include both filtered and original for analysis)
      const workspaceResultsPath = this.folderPath + WORKSPACE_RESULTS_FILENAME;
      const workspaceSummary = {
        timestamp: new Date().toISOString(),
        totalFiles: results.length,
        totalVulnerabilities: filteredResults.reduce((sum, result) =>
          sum + result.patternVulnerabilities.length + result.dataFlowVulnerabilities.length, 0
        ),
        totalScanTime: results.reduce((sum, result) => sum + result.scanTime, 0),
        summary: {
          patternVulnerabilities: filteredResults.reduce((sum, result) => sum + result.patternVulnerabilities.length, 0),
          dataFlowVulnerabilities: filteredResults.reduce((sum, result) => sum + result.dataFlowVulnerabilities.length, 0)
        },
        // Save original results with all vulnerabilities (including false positives) for analysis
        originalResults: results,
        // Save filtered results for display
        filteredResults
      };
      
      fs.writeFileSync(workspaceResultsPath, JSON.stringify(workspaceSummary, null, 2), 'utf8');
      console.log(`📄 Workspace scan results saved to: ${workspaceResultsPath}`);

      // Display workspace results (only confirmed vulnerabilities)
      OutputManager.diagnosticCollection.clear();
      
      // Group diagnostics by file path (only for confirmed vulnerabilities)
      const diagnosticsByFile = new Map<string, vscode.Diagnostic[]>();
      filteredResults.forEach(result => {
        result.patternVulnerabilities.forEach(vuln => {
          const filePath = vuln.filePath;
          if (!diagnosticsByFile.has(filePath)) {
            diagnosticsByFile.set(filePath, []);
          }
          diagnosticsByFile.get(filePath)!.push(this.createPatternDiagnostic(vuln));
        });
        result.dataFlowVulnerabilities.forEach(dfv => {
          const filePath = dfv.filePath;
          if (!diagnosticsByFile.has(filePath)) {
            diagnosticsByFile.set(filePath, []);
          }
          diagnosticsByFile.get(filePath)!.push(this.createDataFlowDiagnostic(dfv));
        });
      });
      // Set diagnostics for each file
      diagnosticsByFile.forEach((diagnostics, filePath) => {
        if (diagnostics.length > 0) {
          const uri = vscode.Uri.file(filePath);
          console.log('[OUTPUT] Setting diagnostics for', uri.fsPath, diagnostics.length);
          OutputManager.diagnosticCollection.set(uri, diagnostics);
        }
      });
      
      console.log(`🔍 Created diagnostics for ${diagnosticsByFile.size} files`);
      this.updateStatusBar(filteredResults);
      
      const totalVulns = workspaceSummary.totalVulnerabilities;
      const originalTotal = results.reduce((sum, result) =>
        sum + result.patternVulnerabilities.length + result.dataFlowVulnerabilities.length, 0
      );
      
      vscode.window.showInformationMessage(
        `Workspace scan results saved. Found ${totalVulns} confirmed vulnerabilities (${originalTotal - totalVulns} false positives filtered out) across ${results.length} files.`
      );
    } catch (error) {
      console.error('[ERROR] Failed to save workspace results:', error);
      vscode.window.showErrorMessage('Failed to save workspace scan results');
    }
  }

  /**
   * Saves the analysis result to a temporary file.
   * @param analysisResult The analysis result to save.
   * @returns True if successful, false otherwise.
   * @deprecated Use handleScanResults() instead for combined display and saving.
   */
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


  /**
   * Opens a webview panel with a formatted HTML security report.
   */
  public async createReport(): Promise<void> {
    if (!fs.existsSync(this.filePath)) {
      vscode.window.showInformationMessage('No analysis report available. Please run a scan first.');
      return;
    }
    let reportData: any;
    try {
      const fileContent = fs.readFileSync(this.filePath, 'utf8');
      reportData = JSON.parse(fileContent);
    } catch (err) {
      vscode.window.showErrorMessage('Failed to read the last analysis result.');
      return;
    }
    
    // Detect type by structure - workspace has 'originalResults' and 'filteredResults'
    let html = '';
    if (reportData.originalResults && reportData.filteredResults) {
      // Workspace report structure - convert to single file format for existing generator
      const workspaceAsAnalysisResult = {
        patternVulnerabilities: reportData.filteredResults.flatMap((result: any) => result.patternVulnerabilities || []),
        dataFlowVulnerabilities: reportData.filteredResults.flatMap((result: any) => result.dataFlowVulnerabilities || [])
      };
      html = this.generateHtmlReport(workspaceAsAnalysisResult);
    } else {
      // Single file report structure
      html = this.generateHtmlReport(reportData);
    }
    
    // Save HTML file to workspace root
    const timestamp = new Date().toISOString().replace(/[:.]/g, '-');
    const htmlFilePath = `${this.folderPath}/unagi-sast-report-${timestamp}.html`;
    
    try {
      fs.writeFileSync(htmlFilePath, html, 'utf8');
      console.log(`📄 HTML report saved to: ${htmlFilePath}`);
      
      // Show success message with options
      const action = await vscode.window.showInformationMessage(
        `✅ HTML report saved successfully!`,
        'Open HTML File',
        'Show in Explorer'
      );
      
      if (action === 'Open HTML File') {
        const uri = vscode.Uri.file(htmlFilePath);
        await vscode.commands.executeCommand('vscode.open', uri);
      } else if (action === 'Show in Explorer') {
        await vscode.commands.executeCommand('revealFileInOS', vscode.Uri.file(htmlFilePath));
      }
      
    } catch (err) {
      console.error('Failed to save HTML report:', err);
      vscode.window.showErrorMessage(`Failed to save HTML report: ${err instanceof Error ? err.message : String(err)}`);
    }
    
    // Show webview as well
    const panel = vscode.window.createWebviewPanel(
      'unagiSastReport',
      'Unagi SAST Report',
      vscode.ViewColumn.One,
      { enableScripts: true }
    );
    panel.webview.html = html;
  }

  /**
   * Disposes all resources held by this manager.
   */
  public dispose(): void {
    OutputManager.diagnosticCollection.dispose();
    OutputManager.statusBarItem.dispose();
  }
  // --- Private helpers ---

  /**
   * Shows a summary message for a scan result.
   * @param result The scan result.
   */
  private displayInline(result: ScanResult): void {
    const summary = `Scan complete: ${result.patternVulnerabilities.length + result.dataFlowVulnerabilities.length} vulnerabilities, ${result.dataFlowVulnerabilities.length} dataflow, ${result.patternVulnerabilities.length} pattern`;
    vscode.window.showInformationMessage(summary);
  }

  /**
   * Updates the status bar with the number of vulnerabilities found.
   * @param result The scan result(s).
   */
  private updateStatusBar(result: ScanResult | ScanResult[] | WorkspaceScanResult[]): void {
    const totalVulnerabilities = Array.isArray(result)
      ? result.reduce((sum, r) => sum + r.patternVulnerabilities.length + r.dataFlowVulnerabilities.length, 0)
      : result.patternVulnerabilities.length + result.dataFlowVulnerabilities.length;
    OutputManager.statusBarItem.text = `$(shield) Unagi: ${totalVulnerabilities} issues`;
    OutputManager.statusBarItem.tooltip = `Found ${totalVulnerabilities} security vulnerabilities`;
  }

  /**
   * Creates a diagnostic for a pattern vulnerability.
   * @param vulnerability The pattern vulnerability.
   */
  private createPatternDiagnostic(vulnerability: PatternVulnerability): vscode.Diagnostic {
    const startLine = vulnerability.line - 1;
    const startColumn = vulnerability.column;
    const endLine = vulnerability.line - 1;
    const endColumn = vulnerability.column;
    const range = new vscode.Range(startLine, startColumn, endLine, endColumn);
    const diagnostic = new vscode.Diagnostic(
      range,
      vulnerability.message,
      this.getSeverity(vulnerability.severity)
    );
    diagnostic.source = 'Unagi SAST - Pattern';
    diagnostic.code = vulnerability.type;
    return diagnostic;
  }

  /**
   * Creates a diagnostic for a data flow vulnerability.
   * @param dfv The data flow vulnerability.
   */
  private createDataFlowDiagnostic(dfv: DataFlowVulnerability): vscode.Diagnostic {
    const startLine = dfv.sink.loc.start.line - 1;
    const startColumn = dfv.sink.loc.start.column;
    const endLine = dfv.sink.loc.end.line - 1;
    const endColumn = dfv.sink.loc.end.column;
    const range = new vscode.Range(startLine, startColumn, endLine, endColumn);
    const diagnostic = new vscode.Diagnostic(
      range,
      dfv.message,
      this.getSeverity(dfv.severity)
    );
    diagnostic.source = 'Unagi SAST - DataFlow';
    diagnostic.code = dfv.type;
    const relatedInfo: vscode.DiagnosticRelatedInformation[] = [];
    if (dfv.sources && dfv.sources.length > 0) {
      for (const src of dfv.sources) {
        if (src.loc) {
          relatedInfo.push(new vscode.DiagnosticRelatedInformation(
            new vscode.Location(
              vscode.Uri.file(src.filePath),
              new vscode.Range(
                new vscode.Position(src.loc.start.line - 1, src.loc.start.column),
                new vscode.Position(src.loc.end.line - 1, src.loc.end.column)
              )
            ),
            `Source: ${src.description || src.id}`
          ));
        }
      }
    }
    if (dfv.sink && dfv.sink.loc) {
      const sinkLoc = dfv.sink.loc;
      relatedInfo.push(new vscode.DiagnosticRelatedInformation(
        new vscode.Location(
          vscode.Uri.file(dfv.filePath),
          new vscode.Range(
            sinkLoc.start.line - 1,
            sinkLoc.start.column,
            sinkLoc.end.line - 1,
            sinkLoc.end.column
          )
        ),
        `Sink: ${dfv.sink.description}`
      ));
    }
    if (dfv.sanitizers && dfv.sanitizers.length > 0) {
      dfv.sanitizers.forEach(san => {
        if (san.loc) {
          relatedInfo.push(new vscode.DiagnosticRelatedInformation(
            new vscode.Location(
              vscode.Uri.file(dfv.filePath),
              new vscode.Range(
                san.loc.start.line - 1,
                san.loc.start.column,
                san.loc.end.line - 1,
                san.loc.end.column
              )
            ),
            `Sanitizer: ${san.description}`
          ));
        }
      });
    }
    if (relatedInfo.length > 0) {
      diagnostic.relatedInformation = relatedInfo;
    }
    return diagnostic;
  }

  /**
   * Maps a custom severity to a VSCode diagnostic severity.
   * @param severity The custom severity.
   */
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

  /**
   * Generates an HTML report for the given analysis result.
   * @param analysisResult The analysis result to report.
   */
  private generateHtmlReport(analysisResult: AnalysisResult): string {
    const { patternVulnerabilities, dataFlowVulnerabilities } = analysisResult;
    
    // Filter confirmed vulnerabilities (isVulnerable: true)
    const confirmedPatternVulns = patternVulnerabilities.filter(vuln => vuln.isVulnerable);
    const confirmedDataFlowVulns = dataFlowVulnerabilities.filter(vuln => vuln.isVulnerable);
    
    // Filter false positives (isVulnerable: false)
    const falsePositivePatternVulns = patternVulnerabilities.filter(vuln => !vuln.isVulnerable);
    const falsePositiveDataFlowVulns = dataFlowVulnerabilities.filter(vuln => !vuln.isVulnerable);
    
    // Confirmed vulnerabilities for main report
    const confirmedVulnerabilities = [
      ...confirmedPatternVulns.map(pv => ({
        id: pv.id,
        type: pv.type,
        severity: pv.severity,
        message: pv.message,
        file: pv.filePath,
        line: pv.line,
        column: pv.column,
        rule: pv.rule,
        description: pv.description,
        recommendation: pv.recommendation,
        ai: pv.ai,
        isVulnerable: pv.isVulnerable
      })),
      ...confirmedDataFlowVulns.map(dfv => ({
        id: dfv.id,
        type: dfv.type,
        severity: dfv.severity,
        message: dfv.message,
        file: dfv.filePath,
        line: dfv.sink?.loc?.start?.line ?? 0,
        column: dfv.sink?.loc?.start?.column ?? 0,
        rule: dfv.rule,
        description: dfv.description,
        recommendation: dfv.recommendation,
        ai: dfv.ai,
        isVulnerable: dfv.isVulnerable
      }))
    ];
    
    // False positives for separate section
    const falsePositives = [
      ...falsePositivePatternVulns.map(pv => ({
        id: pv.id,
        type: pv.type,
        severity: pv.severity,
        message: pv.message,
        file: pv.filePath,
        line: pv.line,
        column: pv.column,
        rule: pv.rule,
        description: pv.description,
        recommendation: pv.recommendation,
        ai: pv.ai,
        isVulnerable: pv.isVulnerable
      })),
      ...falsePositiveDataFlowVulns.map(dfv => ({
        id: dfv.id,
        type: dfv.type,
        severity: dfv.severity,
        message: dfv.message,
        file: dfv.filePath,
        line: dfv.sink?.loc?.start?.line ?? 0,
        column: dfv.sink?.loc?.start?.column ?? 0,
        rule: dfv.rule,
        description: dfv.description,
        recommendation: dfv.recommendation,
        ai: dfv.ai,
        isVulnerable: dfv.isVulnerable
      }))
    ];
    const sources = confirmedDataFlowVulns.map(dfv => dfv.sources[0]);
    const sinks = confirmedDataFlowVulns.map(dfv => dfv.sink);
    const sanitizers = confirmedDataFlowVulns.flatMap(dfv => dfv.sanitizers);
    return `
      <!DOCTYPE html>
      <html lang="en">
      <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>Unagi SAST Security Report</title>
        <style>
          * { box-sizing: border-box; }
          body { 
            font-family: 'Segoe UI', -apple-system, BlinkMacSystemFont, sans-serif; 
            background: #f5f7fa; 
            color: #2d3748; 
            margin: 0; 
            padding: 20px;
            line-height: 1.6;
          }
          .container { 
            max-width: 1200px; 
            margin: 0 auto; 
            background: white; 
            border-radius: 8px; 
            box-shadow: 0 4px 6px rgba(0,0,0,0.07); 
            overflow: hidden;
          }
          .header {
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 40px;
            text-align: center;
          }
          h1 { 
            margin: 0 0 10px 0;
            font-size: 2.5rem;
            font-weight: 600;
          }
          .subtitle {
            opacity: 0.9;
            font-size: 1.1rem;
            margin: 0;
          }
          .stats-section {
            padding: 30px 40px;
            background: #f8fafc;
            border-bottom: 1px solid #e2e8f0;
          }
          .stats-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 20px;
          }
          .stat-card {
            background: white;
            padding: 20px;
            border-radius: 8px;
            border: 1px solid #e2e8f0;
            text-align: center;
          }
          .stat-number {
            font-size: 2rem;
            font-weight: 700;
            color: #667eea;
            margin-bottom: 5px;
          }
          .stat-label {
            color: #64748b;
            font-size: 0.9rem;
            text-transform: uppercase;
            letter-spacing: 0.5px;
          }
          .content {
            padding: 40px;
          }
          .section { 
            margin-bottom: 40px;
          }
          .section-title {
            font-size: 1.5rem;
            font-weight: 600;
            color: #1a202c;
            margin-bottom: 20px;
            padding-bottom: 10px;
            border-bottom: 2px solid #e2e8f0;
          }
          .vulnerability-card {
            background: white;
            border: 1px solid #e2e8f0;
            border-radius: 8px;
            margin-bottom: 20px;
            overflow: hidden;
          }
          .vulnerability-header {
            padding: 20px;
            background: #f8fafc;
            border-bottom: 1px solid #e2e8f0;
            display: flex;
            justify-content: space-between;
            align-items: center;
            flex-wrap: wrap;
            gap: 10px;
          }
          .vulnerability-title {
            font-weight: 600;
            font-size: 1.1rem;
            color: #1a202c;
          }
          .vulnerability-meta {
            display: flex;
            gap: 10px;
            align-items: center;
            flex-wrap: wrap;
          }
          .badge {
            padding: 4px 12px;
            border-radius: 20px;
            font-size: 0.75rem;
            font-weight: 600;
            text-transform: uppercase;
            letter-spacing: 0.5px;
          }
          .badge-critical { background: #fed7d7; color: #c53030; }
          .badge-high { background: #feebc8; color: #dd6b20; }
          .badge-medium { background: #fefcbf; color: #d69e2e; }
          .badge-low { background: #c6f6d5; color: #38a169; }
          .badge-info { background: #bee3f8; color: #3182ce; }
          .line-badge {
            background: #edf2f7;
            color: #4a5568;
            padding: 2px 8px;
            border-radius: 4px;
            font-family: 'Monaco', 'Menlo', monospace;
            font-size: 0.8rem;
          }
          .vulnerability-body {
            padding: 20px;
          }
          .field {
            margin-bottom: 15px;
          }
          .field-label {
            font-weight: 600;
            color: #4a5568;
            margin-bottom: 5px;
            font-size: 0.9rem;
            text-transform: uppercase;
            letter-spacing: 0.5px;
          }
          .field-value {
            color: #2d3748;
            word-wrap: break-word;
            overflow-wrap: break-word;
          }
          .ai-section {
            background: #f7fafc;
            padding: 15px;
            border-radius: 6px;
            margin-top: 15px;
            border-left: 4px solid #667eea;
          }
          .ai-confidence {
            font-weight: 600;
            color: #667eea;
          }
          .no-data {
            text-align: center;
            color: #64748b;
            padding: 60px 20px;
            background: #f8fafc;
            border-radius: 8px;
            border: 2px dashed #cbd5e0;
          }
          .no-data-icon {
            font-size: 3rem;
            margin-bottom: 15px;
            opacity: 0.5;
          }
          .false-positive {
            opacity: 0.8;
            background: #f7fafc;
          }
          .false-positive .vulnerability-header {
            background: #edf2f7;
          }
          .metadata-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 20px;
            margin-top: 20px;
          }
          .metadata-card {
            background: #f8fafc;
            padding: 15px;
            border-radius: 6px;
            border: 1px solid #e2e8f0;
          }
          .footer {
            background: #f8fafc;
            padding: 30px 40px;
            text-align: center;
            color: #64748b;
            border-top: 1px solid #e2e8f0;
          }
          @media (max-width: 768px) {
            .container { margin: 10px; }
            .header, .content { padding: 20px; }
            .stats-section { padding: 20px; }
            .vulnerability-header { flex-direction: column; align-items: flex-start; }
            .vulnerability-meta { justify-content: flex-start; }
            .stats-grid { grid-template-columns: repeat(2, 1fr); }
          }
        </style>
      </head>
      <body>
        <div class="container">
          <div class="header">
            <h1>🛡️ Security Analysis Report</h1>
            <p class="subtitle">Unagi SAST • Comprehensive Security Assessment</p>
          </div>
          
          <div class="stats-section">
            <div class="stats-grid">
              <div class="stat-card">
                <div class="stat-number">${confirmedVulnerabilities.length}</div>
                <div class="stat-label">Confirmed Issues</div>
              </div>
              <div class="stat-card">
                <div class="stat-number">${falsePositives.length}</div>
                <div class="stat-label">False Positives</div>
              </div>
              <div class="stat-card">
                <div class="stat-number">${sources.length}</div>
                <div class="stat-label">Data Sources</div>
              </div>
              <div class="stat-card">
                <div class="stat-number">${sinks.length}</div>
                <div class="stat-label">Vulnerability Sinks</div>
              </div>
            </div>
          </div>

          <div class="content">
          <div class="section">
              <h2 class="section-title">🚨 Security Vulnerabilities</h2>
              ${confirmedVulnerabilities.length === 0 ? `
                <div class="no-data">
                  <div class="no-data-icon">✅</div>
                  <h3>No security vulnerabilities detected</h3>
                  <p>Your code appears to be secure based on our analysis.</p>
                </div>
              ` : confirmedVulnerabilities.map((vuln: any) => {
                const severityClass = vuln.severity ? vuln.severity.toLowerCase() : 'info';
                  return `
                  <div class="vulnerability-card">
                    <div class="vulnerability-header">
                      <div class="vulnerability-title">${vuln.type || 'Security Issue'}</div>
                      <div class="vulnerability-meta">
                        <span class="badge badge-${severityClass}">${vuln.severity || 'Info'}</span>
                        ${vuln.line ? `<span class="line-badge">Line ${vuln.line}</span>` : ''}
                      </div>
                    </div>
                    <div class="vulnerability-body">
                      ${vuln.file || vuln.line ? `
                        <div class="field">
                          <div class="field-label">Location</div>
                          <div class="field-value">
                            ${vuln.file ? `<strong>File:</strong> ${vuln.file.replace(/\\/g, '/')}` : ''}
                            ${vuln.file && vuln.line ? '<br>' : ''}
                            ${vuln.line ? `<strong>Line:</strong> ${vuln.line}` : ''}
                            ${vuln.column ? `, <strong>Column:</strong> ${vuln.column}` : ''}
                          </div>
                        </div>
                      ` : ''}

                      ${vuln.message ? `
                        <div class="field">
                          <div class="field-label">Detection Message</div>
                          <div class="field-value">${vuln.message}</div>
                        </div>
                      ` : ''}
                      
                      ${vuln.description ? `
                        <div class="field">
                          <div class="field-label">Description</div>
                          <div class="field-value">${vuln.description}</div>
                        </div>
                      ` : ''}

                      ${vuln.ai && (vuln.ai.confidenceScore !== undefined || vuln.ai.shortExplanation || vuln.ai.remediation) ? `
                        <div class="ai-section">
                          <div class="field-label" style="margin-bottom: 10px;">🤖 AI Analysis</div>
                          
                          ${vuln.ai.confidenceScore !== undefined ? `
                            <div class="field">
                              <div class="field-label">Confidence Score</div>
                              <div class="field-value ai-confidence">${(vuln.ai.confidenceScore * 100).toFixed(0)}%</div>
                            </div>
                          ` : ''}
                          
                          ${vuln.ai.shortExplanation ? `
                            <div class="field">
                              <div class="field-label">AI Explanation</div>
                              <div class="field-value">${vuln.ai.shortExplanation}</div>
                            </div>
                          ` : ''}
                          
                          ${vuln.ai.remediation ? `
                            <div class="field">
                              <div class="field-label">Recommended Fix</div>
                              <div class="field-value">${vuln.ai.remediation}</div>
                            </div>
                          ` : ''}
                        </div>
                      ` : ''}
                    </div>
                  </div>
                  `;
                }).join('')}
          </div>

            ${falsePositives.length > 0 ? `
          <div class="section">
                <h2 class="section-title">🔍 False Positives</h2>
                <p style="color: #64748b; margin-bottom: 20px; font-style: italic;">
                  These potential issues were flagged by pattern analysis but determined to be false positives by AI verification.
                </p>
                ${falsePositives.map((vuln: any) => {
                  const severityClass = vuln.severity ? vuln.severity.toLowerCase() : 'info';
                  return `
                    <div class="vulnerability-card false-positive">
                      <div class="vulnerability-header">
                        <div class="vulnerability-title">${vuln.type || 'Potential Issue'}</div>
                        <div class="vulnerability-meta">
                          <span class="badge badge-${severityClass}">${vuln.severity || 'Info'}</span>
                          ${vuln.line ? `<span class="line-badge">Line ${vuln.line}</span>` : ''}
                        </div>
                      </div>
                      <div class="vulnerability-body">
                        ${vuln.file || vuln.line ? `
                          <div class="field">
                            <div class="field-label">Location</div>
                            <div class="field-value">
                              ${vuln.file ? `<strong>File:</strong> ${vuln.file.replace(/\\/g, '/')}` : ''}
                              ${vuln.file && vuln.line ? '<br>' : ''}
                              ${vuln.line ? `<strong>Line:</strong> ${vuln.line}` : ''}
                              ${vuln.column ? `, <strong>Column:</strong> ${vuln.column}` : ''}
                            </div>
                          </div>
                        ` : ''}

                        ${vuln.message ? `
                          <div class="field">
                            <div class="field-label">Detection Message</div>
                            <div class="field-value">${vuln.message}</div>
                          </div>
                        ` : ''}
                        
                        ${vuln.ai && vuln.ai.shortExplanation ? `
                          <div class="ai-section">
                            <div class="field">
                              <div class="field-label">🤖 Why This is a False Positive</div>
                              <div class="field-value">${vuln.ai.shortExplanation}</div>
                            </div>
                          </div>
                        ` : ''}
                      </div>
                    </div>
                  `;
                }).join('')}
          </div>
            ` : ''}

            ${sources.length > 0 || sinks.length > 0 || sanitizers.length > 0 ? `
          <div class="section">
                <h2 class="section-title">📋 Technical Details</h2>
                <div class="metadata-grid">
                  ${sources.length > 0 ? `
                    <div class="metadata-card">
                      <h4 style="margin: 0 0 15px 0; color: #4a5568;">📥 Data Sources (${sources.length})</h4>
                      ${sources.slice(0, 5).map((src: any) => `
                        <div style="margin-bottom: 10px; padding: 8px; background: white; border-radius: 4px; border: 1px solid #e2e8f0;">
                          <div style="font-weight: 600; font-size: 0.9rem;">${src.type || 'Unknown'}</div>
                          <div style="font-size: 0.8rem; color: #64748b;">${src.description || '-'}</div>
                          ${src.line ? `<div style="font-size: 0.75rem; color: #9ca3af;">Line ${src.line}</div>` : ''}
                        </div>
                      `).join('')}
                      ${sources.length > 5 ? `<div style="font-size: 0.8rem; color: #64748b; text-align: center; margin-top: 10px;">... and ${sources.length - 5} more</div>` : ''}
                    </div>
                  ` : ''}
                  
                  ${sinks.length > 0 ? `
                    <div class="metadata-card">
                      <h4 style="margin: 0 0 15px 0; color: #4a5568;">📤 Vulnerability Sinks (${sinks.length})</h4>
                      ${sinks.slice(0, 5).map((sink: any) => `
                        <div style="margin-bottom: 10px; padding: 8px; background: white; border-radius: 4px; border: 1px solid #e2e8f0;">
                          <div style="font-weight: 600; font-size: 0.9rem;">${sink.vulnerabilityType || sink.type || 'Unknown'}</div>
                          <div style="font-size: 0.8rem; color: #64748b;">${sink.description || '-'}</div>
                          ${sink.line ? `<div style="font-size: 0.75rem; color: #9ca3af;">Line ${sink.line}</div>` : ''}
                        </div>
                `).join('')}
                      ${sinks.length > 5 ? `<div style="font-size: 0.8rem; color: #64748b; text-align: center; margin-top: 10px;">... and ${sinks.length - 5} more</div>` : ''}
                    </div>
                  ` : ''}

                  ${sanitizers.length > 0 ? `
                    <div class="metadata-card">
                      <h4 style="margin: 0 0 15px 0; color: #4a5568;">🧼 Sanitizers (${sanitizers.length})</h4>
                      ${sanitizers.slice(0, 5).map((san: any) => `
                        <div style="margin-bottom: 10px; padding: 8px; background: white; border-radius: 4px; border: 1px solid #e2e8f0;">
                          <div style="font-weight: 600; font-size: 0.9rem;">${san.type || 'Unknown'}</div>
                          <div style="font-size: 0.8rem; color: #64748b;">${san.description || '-'}</div>
                          ${san.effectiveness !== undefined ? `<div style="font-size: 0.75rem; color: #38a169;">Effectiveness: ${(san.effectiveness * 100).toFixed(0)}%</div>` : ''}
          </div>
                `).join('')}
                      ${sanitizers.length > 5 ? `<div style="font-size: 0.8rem; color: #64748b; text-align: center; margin-top: 10px;">... and ${sanitizers.length - 5} more</div>` : ''}
                    </div>
                  ` : ''}
                </div>
              </div>
            ` : ''}
          </div>

          <div class="footer">
            <p><strong>Unagi SAST</strong> • Security Analysis Report</p>
            <p>Generated on ${new Date().toLocaleString()}</p>
          </div>
        </div>
      </body>
      </html>
    `;
  }
}
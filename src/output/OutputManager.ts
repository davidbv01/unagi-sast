import * as vscode from 'vscode';
import { ScanResult, Severity, DataFlowVulnerability, PatternVulnerability, Source, AnalysisResult, WorkspaceScanResult } from '../types';
import * as fs from 'fs';

const DIAGNOSTIC_COLLECTION_NAME = 'unagi';
const STATUS_BAR_PRIORITY = 100;
const SAST_RESULTS_FILENAME = '/sast-results.json';
const WORKSPACE_RESULTS_FILENAME = '/workspace-scan-results.json';

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
      ...confirmedPatternVulns,
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
      ...falsePositivePatternVulns,
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
          .false-positive { opacity: 0.6; background: #2a2a2a; }
        </style>
      </head>
      <body>
        <div class="container">
          <h1>Unagi SAST Security Report</h1>
          <div class="section">
            <h2>Confirmed Vulnerabilities (${confirmedVulnerabilities.length})</h2>
            ${confirmedVulnerabilities.length === 0 ? '<p>No confirmed vulnerabilities found.</p>' : `
              <table>
                <tr><th>Type</th><th>Severity</th><th>Message</th><th>Line</th><th>Description</th><th>AI Confidence</th><th>AI Explanation</th><th>AI Exploit Example</th><th>AI Remediation</th></tr>
                ${confirmedVulnerabilities.map((vuln: any) => {
                  const sourcesText = vuln.sources ? vuln.sources.map((s: Source) => s.description || s.id).join(', ') : '';
                  return `
                    <tr>
                      <td>${vuln.type}</td>
                      <td class="severity-${vuln.severity ? vuln.severity.toLowerCase() : 'info'}">${vuln.severity ?? ''}</td>
                      <td>${vuln.message}</td>
                      <td>${vuln.line ?? ''}</td>
                      <td>${vuln.description ?? ''}</td>
                      <td>${vuln.ai && vuln.ai.confidenceScore !== undefined ? (vuln.ai.confidenceScore * 100).toFixed(0) + '%' : '-'}</td>
                      <td>${vuln.ai && vuln.ai.shortExplanation ? vuln.ai.shortExplanation : '-'}</td>
                      <td>${vuln.ai && vuln.ai.exploitExample ? vuln.ai.exploitExample : '-'}</td>
                      <td>${vuln.ai && vuln.ai.remediation ? vuln.ai.remediation : '-'}</td>
                    </tr>
                  `;
                }).join('')}
              </table>
            `}
          </div>
          <div class="section">
            <h2>False Positives (${falsePositives.length})</h2>
            ${falsePositives.length === 0 ? '<p>No false positives detected.</p>' : `
              <p><em>These vulnerabilities were flagged by pattern/data flow analysis but identified as false positives by AI analysis:</em></p>
              <table class="false-positive">
                <tr><th>Type</th><th>Severity</th><th>Message</th><th>Line</th><th>Description</th><th>AI Confidence</th><th>AI Explanation</th><th>AI Exploit Example</th><th>AI Remediation</th></tr>
                ${falsePositives.map((vuln: any) => {
                  const sourcesText = vuln.sources ? vuln.sources.map((s: Source) => s.description || s.id).join(', ') : '';
                  return `
                    <tr>
                      <td>${vuln.type}</td>
                      <td class="severity-${vuln.severity ? vuln.severity.toLowerCase() : 'info'}">${vuln.severity ?? ''}</td>
                      <td>${vuln.message}</td>
                      <td>${vuln.line ?? ''}</td>
                      <td>${vuln.description ?? ''}</td>
                      <td>${vuln.ai && vuln.ai.confidenceScore !== undefined ? (vuln.ai.confidenceScore * 100).toFixed(0) + '%' : '-'}</td>
                      <td>${vuln.ai && vuln.ai.shortExplanation ? vuln.ai.shortExplanation : '-'}</td>
                      <td>${vuln.ai && vuln.ai.exploitExample ? vuln.ai.exploitExample : '-'}</td>
                      <td>${vuln.ai && vuln.ai.remediation ? vuln.ai.remediation : '-'}</td>
                    </tr>
                  `;
                }).join('')}
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
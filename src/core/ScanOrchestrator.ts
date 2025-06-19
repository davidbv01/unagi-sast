import * as vscode from 'vscode';
import { Vulnerability, ScanResult } from '../types';
import { SecurityRuleEngine, AnalysisResult } from '../rules/SecurityRuleEngine';
import { OutputManager } from '../output/OutputManager';
import { ASTParser } from '../parser/ASTParser';
import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';

export class ScanOrchestrator {
  private ruleEngine: SecurityRuleEngine;
  private outputManager: OutputManager;
  private astParser: ASTParser;
  private lastAnalysisResultTempFilePath: string | null = null;

  constructor(outputManager: OutputManager, apiKey: string) {
    this.ruleEngine = new SecurityRuleEngine(apiKey);
    this.outputManager = outputManager;
    this.astParser = new ASTParser();
  }

  public async scanFile(document: vscode.TextDocument): Promise<ScanResult> {
    const startTime = Date.now();
    const content = document.getText();
    const lines = content.split('\n');
    
    try {
      
      // Parse content into AST
      let ast;
      try {
        ast = this.astParser.parse(content, document.languageId, document.fileName);
        if (!ast) {
          throw new Error('AST parser returned null or undefined');
        }
      } catch (error) {
        console.error('[ERROR] Failed to parse file into AST:', {
          file: document.fileName,
          language: document.languageId,
          error: error instanceof Error ? error.message : 'Unknown error',
          stack: error instanceof Error ? error.stack : undefined
        });
        vscode.window.showErrorMessage(
          `Failed to parse ${document.fileName}: ${error instanceof Error ? error.message : 'Unknown error'}`
        );
        return this.createScanResult(document, { vulnerabilities: [], sources: [], sinks: [], sanitizers: [] }, startTime, lines.length);
      }
      
      let vulnerabilities: Vulnerability[] = [];
      let analysisResult: AnalysisResult | null = null;
      
      if (ast) {
        try {
          analysisResult = await this.ruleEngine.analyzeFile(ast, document.languageId, document.fileName, content);
          vulnerabilities = analysisResult.vulnerabilities;
          // Save analysisResult to temp file and log the path
          if (analysisResult) {
            const tempFilePath = await this.saveAnalysisResultToTempFile(analysisResult);
          }
        } catch (error) {
          console.error('[ERROR] Failed to analyze AST:', error);
          vscode.window.showErrorMessage(`Failed to analyze file: ${document.fileName}`);
        }
      } else {
        vscode.window.showWarningMessage(`Could not parse file into AST: ${document.fileName}`);
      }
      
      const result = this.createScanResult(document, analysisResult || { vulnerabilities: [], sources: [], sinks: [], sanitizers: [] }, startTime, lines.length);
      
      try {
        await this.outputManager.displayResults(result);
      } catch (error) {
        vscode.window.showErrorMessage('Failed to display scan results');
      }

      return result;
    } catch (error) {
      vscode.window.showErrorMessage(`Scan failed for file: ${document.fileName}`);
      return this.createScanResult(document, { vulnerabilities: [], sources: [], sinks: [], sanitizers: [] }, startTime, lines.length);
    }
  }

  private createScanResult(document: vscode.TextDocument, analysisResult: AnalysisResult, startTime: number, linesScanned: number): ScanResult {
    return {
      file: document.fileName,
      vulnerabilities: analysisResult.vulnerabilities,
      sources: analysisResult.sources,
      sinks: analysisResult.sinks,
      sanitizers: analysisResult.sanitizers,
      scanTime: Date.now() - startTime,
      linesScanned,
      language: document.languageId
    };
  }

  public clearResults(): void {
    this.outputManager.clearResults();
  }

  /**
   * Saves the provided analysisResult to a temp file as JSON.
   * Returns the path to the temp file.
   */
  public async saveAnalysisResultToTempFile(analysisResult: AnalysisResult): Promise<string> {
    const tempDir = os.tmpdir();
    const fileName = `unagi-analysis-${Date.now()}-${Math.random().toString(36).substring(2, 10)}.json`;
    const filePath = path.join(tempDir, fileName);
    return new Promise((resolve, reject) => {
      fs.writeFile(filePath, JSON.stringify(analysisResult, null, 2), 'utf8', (err) => {
        if (err) {
          console.error('[ERROR] Failed to write analysis result to temp file:', err);
          reject(err);
        } else {
          this.lastAnalysisResultTempFilePath = filePath;
          resolve(filePath);
        }
      });
    });
  }

  /**
   * Creates a styled HTML report from the last analysis result and shows it in a VSCode WebviewPanel.
   * If no last result exists, shows a message in the IDE.
   */
  public async createReport(): Promise<void> {
    if (!this.lastAnalysisResultTempFilePath || !fs.existsSync(this.lastAnalysisResultTempFilePath)) {
      vscode.window.showInformationMessage('No analysis report available. Please run a scan first.');
      return;
    }
    let analysisResult: AnalysisResult;
    try {
      const fileContent = fs.readFileSync(this.lastAnalysisResultTempFilePath, 'utf8');
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
   * Generates a styled HTML report from the analysis result.
   */
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
                    <td class="severity-${vuln.severity.toLowerCase()}">${vuln.severity}</td>
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
              <ul>${sources.map(src => `<li>${src}</li>`).join('')}</ul>
            `}
          </div>
          <div class="section">
            <h2>Sinks (${sinks.length})</h2>
            ${sinks.length === 0 ? '<p>No sinks found.</p>' : `
              <ul>${sinks.map(sink => `<li>${sink}</li>`).join('')}</ul>
            `}
          </div>
          <div class="section">
            <h2>Sanitizers (${sanitizers.length})</h2>
            ${sanitizers.length === 0 ? '<p>No sanitizers found.</p>' : `
              <ul>${sanitizers.map(san => `<li>${san}</li>`).join('')}</ul>
            `}
          </div>
        </div>
      </body>
      </html>
    `;
  }
} 
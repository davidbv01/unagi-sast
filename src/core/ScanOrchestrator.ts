import * as vscode from 'vscode';
import { ScanResult, AstNode, AnalysisResult } from '../types';
import { SecurityRuleEngine } from '../rules/SecurityRuleEngine';
import { OutputManager } from '../output/OutputManager';
import { ASTParser } from '../parser/ASTParser';

/**
 * Orchestrates the scanning and analysis of a single file for security vulnerabilities.
 */
export class ScanOrchestrator {
  /** The security rule engine used for analysis. */
  public readonly ruleEngine: SecurityRuleEngine;
  private readonly outputManager: OutputManager;
  private readonly parser: ASTParser;

  /**
   * Creates a new ScanOrchestrator instance.
   * @param outputManager The output manager for reporting results.
   * @param apiKey The OpenAI API key for AI-powered features.
   */
  constructor(outputManager: OutputManager, apiKey: string) {
    this.ruleEngine = new SecurityRuleEngine(apiKey);
    this.outputManager = outputManager;
    this.parser = new ASTParser();
  }

  /**
   * Runs security analysis on a single document.
   * @param document The VS Code document to analyze.
   * @returns Promise resolving to scan results.
   */
  public async run(document: vscode.TextDocument): Promise<ScanResult> {
    const startTime = Date.now();
    const content = document.getText();
    const linesScanned = content.split('\n').length;
    console.log(`🔍 Starting scan for: ${document.fileName}`);
    try {
      // Step 1: Parse the document into an AST
      const ast = await this.parseDocument(document, content);
      if (!ast) {
        return this.createEmptyScanResult(document, startTime, linesScanned);
      }
      // Step 2: Perform security analysis
      const analysisResult = await this.performSecurityAnalysis(ast, document, content);
      // Step 3: Create and handle results (display and save)
      const scanResult = this.createScanResult(document, analysisResult, startTime, linesScanned);
      await this.handleScanResults(scanResult, analysisResult);
      console.log(`✅ Scan completed for: ${document.fileName} (${scanResult.scanTime}ms)`);
      return scanResult;
    } catch (error) {
      const errorMessage = `Scan failed for file: ${document.fileName}`;
      console.error(errorMessage, error);
      vscode.window.showErrorMessage(errorMessage);
      return this.createEmptyScanResult(document, startTime, linesScanned);
    }
  }

  // --- Private helpers ---

  /**
   * Parses the document content into an Abstract Syntax Tree.
   * @param document The VS Code document.
   * @param content The document content.
   * @returns The parsed AST or undefined if parsing failed.
   */
  private async parseDocument(document: vscode.TextDocument, content: string): Promise<AstNode | undefined> {
    try {
      console.log(`📄 Parsing document: ${document.fileName}`);
      const ast = this.parser.parse(content, document.languageId, document.fileName);
      if (!ast) {
        vscode.window.showWarningMessage(`Could not parse file into AST: ${document.fileName}`);
        return undefined;
      }
      console.log(`✅ Successfully parsed: ${document.fileName}`);
      return ast;
    } catch (error) {
      const errorMsg = error instanceof Error ? error.message : 'Unknown parsing error';
      const fullMessage = `Failed to parse ${document.fileName}: ${errorMsg}`;
      console.error(fullMessage, error);
      vscode.window.showErrorMessage(fullMessage);
      return undefined;
    }
  }

  /**
   * Performs security analysis on the parsed AST.
   * @param ast The Abstract Syntax Tree to analyze.
   * @param document The VS Code document.
   * @param content The document content.
   * @returns Analysis results.
   */
  private async performSecurityAnalysis(
    ast: AstNode,
    document: vscode.TextDocument,
    content: string
  ): Promise<AnalysisResult> {
    try {
      console.log(`🔍 Analyzing security for: ${document.fileName}`);
      const analysisResult = await this.ruleEngine.analyzeFile(
        ast,
        document.languageId,
        document.fileName,
        content
      );
      console.log(`✅ Security analysis completed for: ${document.fileName}`);
      return analysisResult;
    } catch (error) {
      const errorMessage = `Failed to analyze file: ${document.fileName}`;
      console.error(errorMessage, error);
      vscode.window.showErrorMessage(errorMessage);
      return { patternVulnerabilities: [], dataFlowVulnerabilities: [] };
    }
  }

  /**
   * Handles scan results by displaying and saving them.
   * @param scanResult The scan results to handle.
   * @param analysisResult The analysis results to save.
   */
  private async handleScanResults(scanResult: ScanResult, analysisResult: AnalysisResult): Promise<void> {
    try {
      const success = await this.outputManager.handleScanResults(scanResult, analysisResult);
      if (success) {
        console.log(`📊 Handled scan results for: ${scanResult.file}`);
      } else {
        console.warn(`⚠️ Failed to save analysis results for ${scanResult.file}`);
      }
    } catch (error) {
      console.error(`Failed to handle scan results for ${scanResult.file}:`, error);
      vscode.window.showErrorMessage('Failed to handle scan results');
    }
  }

  /**
   * Creates a scan result with analysis data.
   * @param document The scanned document.
   * @param analysisResult The analysis results.
   * @param startTime When the scan started.
   * @param linesScanned Number of lines scanned.
   * @returns Complete scan result.
   */
  private createScanResult(
    document: vscode.TextDocument,
    analysisResult: AnalysisResult,
    startTime: number,
    linesScanned: number
  ): ScanResult {
    return {
      file: document.fileName,
      patternVulnerabilities: analysisResult.patternVulnerabilities,
      dataFlowVulnerabilities: analysisResult.dataFlowVulnerabilities,
      scanTime: Date.now() - startTime,
      linesScanned,
      language: document.languageId
    };
  }

  /**
   * Creates an empty scan result for failed scans.
   * @param document The document that failed to scan.
   * @param startTime When the scan started.
   * @param linesScanned Number of lines in the document.
   * @returns Empty scan result.
   */
  private createEmptyScanResult(
    document: vscode.TextDocument,
    startTime: number,
    linesScanned: number
  ): ScanResult {
    return this.createScanResult(
      document,
      { patternVulnerabilities: [], dataFlowVulnerabilities: [] },
      startTime,
      linesScanned
    );
  }
} 
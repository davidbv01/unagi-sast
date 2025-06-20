import * as vscode from 'vscode';
import { Vulnerability, ScanResult } from '../types';
import { SecurityRuleEngine, AnalysisResult } from '../rules/SecurityRuleEngine';
import { OutputManager } from '../output/OutputManager';
import { ASTParser } from '../parser/ASTParser';

export class ScanOrchestrator {
  public ruleEngine: SecurityRuleEngine;
  private outputManager: OutputManager;
  private astParser: ASTParser;

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
          await this.outputManager.saveAnalysisResultToTempFile(analysisResult);
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
} 
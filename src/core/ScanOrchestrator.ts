import * as vscode from 'vscode';
import { Vulnerability, ScanResult } from '../types';
import { SecurityRuleEngine, AnalysisResult } from '../rules/SecurityRuleEngine';
import { OutputManager } from '../output/OutputManager';
import { ASTParser } from '../parser/ASTParser';

export class ScanOrchestrator {
  private ruleEngine: SecurityRuleEngine;
  private outputManager: OutputManager;
  private astParser: ASTParser;

  constructor(outputManager: OutputManager) {
    this.ruleEngine = new SecurityRuleEngine();
    this.outputManager = outputManager;
    this.astParser = new ASTParser();
  }

  public async scanFile(document: vscode.TextDocument): Promise<ScanResult> {
    const startTime = Date.now();
    console.log(`[DEBUG] 🔍 Starting scan of file: ${document.fileName}`);
    console.log(`[DEBUG] 📄 Language: ${document.languageId}`);
    
    const content = document.getText();
    const lines = content.split('\n');
    console.log(`[DEBUG] 📊 File contains ${lines.length} lines`);
    
    try {
      console.log('[DEBUG] ⚙️ Running security rule engine...');
      
      // Parse content into AST
      console.log('[DEBUG] 🔄 Parsing content into AST');
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
          console.log(`[DEBUG] 🔎 Analysis results: ${vulnerabilities.length} vulnerabilities, ${analysisResult.sources.length} sources, ${analysisResult.sinks.length} sinks, ${analysisResult.sanitizers.length} sanitizers`);
          
          if (vulnerabilities.length === 0) {
            console.log('[DEBUG] ℹ️ No vulnerabilities found. Checking if rules were properly loaded...');
          }
        } catch (error) {
          console.error('[ERROR] Failed to analyze AST:', error);
          vscode.window.showErrorMessage(`Failed to analyze file: ${document.fileName}`);
        }
      } else {
        console.log('[DEBUG] ⚠️ Could not parse file into AST, skipping analysis');
        vscode.window.showWarningMessage(`Could not parse file into AST: ${document.fileName}`);
      }
      
      const result = this.createScanResult(document, analysisResult || { vulnerabilities: [], sources: [], sinks: [], sanitizers: [] }, startTime, lines.length);
      console.log(`[DEBUG] ⏱️ Scan completed in ${result.scanTime}ms`);
      console.log('[DEBUG] 📤 Displaying results...');
      
      try {
        await this.outputManager.displayResults(result);
      } catch (error) {
        console.error('[ERROR] Failed to display results:', error);
        vscode.window.showErrorMessage('Failed to display scan results');
      }
      
      console.log('[DEBUG] ✅ Scan process completed');
      return result;
    } catch (error) {
      console.error('[ERROR] Scan process failed:', error);
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
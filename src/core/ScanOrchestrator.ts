import * as vscode from 'vscode';
import { ScanResult, AstNode } from '../types';
import { SecurityRuleEngine, AnalysisResult } from '../rules/SecurityRuleEngine';
import { OutputManager } from '../output/OutputManager';
import { ASTParser } from '../parser/ASTParser';
import { DataFlowGraph } from '../parser/DataFlowGraph';

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
      let ast : AstNode | undefined;
      const dfg = DataFlowGraph.getInstance();
      try {
        ast = this.astParser.parse(content, document.languageId, document.fileName);
        if(ast)
        {
          dfg.reset();
          dfg.buildFromAst(ast);
          dfg.printGraph();
        }
        
        if (!ast) {
          throw new Error('AST parser returned null or undefined');
        }
      } catch (error) {
        vscode.window.showErrorMessage(
          `Failed to parse ${document.fileName}: ${error instanceof Error ? error.message : 'Unknown error'}`
        );
        return this.createScanResult(document, { patternVulnerabilities: [], dataFlowVulnerabilities: [] }, startTime, lines.length);
      }
      
      let analysisResult: AnalysisResult | null = null;
      
      if (ast) {
        try {
          analysisResult = await this.ruleEngine.analyzeFile(ast, dfg, document.languageId, document.fileName, content);
          await this.outputManager.saveAnalysisResultToTempFile(analysisResult);
        } catch (error) {
          vscode.window.showErrorMessage(`Failed to analyze file: ${document.fileName}`);
        }
      } else {
        vscode.window.showWarningMessage(`Could not parse file into AST: ${document.fileName}`);
      }
      
      const result = this.createScanResult(document, analysisResult || { patternVulnerabilities: [], dataFlowVulnerabilities: [] }, startTime, lines.length);
      
      try {
        await this.outputManager.displayResults(result);
      } catch (error) {
        vscode.window.showErrorMessage('Failed to display scan results');
      }

      return result;
    } catch (error) {
      vscode.window.showErrorMessage(`Scan failed for file: ${document.fileName}`);
      return this.createScanResult(document, { patternVulnerabilities: [], dataFlowVulnerabilities: [] }, startTime, lines.length);
    }
  }

  private createScanResult(document: vscode.TextDocument, analysisResult: AnalysisResult, startTime: number, linesScanned: number): ScanResult {
    // Combine all vulnerabilities for ScanResult
    const allVulnerabilities = [
      ...analysisResult.patternVulnerabilities,
      ...analysisResult.dataFlowVulnerabilities.map(dfv => ({
        id: dfv.id,
        type: dfv.type,
        severity: dfv.severity,
        message: dfv.message,
        file: dfv.file,
        line: dfv.pathLines?.[0] || 0,
        column: 0,
        rule: dfv.rule,
        description: dfv.description,
        recommendation: dfv.recommendation,
        ai: dfv.ai
      }))
    ];
    
    // Extract sources, sinks, and sanitizers from data flow vulnerabilities
    const sources = analysisResult.dataFlowVulnerabilities.map(dfv => dfv.source);
    const sinks = analysisResult.dataFlowVulnerabilities.map(dfv => dfv.sink);
    const sanitizers = analysisResult.dataFlowVulnerabilities.flatMap(dfv => dfv.sanitizers);
    
    return {
      file: document.fileName,
      vulnerabilities: allVulnerabilities,
      sources: sources,
      sinks: sinks,
      sanitizers: sanitizers,
      scanTime: Date.now() - startTime,
      linesScanned,
      language: document.languageId
    };
  }

  public clearResults(): void {
    this.outputManager.clearResults();
  }
} 
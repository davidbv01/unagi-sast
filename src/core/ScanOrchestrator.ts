import * as vscode from 'vscode';
import * as fs from 'fs';
import { ScanResult, AstNode } from '../types';
import { SecurityRuleEngine, AnalysisResult } from '../rules/SecurityRuleEngine';
import { OutputManager } from '../output/OutputManager';
import { ASTParser } from '../parser/ASTParser';
import { DataFlowGraph } from '../analysis/DataFlowGraph';
import { FileUtils } from '../utils';

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
    return {
      file: document.fileName,
      patternVulnerabilities: analysisResult.patternVulnerabilities,
      dataFlowVulnerabilities: analysisResult.dataFlowVulnerabilities,
      scanTime: Date.now() - startTime,
      linesScanned,
      language: document.languageId
    };
  }

  public async scanWorkspace(workspacePath?: string): Promise<ScanResult[]> {
    const startTime = Date.now();
    const results: ScanResult[] = [];

    try {
      // Use VS Code workspace API to find Python files
      const pattern = '**/*.py';
      const excludePatterns = [
        '**/node_modules/**',
        '**/.git/**',
        '**/.vscode/**',
        '**/venv/**',
        '**/__pycache__/**',
        '**/.pytest_cache/**',
        '**/build/**',
        '**/dist/**'
      ];

      console.log('🔍 Discovering Python files in workspace...');
      const fileUris = await vscode.workspace.findFiles(pattern, `{${excludePatterns.join(',')}}`);
      
      if (fileUris.length === 0) {
        vscode.window.showInformationMessage('No Python files found in workspace');
        return results;
      }

      console.log(`📁 Found ${fileUris.length} Python files`);

      // Scan each file with progress reporting
      await vscode.window.withProgress({
        location: vscode.ProgressLocation.Notification,
        title: "Unagi Workspace Scan",
        cancellable: true
      }, async (progress, token) => {
        let completed = 0;
        
        for (const fileUri of fileUris) {
          if (token.isCancellationRequested) {
            break;
          }

          const fileName = vscode.workspace.asRelativePath(fileUri);
          progress.report({ 
            message: `Scanning ${fileName}...`,
            increment: (100 / fileUris.length)
          });

          try {
            const result = await this.scanFileByPath(fileUri.fsPath);
            if (result) {
              results.push(result);
            }
          } catch (error) {
            console.error(`Failed to scan ${fileName}:`, error);
            vscode.window.showWarningMessage(`Failed to scan ${fileName}: ${error instanceof Error ? error.message : 'Unknown error'}`);
          }

          completed++;
          console.log(`✅ Completed ${completed}/${fileUris.length} files`);
        }

        const totalTime = Date.now() - startTime;
        const totalVulns = results.reduce((sum, result) => 
          sum + result.patternVulnerabilities.length + result.dataFlowVulnerabilities.length, 0
        );

        progress.report({ 
          message: `Scan complete: ${totalVulns} vulnerabilities found in ${results.length} files`
        });

        setTimeout(() => {
          vscode.window.showInformationMessage(
            `Workspace scan completed in ${(totalTime / 1000).toFixed(2)}s. Found ${totalVulns} vulnerabilities across ${results.length} files.`
          );
        }, 1000);
      });

      return results;
    } catch (error) {
      vscode.window.showErrorMessage(`Workspace scan failed: ${error instanceof Error ? error.message : 'Unknown error'}`);
      return results;
    }
  }

  private async scanFileByPath(filePath: string): Promise<ScanResult | null> {
    try {
      // Read file content
      const content = fs.readFileSync(filePath, 'utf8');
      const lines = content.split('\n');
      
      // Create a mock document-like object
      const mockDocument = {
        fileName: filePath,
        languageId: FileUtils.getLanguageFromExtension(filePath),
        getText: () => content
      };

      // Use existing scan logic
      let ast: AstNode | undefined;
      const dfg = DataFlowGraph.getInstance();
      
      try {
        ast = this.astParser.parse(content, mockDocument.languageId, filePath);
        if (ast) {
          dfg.reset();
          dfg.buildFromAst(ast);
        }
      } catch (error) {
        console.error(`Failed to parse ${filePath}:`, error);
        return this.createScanResultFromPath(filePath, mockDocument.languageId, { patternVulnerabilities: [], dataFlowVulnerabilities: [] }, Date.now(), lines.length);
      }

      let analysisResult: AnalysisResult | null = null;
      
      if (ast) {
        try {
          analysisResult = await this.ruleEngine.analyzeFile(ast, dfg, mockDocument.languageId, filePath, content);
        } catch (error) {
          console.error(`Failed to analyze ${filePath}:`, error);
        }
      }

      return this.createScanResultFromPath(
        filePath, 
        mockDocument.languageId, 
        analysisResult || { patternVulnerabilities: [], dataFlowVulnerabilities: [] }, 
        Date.now(), 
        lines.length
      );
    } catch (error) {
      console.error(`Error scanning file ${filePath}:`, error);
      return null;
    }
  }

  private createScanResultFromPath(filePath: string, languageId: string, analysisResult: AnalysisResult, startTime: number, linesScanned: number): ScanResult {
    return {
      file: filePath,
      patternVulnerabilities: analysisResult.patternVulnerabilities,
      dataFlowVulnerabilities: analysisResult.dataFlowVulnerabilities,
      scanTime: Date.now() - startTime,
      linesScanned,
      language: languageId
    };
  }

  public clearResults(): void {
    this.outputManager.clearResults();
  }
} 
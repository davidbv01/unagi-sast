import * as vscode from 'vscode';
import * as fs from 'fs';
import { ScanResult, AstNode, WorkspaceScanResult } from '../types';
import { SecurityRuleEngine, AnalysisResult } from '../rules/SecurityRuleEngine';
import { OutputManager } from '../output/OutputManager';
import { ASTParser } from '../parser/ASTParser';
import { DataFlowGraph } from '../analysis/DataFlowGraph';
import { InterFileAnalyzer } from '../analysis/InterFileAnalyzer';
import { FileUtils } from '../utils';

export class ScanOrchestrator {
  public ruleEngine: SecurityRuleEngine;
  private outputManager: OutputManager;
  private astParser: ASTParser;
  private interFileAnalyzer: InterFileAnalyzer;

  constructor(outputManager: OutputManager, apiKey: string) {
    this.ruleEngine = new SecurityRuleEngine(apiKey);
    this.outputManager = outputManager;
    this.astParser = new ASTParser();
    // Initialize with a default workspace root - this will be updated in scanWorkspace
    this.interFileAnalyzer = new InterFileAnalyzer(vscode.workspace.workspaceFolders?.[0]?.uri.fsPath || '', apiKey);
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

    try {
      // Get workspace root
      const workspaceRoot = workspacePath || vscode.workspace.workspaceFolders?.[0]?.uri.fsPath;
      if (!workspaceRoot) {
        vscode.window.showErrorMessage('No workspace folder found');
        return [];
      }

      // Update inter-file analyzer with correct workspace root
      this.interFileAnalyzer = new InterFileAnalyzer(workspaceRoot, this.ruleEngine.getApiKey());

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
        return [];
      }

      console.log(`📁 Found ${fileUris.length} Python files`);

      // Perform inter-file analysis with progress reporting
      let workspaceResult: WorkspaceScanResult;
      
      await vscode.window.withProgress({
        location: vscode.ProgressLocation.Notification,
        title: "Unagi Advanced Workspace Scan",
        cancellable: true
      }, async (progress, token) => {
        if (token.isCancellationRequested) {
          return;
        }

        progress.report({ 
          message: 'Analyzing individual files and building workspace graph...',
          increment: 25
        });

        // Perform the comprehensive inter-file analysis
        workspaceResult = await this.interFileAnalyzer.analyzeWorkspace(fileUris);

        progress.report({ 
          message: 'Building cross-file connections...',
          increment: 25
        });

        progress.report({ 
          message: 'Detecting cross-file vulnerabilities...',
          increment: 25
        });

        const totalVulns = workspaceResult.totalVulnerabilities;
        const crossFileVulns = workspaceResult.crossFileVulnerabilities.length;

        progress.report({ 
          message: `Scan complete: ${totalVulns} total vulnerabilities (${crossFileVulns} cross-file)`,
          increment: 25
        });

        const totalTime = Date.now() - startTime;
        
        // Show enhanced results message
        setTimeout(() => {
          const stats = this.interFileAnalyzer.getAnalysisStatistics();
          vscode.window.showInformationMessage(
            `Advanced workspace scan completed in ${(totalTime / 1000).toFixed(2)}s. ` +
            `Found ${totalVulns} vulnerabilities across ${stats.totalFiles} files. ` +
            `${crossFileVulns} cross-file vulnerabilities detected with ${stats.crossFileConnections} inter-file connections.`
          );
        }, 1000);
      });

      // Display the enhanced results
      await this.displayWorkspaceResults(workspaceResult!);

      // Return the file results for backwards compatibility
      return workspaceResult!.fileResults;
      
    } catch (error) {
      vscode.window.showErrorMessage(`Advanced workspace scan failed: ${error instanceof Error ? error.message : 'Unknown error'}`);
      return [];
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

  /**
   * Displays the enhanced workspace scan results
   */
  private async displayWorkspaceResults(workspaceResult: WorkspaceScanResult): Promise<void> {
    try {
      // Display individual file results
      for (const fileResult of workspaceResult.fileResults) {
        await this.outputManager.displayResults(fileResult);
      }

      // TODO: Display cross-file vulnerabilities in a special way
      // For now, we'll display them as regular vulnerabilities but with enhanced context
      for (const crossFileVuln of workspaceResult.crossFileVulnerabilities) {
        // Convert cross-file vulnerability to a format the output manager can handle
        const syntheticResult: ScanResult = {
          file: crossFileVuln.file,
          patternVulnerabilities: [],
          dataFlowVulnerabilities: [crossFileVuln],
          scanTime: 0,
          linesScanned: 0,
          language: 'python'
        };
        await this.outputManager.displayResults(syntheticResult);
      }

      // Log analysis statistics
      const stats = this.interFileAnalyzer.getAnalysisStatistics();
      console.log('📊 Inter-file Analysis Statistics:');
      console.log(`  - Total files analyzed: ${stats.totalFiles}`);
      console.log(`  - Total nodes in graphs: ${stats.totalNodes}`);
      console.log(`  - Cross-file connections: ${stats.crossFileConnections}`);
      console.log(`  - Files with vulnerabilities: ${stats.vulnerableFiles.length}`);

    } catch (error) {
      console.error('Failed to display workspace results:', error);
      vscode.window.showErrorMessage('Failed to display workspace scan results');
    }
  }
} 
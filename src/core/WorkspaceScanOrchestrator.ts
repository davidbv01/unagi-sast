import * as vscode from 'vscode';
import * as fs from 'fs';
import { ASTParser } from '../parser/ASTParser';
import { DataFlowGraph } from '../analysis/DataFlowGraph';
import { AstNode, DataFlowVulnerability, WorkspaceScanResult, PatternVulnerability, SymbolTableEntry, AnalysisResult } from '../types';
import { FileUtils } from '../utils';
import { OutputManager } from '../output/OutputManager';
import { WorkspaceSecurityRuleEngine } from '../rules/WorkspaceSecurityRuleEngine';
import * as path from 'path';

/**
 * Orchestrates workspace-wide scanning and analysis for security vulnerabilities.
 */
export class WorkspaceScanOrchestrator {
  private readonly parser: ASTParser;
  private readonly asts: Map<string, AstNode>;
  private readonly symbolTable: Map<string, SymbolTableEntry>;
  private readonly graphs: Map<string, DataFlowGraph>;
  private cachedVulnerabilities: DataFlowVulnerability[] | null = null;
  private readonly outputManager: OutputManager;
  private readonly ruleEngine: WorkspaceSecurityRuleEngine;

  /**
   * Creates a new WorkspaceScanOrchestrator instance.
   * @param outputManager The output manager for reporting results.
   * @param apiKey The OpenAI API key for AI-powered features.
   * @param skipAiAnalysis Flag to skip AI analysis (useful for MCP calls).
   */
  constructor(outputManager: OutputManager, apiKey: string, skipAiAnalysis: boolean = false) {
    this.parser = new ASTParser();
    this.asts = new Map();
    this.symbolTable = new Map();
    this.graphs = new Map();
    this.cachedVulnerabilities = null;
    this.outputManager = outputManager;
    this.ruleEngine = new WorkspaceSecurityRuleEngine(apiKey, skipAiAnalysis);
  }

  /**
   * Discover all relevant source files in the workspace.
   * @param workspaceRoot The root directory of the workspace.
   * @returns Array of file paths.
   */
  public async discoverSourceFiles(workspaceRoot: string): Promise<string[]> {
    const supportedExtensions = FileUtils.getSupportedExtensions();
    const patterns = supportedExtensions.map(ext => `**/*${ext}`);
    const excludePatterns = [
      '**/node_modules/**',
      '**/.git/**',
      '**/.vscode/**',
      '**/venv/**',
      '**/__pycache__/**',
      '**/.pytest_cache/**',
      '**/build/**',
      '**/dist/**',
      '**/target/**',
      '**/.idea/**'
    ];
    const foundFiles: string[] = [];
    try {
      for (const pattern of patterns) {
        console.log(`🔍 Discovering files with pattern: ${pattern}`);
        const fileUris = await vscode.workspace.findFiles(pattern, `{${excludePatterns.join(',')}}`);
        for (const uri of fileUris) {
          const filePath = uri.fsPath;
          if (FileUtils.isSupportedFile(filePath) && !FileUtils.shouldExcludeFile(filePath, excludePatterns)) {
            foundFiles.push(filePath);
          }
        }
      }
      console.log(`📁 Found ${foundFiles.length} source files`);
      return foundFiles;
    } catch (error) {
      console.error('Error discovering source files:', error);
      return [];
    }
  }

  /**
   * Parse all files to ASTs.
   * @param filePaths Array of file paths to parse.
   */
  public async parseFilesToASTs(filePaths: string[]): Promise<void> {
    console.log(`🔄 Parsing ${filePaths.length} files to ASTs...`);
    for (const filePath of filePaths) {
      try {
        const content = fs.readFileSync(filePath, 'utf8');
        const languageId = FileUtils.getLanguageFromExtension(filePath);
        const ast = this.parser.parse(content, languageId, filePath);
        if (ast) {
          const relativePath = vscode.workspace.asRelativePath(filePath);
          ast.filePath = relativePath;
          this.asts.set(relativePath, ast);
          console.log(`✅ Parsed AST for: ${relativePath}`);
        } else {
          console.warn(`⚠️ Failed to parse AST for: ${filePath}`);
        }
      } catch (error) {
        console.error(`❌ Error parsing ${filePath}:`, error);
      }
    }
    console.log(`📊 Successfully parsed ${this.asts.size} ASTs`);
  }

  /**
   * Build the global symbol table from all ASTs (first pass).
   */
  public buildSymbolTable(): void {
    console.log('🔍 Building global symbol table...');
    this.symbolTable.clear();
    for (const [filePath, ast] of this.asts) {
      if ((ast as any).symbols && Array.isArray((ast as any).symbols)) {
        for (const symbol of (ast as any).symbols) {
          console.log('[SYMBOL TABLE] Añadiendo símbolo:', symbol.name, 'en', symbol.filePath);
          const symbolKey = `${filePath}:${symbol.name}`;
          this.symbolTable.set(symbolKey, symbol);
        }
      }
    }
    console.log(`📊 Built symbol table with ${this.symbolTable.size} symbols`);
  }

  /**
   * Build DataFlowGraphs for all files (second pass).
   */
  public buildDataFlowGraphs(): void {
    console.log('🔄 Building data flow graphs for all files...');
    for (const [filePath, ast] of this.asts) {
      try {
        const dfg = new DataFlowGraph();
        dfg.setSymbolTable(this.symbolTable);
        dfg.setCurrentFilePath(filePath);
        dfg.buildFromAst(ast);
        this.graphs.set(filePath, dfg);
        console.log(`✅ Built DFG for: ${filePath}`);
      } catch (error) {
        console.error(`❌ Error building DFG for ${filePath}:`, error);
      }
    }
    console.log(`📊 Built ${this.graphs.size} data flow graphs`);
  }



  /**
   * Run the complete workspace analysis.
   * @param workspaceRoot The root directory of the workspace.
   */
  public async run(workspaceRoot: string): Promise<WorkspaceScanResult> {
    const startTime = Date.now();
    console.log('🚀 Starting workspace-wide security analysis...');
    console.log(`📂 Workspace root: ${workspaceRoot}`);
    try {
      const filePaths = await this.discoverSourceFiles(workspaceRoot);
      if (filePaths.length === 0) {
        vscode.window.showInformationMessage('No supported source files found in workspace');
        return this.createEmptyScanResult(workspaceRoot, startTime, 0);
      }
      await this.parseFilesToASTs(filePaths);
      if (this.asts.size === 0) {
        vscode.window.showWarningMessage('No files could be parsed successfully');
        return this.createEmptyScanResult(workspaceRoot, startTime, 0);
      }
      this.buildSymbolTable();
      this.buildDataFlowGraphs();
      
      // Delegate all security analysis to the WorkspaceSecurityRuleEngine
      const analysisResult = await this.ruleEngine.analyzeWorkspace(
        this.asts,
        this.symbolTable,
        this.graphs,
        workspaceRoot
      );
      
      // Cache the results
      this.cachedVulnerabilities = analysisResult.dataFlowVulnerabilities;
      
      // Create workspace scan result for output
      const workspaceScanResult: WorkspaceScanResult = {
        workspaceRoot: workspaceRoot,
        filesAnalyzed: this.asts.size,
        patternVulnerabilities: analysisResult.patternVulnerabilities,
        dataFlowVulnerabilities: analysisResult.dataFlowVulnerabilities,
        scanTime: Date.now() - startTime,
        linesScanned: Array.from(this.asts.values()).reduce((total, ast) => total + ast.content.split('\n').length, 0)
      };
      
      await this.outputManager.handleWorkspaceScanResults([workspaceScanResult]);
      const totalTime = Date.now() - startTime;
      vscode.window.showInformationMessage(
        `Workspace analysis completed in ${(totalTime / 1000).toFixed(2)}s. ` +
        `Processed ${this.asts.size} files, found ${this.symbolTable.size} symbols, ` +
        `detected ${analysisResult.dataFlowVulnerabilities.length} data flow vulnerabilities.`
      );
      return workspaceScanResult;
    } catch (error) {
      console.error('❌ Workspace analysis failed:', error);
      vscode.window.showErrorMessage(
        `Workspace analysis failed: ${error instanceof Error ? error.message : 'Unknown error'}`
      );
      return this.createEmptyScanResult(workspaceRoot, startTime, 0);
    }
    
  }

  /**
   * Get the global symbol table.
   * @returns The symbol table map.
   */
  public getSymbolTable(): Map<string, SymbolTableEntry> {
    return this.symbolTable;
  }

  /**
   * Get AST for a specific file.
   * @param filePath The file path.
   * @returns The AST node or undefined.
   */
  public getAstForFile(filePath: string): AstNode | undefined {
    return this.asts.get(filePath);
  }

  /**
   * Get data flow graph for a specific file.
   * @param filePath The file path.
   * @returns The data flow graph or undefined.
   */
  public getDataFlowGraphForFile(filePath: string): DataFlowGraph | undefined {
    return this.graphs.get(filePath);
  }

  /**
   * Find symbol by name across all files.
   * @param symbolName The symbol name to search for.
   * @returns Array of matching symbol table entries.
   */
  public findSymbol(symbolName: string): SymbolTableEntry[] {
    const results: SymbolTableEntry[] = [];
    for (const [, symbol] of this.symbolTable) {
      if (symbol.name === symbolName) {
        results.push(symbol);
      }
    }
    return results;
  }

  /**
   * Find symbols in a specific file.
   * @param filePath The file path.
   * @returns Array of symbol table entries in the file.
   */
  public findSymbolsInFile(filePath: string): SymbolTableEntry[] {
    const results: SymbolTableEntry[] = [];
    for (const symbol of this.symbolTable.values()) {
      if (symbol.filePath === filePath) {
        results.push(symbol);
      }
    }
    return results;
  }

  /**
   * Get workspace vulnerabilities after analysis.
   * @returns Array of data flow vulnerabilities.
   */
  public getWorkspaceVulnerabilities(): DataFlowVulnerability[] {
    if (this.cachedVulnerabilities) {
      return this.cachedVulnerabilities;
    }
    console.warn('⚠️ No vulnerabilities available. Run workspace analysis first.');
    return [];
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
    workspaceRoot: string,
    analysisResult: AnalysisResult,
    startTime: number,
    linesScanned: number
  ): WorkspaceScanResult {
    return {
      workspaceRoot: workspaceRoot,
      filesAnalyzed: analysisResult.patternVulnerabilities.length + analysisResult.dataFlowVulnerabilities.length,
      patternVulnerabilities: analysisResult.patternVulnerabilities,
      dataFlowVulnerabilities: analysisResult.dataFlowVulnerabilities,
      scanTime: Date.now() - startTime,
      linesScanned
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
    workspaceRoot: string,
    startTime: number,
    linesScanned: number
  ): WorkspaceScanResult {
    return this.createScanResult(
      workspaceRoot,
      { patternVulnerabilities: [], dataFlowVulnerabilities: [] },
      startTime,
      linesScanned
    );
  }

  /**
   * Clear all analysis data.
   */
  public clear(): void {
    this.asts.clear();
    this.symbolTable.clear();
    this.graphs.clear();
    this.cachedVulnerabilities = null;
  }
}
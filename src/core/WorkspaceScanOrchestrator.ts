import * as vscode from 'vscode';
import * as fs from 'fs';
import { ASTParser } from '../parser/ASTParser';
import { DataFlowGraph } from '../analysis/DataFlowGraph';
import { AstNode, DataFlowVulnerability, ScanResult, PatternVulnerability, SymbolTableEntry } from '../types';
import { FileUtils } from '../utils';
import { OutputManager } from '../output/OutputManager';
import { SecurityRuleEngine } from '../rules/SecurityRuleEngine';
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
  private readonly ruleEngine: SecurityRuleEngine;

  /**
   * Creates a new WorkspaceScanOrchestrator instance.
   */
  constructor(outputManager: OutputManager, apiKey: string) {
    this.parser = new ASTParser();
    this.asts = new Map();
    this.symbolTable = new Map();
    this.graphs = new Map();
    this.cachedVulnerabilities = null;
    this.outputManager = outputManager;
    this.ruleEngine = new SecurityRuleEngine(apiKey);
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
   * Analyze data flow vulnerabilities with cross-file propagation.
   * @param workspaceRoot The root directory of the workspace.
   * @returns All detected data flow vulnerabilities in the workspace.
   */
  public analyzeWorkspaceDataFlowWithCrossFile(workspaceRoot: string): DataFlowVulnerability[] {
    const allVulnerabilities: DataFlowVulnerability[] = [];
    // Step 1: Analyze each file individually for in-file vulnerabilities
    for (const [filePath, dfg] of this.graphs) {
      try {
        const ast = this.asts.get(filePath);
        if (!ast) continue;
        const absolutePath = path.isAbsolute(filePath) ? filePath : path.join(workspaceRoot, filePath);
        const content = require('fs').readFileSync(absolutePath, 'utf8');
        const patternVulnerabilities: PatternVulnerability[] = this.ruleEngine.getPatternMatcher().matchPatterns(content) || [];
        const fileVulnerabilities = dfg.performCompleteAnalysis(ast);
        allVulnerabilities.push(...fileVulnerabilities);
      } catch (error) {
        // Optionally log or handle errors in production
      }
    }
    // Step 2: Propagate taint across files and analyze resulting vulnerabilities
    let crossFileConnections = 0;
    for (const [sourceFilePath, sourceDfg] of this.graphs) {
      for (const [nodeId, node] of sourceDfg.nodes) {
        if (node.tainted && node.crossFileEdge) {
          const targetFilePath = node.crossFileEdge.to;
          const functionName = node.crossFileEdge.function;
          const targetRelativePath = vscode.workspace.asRelativePath(targetFilePath);
          const targetDfg = this.graphs.get(targetRelativePath);
          const targetAst = this.asts.get(targetRelativePath);
          if (targetDfg && targetAst) {
            const functionSymbol = Array.from(this.symbolTable.values()).find(sym =>
              sym.name === functionName && sym.type === 'function' && sym.filePath === targetRelativePath
            );
            let parameterNodes: any[] = [];
            if (functionSymbol && functionSymbol.parameters) {
              parameterNodes = functionSymbol.parameters.map(paramName => {
                const paramNodeId = `${functionName}_${paramName}`;
                return targetDfg.nodes.get(paramNodeId);
              }).filter(Boolean);
            } else {
              parameterNodes = Array.from(targetDfg.nodes.values()).filter(n =>
                n.id.startsWith(`${functionName}_`) &&
                !n.id.includes('_return') &&
                n.symbol?.scope === functionName
              );
            }
            for (const paramNode of parameterNodes) {
              if (!paramNode.tainted) {
                paramNode.tainted = true;
                if (node.taintSources && node.taintSources.size > 0) {
                  paramNode.taintSources = new Set(node.taintSources);
                  for (const src of node.taintSources) {
                    targetDfg.propagateTaint(src);
                  }
                }
                crossFileConnections++;
              }
            }
            const crossFileVulns = targetDfg.detectVulnerabilities(targetRelativePath);
            const newVulns = crossFileVulns;
            newVulns.forEach(vuln => {
              vuln.id = `cross-file-${vuln.id}`;
              vuln.message = `Cross-file vulnerability: ${vuln.message} (originated from ${sourceFilePath})`;
            });
            allVulnerabilities.push(...newVulns);
          }
        }
      }
    }
    this.cachedVulnerabilities = this.deduplicateVulnerabilities(allVulnerabilities);
    return this.cachedVulnerabilities;
  }

  /**
   * Deduplicate DataFlowVulnerability objects by file, sink location, type, and sources.
   * @param vulns Array of vulnerabilities to deduplicate.
   * @returns Deduplicated array of vulnerabilities.
   */
  private deduplicateVulnerabilities(vulns: DataFlowVulnerability[]): DataFlowVulnerability[] {
    const seen = new Map<string, DataFlowVulnerability>();
    for (const vuln of vulns) {
      const sinkLoc = vuln.sink?.loc?.start;
      const sourcesKey = vuln.sources
        .map(s => `${s.filePath}:${s.loc?.start?.line}:${s.loc?.start?.column}`)
        .sort()
        .join('|');
      const key = `${vuln.file}:${sinkLoc?.line}:${sinkLoc?.column}:${vuln.type}:${sourcesKey}`;
      if (!seen.has(key)) {
        seen.set(key, vuln);
      } else {
        const existing = seen.get(key)!;
        if (vuln.sources.length > existing.sources.length) {
          seen.set(key, vuln);
        }
      }
    }
    return Array.from(seen.values());
  }

  /**
   * Run the complete workspace analysis.
   * @param workspaceRoot The root directory of the workspace.
   */
  public async run(workspaceRoot: string): Promise<void> {
    const startTime = Date.now();
    console.log('🚀 Starting workspace-wide security analysis...');
    console.log(`📂 Workspace root: ${workspaceRoot}`);
    try {
      const filePaths = await this.discoverSourceFiles(workspaceRoot);
      if (filePaths.length === 0) {
        vscode.window.showInformationMessage('No supported source files found in workspace');
        return;
      }
      await this.parseFilesToASTs(filePaths);
      if (this.asts.size === 0) {
        vscode.window.showWarningMessage('No files could be parsed successfully');
        return;
      }
      this.buildSymbolTable();
      this.buildDataFlowGraphs();
      const workspaceVulnerabilities = this.analyzeWorkspaceDataFlowWithCrossFile(workspaceRoot);
      const scanResults: ScanResult[] = [];
      for (const [filePath, dfg] of this.graphs) {
        const dfgInstance = this.graphs.get(filePath);
        if (!dfgInstance) continue;
        const absolutePath = path.isAbsolute(filePath) ? filePath : path.join(workspaceRoot, filePath);
        const content = require('fs').readFileSync(absolutePath, 'utf8');
        const patternVulnerabilities: PatternVulnerability[] = this.ruleEngine.getPatternMatcher().matchPatterns(content) || [];
        const dataFlowVulnerabilities: DataFlowVulnerability[] = workspaceVulnerabilities.filter(v => v.file === filePath || v.file === absolutePath);
        dataFlowVulnerabilities.forEach(vuln => { vuln.file = absolutePath; });
        scanResults.push({
          file: absolutePath,
          patternVulnerabilities,
          dataFlowVulnerabilities,
          scanTime: 0,
          linesScanned: content.split('\n').length,
          language: FileUtils.getLanguageFromExtension(filePath)
        });
      }
      await this.outputManager.handleWorkspaceScanResults(scanResults);
      const totalTime = Date.now() - startTime;
      vscode.window.showInformationMessage(
        `Workspace analysis completed in ${(totalTime / 1000).toFixed(2)}s. ` +
        `Processed ${this.asts.size} files, found ${this.symbolTable.size} symbols, ` +
        `detected ${workspaceVulnerabilities.length} data flow vulnerabilities.`
      );
    } catch (error) {
      console.error('❌ Workspace analysis failed:', error);
      vscode.window.showErrorMessage(
        `Workspace analysis failed: ${error instanceof Error ? error.message : 'Unknown error'}`
      );
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
    if (this.graphs.size === 0) {
      console.warn('⚠️ No data flow graphs available. Run workspace analysis first.');
      return [];
    }
    return this.analyzeWorkspaceDataFlowWithCrossFile('');
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
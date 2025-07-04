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
 * WorkspaceScanOrchestrator - Advanced workspace-wide security analysis
 * 
 * This class provides comprehensive static analysis capabilities across an entire workspace,
 * building cross-file symbol tables and data flow graphs for enhanced security scanning.
 * 
 * Key Features:
 * - Multi-file AST parsing and analysis
 * - Global symbol table construction for cross-file reference resolution
 * - Data flow graph generation with cross-file context
 * - Support for multiple programming languages
 * 
 * Usage Example:
 * ```typescript
 * const orchestrator = new WorkspaceScanOrchestrator();
 * await orchestrator.run('/path/to/workspace');
 * 
 * // Access analysis results
 * const symbolTable = orchestrator.getSymbolTable();
 * const astForFile = orchestrator.getAstForFile('src/main.py');
 * const dfgForFile = orchestrator.getDataFlowGraphForFile('src/main.py');
 * 
 * // Search for specific symbols
 * const mainFunctions = orchestrator.findSymbol('main');
 * const fileSymbols = orchestrator.findSymbolsInFile('src/utils.py');
 * ```
 * 
 * Analysis Pipeline:
 * 1. Discover all supported source files in the workspace
 * 2. Parse each file into an Abstract Syntax Tree (AST)
 * 3. Build a global symbol table from all ASTs (first pass)
 * 4. Generate data flow graphs for each file with cross-file context (second pass)
 */

// Symbol table entry for cross-file analysis


  
export class WorkspaceScanOrchestrator {
  private parser: ASTParser;
  private asts: Map<string, AstNode>;
  private symbolTable: Map<string, SymbolTableEntry>;
  private graphs: Map<string, DataFlowGraph>;
  private cachedVulnerabilities: DataFlowVulnerability[] | null = null;
  private outputManager: OutputManager;
  private ruleEngine: SecurityRuleEngine;

  constructor() {
    this.parser = new ASTParser();
    this.asts = new Map();
    this.symbolTable = new Map();
    this.graphs = new Map();
    this.cachedVulnerabilities = null;
    this.outputManager = new OutputManager('./unagi-output');
    this.ruleEngine = new SecurityRuleEngine(''); // TODO: Pass API key if needed
  }

  /**
   * Discover all relevant source files in the workspace
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
   * Parse all files to ASTs
   */
  public async parseFilesToASTs(filePaths: string[]): Promise<void> {
    console.log(`🔄 Parsing ${filePaths.length} files to ASTs...`);
    
    for (const filePath of filePaths) {
      try {
        const content = fs.readFileSync(filePath, 'utf8');
        const languageId = FileUtils.getLanguageFromExtension(filePath);
        
        const ast = this.parser.parse(content, languageId, filePath);
        if (ast) {
          // Store the relative path for cross-file references
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
   * Build the global symbol table from all ASTs (first pass)
   */
  public buildSymbolTable(): void {
    console.log('🔍 Building global symbol table...');
    this.symbolTable.clear();
    // Combine symbols from all ASTs
    for (const [filePath, ast] of this.asts) {
      if ((ast as any).symbols && Array.isArray((ast as any).symbols)) {
        for (const symbol of (ast as any).symbols) {
          // Log para verificar el filePath de cada símbolo
          console.log('[SYMBOL TABLE] Añadiendo símbolo:', symbol.name, 'en', symbol.filePath);
          // Use a key like filePath:symbolName for uniqueness
          const symbolKey = `${filePath}:${symbol.name}`;
          this.symbolTable.set(symbolKey, symbol);
        }
      }
    }
    console.log(`📊 Built symbol table with ${this.symbolTable.size} symbols`);
  }

  /**
   * Build DataFlowGraphs for all files (second pass)
   */
  public buildDataFlowGraphs(): void {
    console.log('🔄 Building data flow graphs for all files...');
    
    for (const [filePath, ast] of this.asts) {
      try {
        // Create a new DataFlowGraph instance for each file
        const dfg = new DataFlowGraph();
        dfg.setSymbolTable(this.symbolTable);
        dfg.setCurrentFilePath(filePath);
        dfg.buildFromAst(ast);
        
        // Store the unique DFG instance for this file
        this.graphs.set(filePath, dfg);
        console.log(`✅ Built DFG for: ${filePath}`);
      } catch (error) {
        console.error(`❌ Error building DFG for ${filePath}:`, error);
      }
    }
    
    console.log(`📊 Built ${this.graphs.size} data flow graphs`);
  }

  /**
   * Analyze data flow vulnerabilities with cross-file propagation
   */
  public analyzeWorkspaceDataFlowWithCrossFile(workspaceRoot: string): DataFlowVulnerability[] {
    console.log('🔍 Analyzing workspace data flow with cross-file propagation...');
    
    const allVulnerabilities: DataFlowVulnerability[] = [];
    
    // Step 1: Analyze each file individually to find in-file vulnerabilities and identify tainted nodes
    console.log('📋 Step 1: Individual file analysis...');
    for (const [filePath, dfg] of this.graphs) {
      try {
        const ast = this.asts.get(filePath);
        if (!ast) continue;
        
        console.log(`🔍 Analyzing individual file: ${filePath}`);
        const absolutePath = path.isAbsolute(filePath) ? filePath : path.join(workspaceRoot, filePath);
        const content = require('fs').readFileSync(absolutePath, 'utf8');
        const patternVulnerabilities: PatternVulnerability[] = this.ruleEngine.getPatternMatcher().matchPatterns(content) || [];
        const fileVulnerabilities = dfg.performCompleteAnalysis(ast);
        fileVulnerabilities.forEach(vuln => {
          vuln.file = absolutePath;
        });
        allVulnerabilities.push(...fileVulnerabilities);
        console.log(`✅ Found ${fileVulnerabilities.length} in-file vulnerabilities in ${filePath}`);
        
      } catch (error) {
        console.error(`❌ Error analyzing file ${filePath}:`, error);
      }
    }
    
    // Step 2: Cross-file taint propagation
    console.log('🔗 Step 2: Cross-file taint propagation...');
    let crossFileConnections = 0;
    
    for (const [sourceFilePath, sourceDfg] of this.graphs) {
      console.log(`[DEBUG] Checking file: ${sourceFilePath}, nodes: ${sourceDfg.nodes.size}`);
      // Find nodes with cross-file edges that are tainted
      for (const [nodeId, node] of sourceDfg.nodes) {
        console.log(`[DEBUG] Node ${nodeId}: tainted=${node.tainted}, hasEdge=${!!node.crossFileEdge}`);
        if (node.tainted && node.crossFileEdge) {
          const targetFilePath = node.crossFileEdge.to;
          const functionName = node.crossFileEdge.function;
        
          console.log(`🔗 Cross-file taint: ${sourceFilePath} -> ${targetFilePath} via ${functionName}`);
        
          // Convert absolute path to relative path for lookup
          const targetRelativePath = vscode.workspace.asRelativePath(targetFilePath);
          console.log(`[DEBUG] Converting absolute path ${targetFilePath} to relative path ${targetRelativePath}`);
        
          // Get the target DFG using relative path
          const targetDfg = this.graphs.get(targetRelativePath);
          const targetAst = this.asts.get(targetRelativePath);
          
          if (targetDfg && targetAst) {
            console.log('[DEBUG] targetDfg.nodes.size:', targetDfg.nodes.size);
            console.log('[DEBUG] Nodos en DFG destino:', Array.from(targetDfg.nodes.entries()).map(([id, n]) => ({
              id: id, name: n.name, scope: n.symbol?.scope, tainted: n.tainted, isSink: n.isSink
            })));
            console.log('[DEBUG] Buscando parámetros para función:', functionName);
            
            // Find the function definition in the symbol table to get actual parameters
            console.log('[DEBUG] Buscando función en symbol table:', functionName, 'en archivo:', targetRelativePath);
            console.log('[DEBUG] Symbol table entries:', Array.from(this.symbolTable.entries()).map(([key, sym]) => ({
              key, name: sym.name, type: sym.type, filePath: sym.filePath, parameters: sym.parameters
            })));
            
            const functionSymbol = Array.from(this.symbolTable.values()).find(sym => 
              sym.name === functionName && sym.type === 'function' && sym.filePath === targetRelativePath
            );
            
            console.log('[DEBUG] Función encontrada:', !!functionSymbol, functionSymbol);
            
            let parameterNodes: any[] = [];
            if (functionSymbol && functionSymbol.parameters) {
              // Only look for actual function parameters, not all variables in scope
              parameterNodes = functionSymbol.parameters.map(paramName => {
                const paramNodeId = `${functionName}_${paramName}`;
                console.log('[DEBUG] Buscando nodo parámetro:', paramNodeId);
                return targetDfg.nodes.get(paramNodeId);
              }).filter(Boolean);
              console.log('[DEBUG] Función encontrada con parámetros:', functionSymbol.parameters);
            } else {
              // Fallback: look for nodes with the function_parameter pattern
              // Pattern should be: functionName_parameterName
              parameterNodes = Array.from(targetDfg.nodes.values()).filter(n => 
                n.id.startsWith(`${functionName}_`) && 
                !n.id.includes('_return') && // Exclude function return nodes
                n.symbol?.scope === functionName // Must be in function scope
              );
            }
            console.log('[DEBUG] Parámetros reales encontrados:', parameterNodes.length, parameterNodes.map(n => n?.name));
            
            for (const paramNode of parameterNodes) {
              console.log('[DEBUG] Procesando parámetro:', paramNode.name, 'tainted:', paramNode.tainted);
              if (!paramNode.tainted) {
                paramNode.tainted = true;
                paramNode.taintSources.add(`cross-file-from-${sourceFilePath}`);
                console.log(`🔗 Marked parameter ${paramNode.name} as tainted from cross-file call`);
                
                // Propagate taint from this parameter
                targetDfg.propagateTaint(paramNode.id);
                crossFileConnections++;
              }
            }
            
            // Debug: Print node states after taint propagation
            console.log(`[DEBUG] Node states after cross-file taint propagation:`);
            for (const [nodeId, nodeData] of targetDfg.nodes) {
              console.log(`[DEBUG]   ${nodeId}: tainted=${nodeData.tainted}, isSink=${nodeData.isSink}, taintSources=[${Array.from(nodeData.taintSources).join(', ')}]`);
            }
            
            // Re-analyze the target file for new vulnerabilities
            const crossFileVulns = targetDfg.detectVulnerabilities(targetRelativePath);
            console.log(`[DEBUG] Found ${crossFileVulns.length} total vulnerabilities in target file after cross-file taint`);
            
            // For now, include all vulnerabilities found after cross-file taint propagation
            // since any vulnerability at this point should involve the tainted data
            const newVulns = crossFileVulns;
            
            newVulns.forEach(vuln => {
              vuln.id = `cross-file-${vuln.id}`;
              vuln.message = `Cross-file vulnerability: ${vuln.message} (originated from ${sourceFilePath})`;
              // Ensure absolute path for cross-file vulnerabilities
              vuln.file = path.isAbsolute(targetFilePath) ? targetFilePath : path.join(workspaceRoot, targetFilePath);
            });
            
            allVulnerabilities.push(...newVulns);
            
            if (newVulns.length > 0) {
              console.log(`🚨 Found ${newVulns.length} cross-file vulnerabilities in ${targetRelativePath}`);
            }
          }
        }
      }
    }
    
    console.log(`🔗 Total cross-file connections made: ${crossFileConnections}`);
    console.log(`📊 Total vulnerabilities found: ${allVulnerabilities.length}`);
    
    // Cache the results
    this.cachedVulnerabilities = allVulnerabilities;
    
    return allVulnerabilities;
  }

  /**
   * Run the complete workspace analysis
   */
  public async run(workspaceRoot: string): Promise<void> {
    const startTime = Date.now();
    console.log('🚀 Starting workspace-wide security analysis...');
    console.log(`📂 Workspace root: ${workspaceRoot}`);

    try {
      // Step 1: Discover all source files
      const filePaths = await this.discoverSourceFiles(workspaceRoot);
      
      if (filePaths.length === 0) {
        vscode.window.showInformationMessage('No supported source files found in workspace');
        return;
      }

      // Step 2: Parse all files to ASTs
      await this.parseFilesToASTs(filePaths);

      if (this.asts.size === 0) {
        vscode.window.showWarningMessage('No files could be parsed successfully');
        return;
      }

      // Step 3: Build global symbol table (first pass)
      this.buildSymbolTable();

      // Step 4: Build data flow graphs for all files (second pass)
      this.buildDataFlowGraphs();

      // Step 5: Analyze data flow vulnerabilities across the workspace
      const workspaceVulnerabilities = this.analyzeWorkspaceDataFlowWithCrossFile(workspaceRoot);

      // Step 6: Aggregate results per file for output
      const scanResults: ScanResult[] = [];
      for (const [filePath, dfg] of this.graphs) {
        const dfgInstance = this.graphs.get(filePath);
        if (!dfgInstance) continue;
        // Pattern vulnerabilities
        const absolutePath = path.isAbsolute(filePath) ? filePath : path.join(workspaceRoot, filePath);
        const content = require('fs').readFileSync(absolutePath, 'utf8');
        const patternVulnerabilities: PatternVulnerability[] = this.ruleEngine.getPatternMatcher().matchPatterns(content) || [];
        // Data flow vulnerabilities (filter for this file)
        const dataFlowVulnerabilities: DataFlowVulnerability[] = workspaceVulnerabilities.filter(v => v.file === filePath || v.file === absolutePath);
        // Ensure all vulnerabilities have absolute file paths
        dataFlowVulnerabilities.forEach(vuln => { vuln.file = absolutePath; });
        scanResults.push({
          file: absolutePath,
          patternVulnerabilities,
          dataFlowVulnerabilities,
          scanTime: 0, // Could be measured per file if needed
          linesScanned: content.split('\n').length,
          language: FileUtils.getLanguageFromExtension(filePath)
        });
      }
      // Save and display results
      await this.outputManager.saveWorkspaceResults(scanResults);
      this.outputManager.displayWorkspaceResults(scanResults);

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
   * Get the global symbol table
   */
  public getSymbolTable(): Map<string, SymbolTableEntry> {
    return this.symbolTable;
  }

  /**
   * Get AST for a specific file
   */
  public getAstForFile(filePath: string): AstNode | undefined {
    return this.asts.get(filePath);
  }

  /**
   * Get data flow graph for a specific file
   */
  public getDataFlowGraphForFile(filePath: string): DataFlowGraph | undefined {
    return this.graphs.get(filePath);
  }

  /**
   * Find symbol by name across all files
   */
  public findSymbol(symbolName: string): SymbolTableEntry[] {
    const results: SymbolTableEntry[] = [];
    
    for (const [key, symbol] of this.symbolTable) {
      if (symbol.name === symbolName) {
        results.push(symbol);
      }
    }
    
    return results;
  }

  /**
   * Find symbols in a specific file
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
   * Get workspace vulnerabilities after analysis
   */
  public getWorkspaceVulnerabilities(): DataFlowVulnerability[] {
    if (this.graphs.size === 0) {
      console.warn('⚠️ No data flow graphs available. Run workspace analysis first.');
      return [];
    }
    
    return this.analyzeWorkspaceDataFlowWithCrossFile(''); // You may want to pass the actual workspace root here if available
  }

  /**
   * Clear all analysis data
   */
  public clear(): void {
    this.asts.clear();
    this.symbolTable.clear();
    this.graphs.clear();
    this.cachedVulnerabilities = null;
  }
}
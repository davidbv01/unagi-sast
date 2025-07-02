import * as vscode from 'vscode';
import * as fs from 'fs';
import { ASTParser } from '../parser/ASTParser';
import { DataFlowGraph } from '../analysis/DataFlowGraph';
import { AstNode, DataFlowVulnerability } from '../types';
import { FileUtils } from '../utils';

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
export interface SymbolTableEntry {
    name: string; // Symbol name (function, class, variable)
    filePath: string; // Relative file path
    node: AstNode; // AST node for the symbol
    scope?: string; // Optional: class or function scope
    type: 'function' | 'class' | 'variable';
  }

  
export class WorkspaceScanOrchestrator {
  private parser: ASTParser;
  private asts: Map<string, AstNode>;
  private symbolTable: Map<string, SymbolTableEntry>;
  private graphs: Map<string, DataFlowGraph>;
  private cachedVulnerabilities: DataFlowVulnerability[] | null = null;

  constructor() {
    this.parser = new ASTParser();
    this.asts = new Map();
    this.symbolTable = new Map();
    this.graphs = new Map();
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
    
    for (const [filePath, ast] of this.asts) {
      this.extractSymbolsFromAst(ast, filePath);
    }
    
    console.log(`📊 Built symbol table with ${this.symbolTable.size} symbols`);
  }

  /**
   * Extract symbols from an AST node recursively
   */
  private extractSymbolsFromAst(node: AstNode, filePath: string, scope?: string): void {
    // Extract function definitions
    if (node.type === 'function_definition') {
      const functionName = this.extractFunctionName(node);
      if (functionName) {
        const symbolKey = `${filePath}:${functionName}`;
        this.symbolTable.set(symbolKey, {
          name: functionName,
          filePath,
          node,
          scope,
          type: 'function'
        });
      }
    }
    
    // Extract class definitions
    else if (node.type === 'class_definition') {
      const className = this.extractClassName(node);
      if (className) {
        const symbolKey = `${filePath}:${className}`;
        this.symbolTable.set(symbolKey, {
          name: className,
          filePath,
          node,
          scope,
          type: 'class'
        });
        
        // Extract methods within the class
        this.extractSymbolsFromAst(node, filePath, className);
      }
    }
    
    // Extract variable assignments (global level)
    else if (node.type === 'assignment' && !scope) {
      const variableName = this.extractVariableName(node);
      if (variableName) {
        const symbolKey = `${filePath}:${variableName}`;
        this.symbolTable.set(symbolKey, {
          name: variableName,
          filePath,
          node,
          scope,
          type: 'variable'
        });
      }
    }
    
    // Recursively process children
    for (const child of node.children) {
      this.extractSymbolsFromAst(child, filePath, scope);
    }
  }

  /**
   * Extract function name from function definition node
   */
  private extractFunctionName(node: AstNode): string | null {
    // Look for identifier child that represents the function name
    for (const child of node.children) {
      if (child.type === 'identifier') {
        return child.text;
      }
    }
    return null;
  }

  /**
   * Extract class name from class definition node
   */
  private extractClassName(node: AstNode): string | null {
    // Look for identifier child that represents the class name  
    for (const child of node.children) {
      if (child.type === 'identifier') {
        return child.text;
      }
    }
    return null;
  }

  /**
   * Extract variable name from assignment node
   */
  private extractVariableName(node: AstNode): string | null {
    // Look for identifier on the left side of assignment
    for (const child of node.children) {
      if (child.type === 'identifier') {
        return child.text;
      }
    }
    return null;
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
        dfg.buildFromAst(ast);
        
        // Enhance DFG with cross-file symbol information
        this.enhanceDfgWithSymbolTable(dfg, filePath);
        
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
   * Enhance data flow graph with cross-file symbol information
   */
  private enhanceDfgWithSymbolTable(dfg: DataFlowGraph, currentFilePath: string): void {
    console.log(`🔗 Enhancing DFG for ${currentFilePath} with cross-file symbol information...`);
    
    const currentAst = this.asts.get(currentFilePath);
    if (!currentAst) return;
    
    let crossFileReferences = 0;
    
    // Walk through existing DFG nodes to find cross-file references
    for (const [nodeId, dfgNode] of dfg.nodes) {
      const astNode = dfgNode.astNode;
      
      // Check for function calls that might reference external functions
      if (astNode.type === 'call') {
        const functionName = this.extractCallName(astNode);
        if (functionName) {
          const externalSymbol = this.findExternalSymbol(functionName, currentFilePath, 'function');
          if (externalSymbol) {
            // Mark this node with cross-file metadata
            dfgNode.crossFileRef = {
              targetFile: externalSymbol.filePath,
              targetSymbol: functionName,
              type: 'function_call'
            };
            crossFileReferences++;
            console.log(`🔗 Found call to ${functionName} from ${externalSymbol.filePath}`);
          }
        }
      }
      
      // Check for identifier references that might be external variables
      else if (astNode.type === 'identifier') {
        const varName = astNode.text;
        if (varName) {
          const externalSymbol = this.findExternalSymbol(varName, currentFilePath, 'variable');
          if (externalSymbol) {
            // Mark this node with cross-file metadata
            (dfgNode as any).crossFileRef = {
              targetFile: externalSymbol.filePath,
              targetSymbol: varName,
              type: 'variable_ref'
            };
            crossFileReferences++;
            console.log(`🔗 Found reference to ${varName} from ${externalSymbol.filePath}`);
          }
        }
      }
    }
    
    console.log(`✅ Enhanced DFG for ${currentFilePath} with ${crossFileReferences} cross-file references`);
  }

  /**
   * Extract function/method name from a call AST node (reuses existing pattern)
   */
  private extractCallName(node: AstNode): string | null {
    // Reuse the same pattern as extractFunctionName but for calls
    for (const child of node.children) {
      if (child.type === 'identifier') {
        return child.text;
      }
      // Handle attribute access like "module.function"
      if (child.type === 'attribute') {
        return child.text;
      }
    }
    return null;
  }

  /**
   * Find external symbol (reuses existing findSymbol logic but excludes current file)
   */
  private findExternalSymbol(symbolName: string, currentFilePath: string, symbolType: 'function' | 'class' | 'variable'): SymbolTableEntry | null {
    for (const symbol of this.symbolTable.values()) {
      if (symbol.filePath !== currentFilePath && 
          symbol.name === symbolName && 
          symbol.type === symbolType) {
        return symbol;
      }
    }
    return null;
  }

  /**
   * Analyze data flow vulnerabilities across the entire workspace
   */
  public analyzeWorkspaceDataFlow(): DataFlowVulnerability[] {
    // Return cached results if available
    if (this.cachedVulnerabilities) {
      console.log('📋 Returning cached workspace vulnerabilities');
      return this.cachedVulnerabilities;
    }
    
    console.log('🔍 Analyzing workspace data flow vulnerabilities...');
    
    const allVulnerabilities: DataFlowVulnerability[] = [];
    let crossFileVulnerabilities = 0;
    
    for (const [filePath, dfg] of this.graphs) {
      try {
        console.log(`🔍 Analyzing data flow for: ${filePath}`);
        
        // Get the AST for this file to pass to performCompleteAnalysis
        const ast = this.asts.get(filePath);
        if (!ast) {
          console.warn(`⚠️ No AST found for ${filePath}, skipping data flow analysis`);
          continue;
        }
        
        // Perform data flow analysis on this file's DFG
        const fileVulnerabilities = dfg.performCompleteAnalysis(ast);
        
        // Mark vulnerabilities with their source file
        fileVulnerabilities.forEach(vuln => {
          vuln.file = filePath;
        });
        
        // Check for cross-file vulnerabilities by examining cross-file references
        const crossFileVulns = this.detectCrossFileVulnerabilities(filePath, dfg, fileVulnerabilities);
        crossFileVulnerabilities += crossFileVulns.length;
        
        // Add all vulnerabilities (both local and cross-file) to the results
        allVulnerabilities.push(...fileVulnerabilities, ...crossFileVulns);
        
        console.log(`✅ Found ${fileVulnerabilities.length} vulnerabilities in ${filePath} (${crossFileVulns.length} cross-file)`);
        
      } catch (error) {
        console.error(`❌ Error analyzing data flow for ${filePath}:`, error);
      }
    }
    
    console.log(`📊 Workspace data flow analysis complete: ${allVulnerabilities.length} total vulnerabilities found`);
    console.log(`🔗 Cross-file vulnerabilities detected: ${crossFileVulnerabilities}`);
    
    // Cache the results
    this.cachedVulnerabilities = allVulnerabilities;
    
    return allVulnerabilities;
  }

  /**
   * Detect vulnerabilities that span across files using cross-file references
   */
  private detectCrossFileVulnerabilities(
    currentFilePath: string, 
    currentDfg: DataFlowGraph, 
    localVulnerabilities: DataFlowVulnerability[]
  ): DataFlowVulnerability[] {
    const crossFileVulns: DataFlowVulnerability[] = [];
    
    // Check each DFG node for cross-file references
    for (const [nodeId, dfgNode] of currentDfg.nodes) {
      const crossFileRef = (dfgNode as any).crossFileRef;
      
      if (crossFileRef) {
        // This node references something in another file
        const targetFile = crossFileRef.targetFile;
        const targetSymbol = crossFileRef.targetSymbol;
        const refType = crossFileRef.type;
        
        console.log(`🔗 Following cross-file reference: ${currentFilePath} -> ${targetFile}:${targetSymbol} (${refType})`);
        
        // Get the target file's DFG
        const targetDfg = this.graphs.get(targetFile);
        if (!targetDfg) {
          console.warn(`⚠️ Target DFG not found for ${targetFile}`);
          continue;
        }
        
        // Check if the target symbol is involved in any vulnerabilities
        const targetAst = this.asts.get(targetFile);
        if (targetAst) {
          const targetVulns = targetDfg.performCompleteAnalysis(targetAst);
          
          // Look for vulnerabilities that might be related to the cross-file reference
          for (const targetVuln of targetVulns) {
            if (this.isVulnerabilityRelatedToCrossFileRef(targetVuln, targetSymbol, refType)) {
              // Create a new cross-file vulnerability
              const crossFileVuln: DataFlowVulnerability & { crossFileContext?: any } = {
                ...targetVuln,
                id: `cross-file-${currentFilePath}-${targetFile}-${targetVuln.id}`,
                message: `Cross-file data flow vulnerability: ${currentFilePath} -> ${targetFile}. ${targetVuln.message}`,
                description: `${targetVuln.description} This vulnerability spans across files from ${currentFilePath} to ${targetFile}.`,
                file: currentFilePath, // Mark as originating from current file
                crossFileContext: {
                  sourceFile: currentFilePath,
                  targetFile: targetFile,
                  targetSymbol: targetSymbol,
                  referenceType: refType,
                  originalVulnerability: targetVuln
                }
              };
              
              crossFileVulns.push(crossFileVuln);
              console.log(`🚨 Cross-file vulnerability detected: ${crossFileVuln.id}`);
            }
          }
        }
      }
    }
    
    return crossFileVulns;
  }

  /**
   * Determine if a vulnerability is related to a cross-file reference
   */
  private isVulnerabilityRelatedToCrossFileRef(
    vulnerability: DataFlowVulnerability, 
    targetSymbol: string, 
    refType: string
  ): boolean {
    // Check if the vulnerability involves the target symbol
    const sourceId = vulnerability.source?.id || '';
    const sinkId = vulnerability.sink?.id || '';
    
    // Simple heuristic: if the target symbol appears in source or sink identifiers
    if (sourceId.includes(targetSymbol) || sinkId.includes(targetSymbol)) {
      return true;
    }
    
    // For function calls, check if the vulnerability is related to the called function
    if (refType === 'function_call' && (
      vulnerability.message.includes(targetSymbol) ||
      vulnerability.description.includes(targetSymbol)
    )) {
      return true;
    }
    
    // For variable references, check if the vulnerability involves the variable
    if (refType === 'variable_ref' && (
      sourceId.includes(targetSymbol) || 
      sinkId.includes(targetSymbol)
    )) {
      return true;
    }
    
    return false;
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
      const workspaceVulnerabilities = this.analyzeWorkspaceDataFlow();

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
    
    return this.analyzeWorkspaceDataFlow();
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
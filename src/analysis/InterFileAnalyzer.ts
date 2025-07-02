import { WorkspaceDataFlowGraph } from './WorkspaceDataFlowGraph';
import { ASTParser } from '../parser/ASTParser';
import { SecurityRuleEngine } from '../rules/SecurityRuleEngine';
import { 
  FileAnalysisResult, 
  WorkspaceScanResult, 
  ScanResult, 
  DataFlowVulnerability,
  CrossFileDataFlow,
  AstNode,
  PythonFunction
} from '../types';
import { SanitizerDetector, SinkDetector, SourceDetector } from './detectors';
import * as vscode from 'vscode';
import * as fs from 'fs';

export class InterFileAnalyzer {
  private workspaceGraph: WorkspaceDataFlowGraph;
  private astParser: ASTParser;
  private ruleEngine: SecurityRuleEngine;
  private sourceDetector: SourceDetector;
  private sinkDetector: SinkDetector;
  private sanitizerDetector: SanitizerDetector;
  
  constructor(private workspaceRoot: string, private apiKey: string) {
    this.workspaceGraph = new WorkspaceDataFlowGraph(workspaceRoot);
    this.astParser = new ASTParser();
    this.ruleEngine = new SecurityRuleEngine(apiKey);
    this.sourceDetector = new SourceDetector();
    this.sinkDetector = new SinkDetector();
    this.sanitizerDetector = new SanitizerDetector();
  }

  /**
   * Analyzes the entire workspace for cross-file vulnerabilities
   */
  public async analyzeWorkspace(fileUris: vscode.Uri[]): Promise<WorkspaceScanResult> {
    const startTime = Date.now();
    
    try {
      // Reset workspace analysis
      this.workspaceGraph.reset();
      
      // Phase 1: Analyze each file individually
      const fileResults = await this.analyzeIndividualFiles(fileUris);
      
      // Phase 2: Build cross-file connections
      this.workspaceGraph.buildCrossFileConnections();
      
      // Phase 3: Propagate taint across the workspace
      this.workspaceGraph.propagateTaintAcrossWorkspace();
      
      // Phase 4: Detect vulnerabilities
      const allVulnerabilities = this.workspaceGraph.detectWorkspaceVulnerabilities();
      
      // Separate local and cross-file vulnerabilities
      const crossFileVulns = allVulnerabilities.filter(v => v.rule === 'CROSS_FILE_TAINTED_SINK');
      const localVulns = allVulnerabilities.filter(v => v.rule !== 'CROSS_FILE_TAINTED_SINK');
      
      // Update file results with local vulnerabilities
      this.updateFileResultsWithVulnerabilities(fileResults, localVulns);
      
      // Get analysis statistics
      const stats = this.workspaceGraph.getAnalysisStatistics();
      const crossFileDataFlows = this.workspaceGraph.getCrossFileDataFlows();
      
      const result: WorkspaceScanResult = {
        fileResults: fileResults.map(fr => this.convertToScanResult(fr)),
        crossFileVulnerabilities: crossFileVulns,
        totalFiles: stats.totalFiles,
        totalVulnerabilities: allVulnerabilities.length,
        interFileConnections: crossFileDataFlows,
        scanTime: Date.now() - startTime
      };

      return result;
      
    } catch (error) {
      throw new Error(`Inter-file analysis failed: ${error instanceof Error ? error.message : 'Unknown error'}`);
    }
  }

  /**
   * Analyzes individual files and builds file analysis results
   */
  private async analyzeIndividualFiles(fileUris: vscode.Uri[]): Promise<FileAnalysisResult[]> {
    const fileResults: FileAnalysisResult[] = [];

    for (const fileUri of fileUris) {
      try {
        const fileResult = await this.analyzeFile(fileUri.fsPath);
        if (fileResult) {
          fileResults.push(fileResult);
          
          // Add to workspace graph
          this.workspaceGraph.analyzeFile(fileResult);
        }
      } catch (error) {
        console.error(`Failed to analyze file ${fileUri.fsPath}:`, error);
      }
    }

    return fileResults;
  }

  /**
   * Analyzes a single file and returns its analysis result
   */
  private async analyzeFile(filePath: string): Promise<FileAnalysisResult | null> {
    try {
      // Read file content
      const content = fs.readFileSync(filePath, 'utf8');
      const languageId = this.getLanguageFromPath(filePath);
      
      if (languageId !== 'python') {
        return null; // Only handle Python files for now
      }

      // Parse AST
      const ast = this.astParser.parse(content, languageId, filePath);
      if (!ast) {
        return null;
      }

      // Extract functions
      const functions = this.astParser.extractPythonFunctionsFromAST(ast);

      // Detect sources, sinks, and sanitizers
      const sources = this.extractDetectionsFromAST(ast, 'source');
      const sinks = this.extractDetectionsFromAST(ast, 'sink');
      const sanitizers = this.extractDetectionsFromAST(ast, 'sanitizer');

      const fileResult: FileAnalysisResult = {
        filePath,
        ast,
        imports: [], // Will be populated by WorkspaceDataFlowGraph
        exports: [], // Will be populated by WorkspaceDataFlowGraph
        functions,
        sources,
        sinks,
        sanitizers,
        localVulnerabilities: []
      };

      return fileResult;

    } catch (error) {
      console.error(`Error analyzing file ${filePath}:`, error);
      return null;
    }
  }

  /**
   * Extracts sources, sinks, or sanitizers from an AST
   */
  private extractDetectionsFromAST(ast: AstNode, type: 'source' | 'sink' | 'sanitizer'): any[] {
    const detections: any[] = [];
    
    this.traverseAST(ast, (node) => {
      let detection = null;
      
      switch (type) {
        case 'source':
          detection = this.sourceDetector.detectSource(node);
          break;
        case 'sink':
          detection = this.sinkDetector.detectSink(node);
          break;
        case 'sanitizer':
          detection = this.sanitizerDetector.detectSanitizer(node);
          break;
      }
      
      if (detection) {
        detections.push(detection);
      }
    });
    
    return detections;
  }

  /**
   * Traverses an AST node and calls callback for each node
   */
  private traverseAST(node: AstNode, callback: (node: AstNode) => void): void {
    callback(node);
    for (const child of node.children || []) {
      this.traverseAST(child, callback);
    }
  }

  /**
   * Updates file results with detected vulnerabilities
   */
  private updateFileResultsWithVulnerabilities(
    fileResults: FileAnalysisResult[], 
    vulnerabilities: DataFlowVulnerability[]
  ): void {
    const vulnsByFile = new Map<string, DataFlowVulnerability[]>();
    
    // Group vulnerabilities by file
    for (const vuln of vulnerabilities) {
      if (!vulnsByFile.has(vuln.file)) {
        vulnsByFile.set(vuln.file, []);
      }
      vulnsByFile.get(vuln.file)!.push(vuln);
    }
    
    // Update file results
    for (const fileResult of fileResults) {
      const fileVulns = vulnsByFile.get(fileResult.filePath) || [];
      fileResult.localVulnerabilities = fileVulns;
    }
  }

  /**
   * Converts FileAnalysisResult to ScanResult for backwards compatibility
   */
  private convertToScanResult(fileResult: FileAnalysisResult): ScanResult {
    return {
      file: fileResult.filePath,
      patternVulnerabilities: [], // Pattern vulnerabilities would be handled separately
      dataFlowVulnerabilities: fileResult.localVulnerabilities,
      scanTime: 0, // Individual file scan time not tracked in this context
      linesScanned: this.countLines(fileResult.ast.content),
      language: 'python'
    };
  }

  /**
   * Counts lines in content
   */
  private countLines(content: string): number {
    return content.split('\n').length;
  }

  /**
   * Gets language from file path
   */
  private getLanguageFromPath(filePath: string): string {
    const extension = filePath.split('.').pop()?.toLowerCase();
    switch (extension) {
      case 'py':
        return 'python';
      case 'js':
      case 'jsx':
        return 'javascript';
      case 'ts':
      case 'tsx':
        return 'typescript';
      default:
        return 'unknown';
    }
  }

  /**
   * Gets inter-file analysis statistics
   */
  public getAnalysisStatistics(): {
    totalFiles: number;
    totalNodes: number;
    crossFileConnections: number;
    vulnerableFiles: string[];
  } {
    return this.workspaceGraph.getAnalysisStatistics();
  }

  /**
   * Gets cross-file data flows for reporting
   */
  public getCrossFileDataFlows(): CrossFileDataFlow[] {
    return this.workspaceGraph.getCrossFileDataFlows();
  }

  /**
   * Resets the analyzer state
   */
  public reset(): void {
    this.workspaceGraph.reset();
  }
}
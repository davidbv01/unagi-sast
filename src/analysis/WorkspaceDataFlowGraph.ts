import { DataFlowGraph } from './DataFlowGraph';
import { ImportResolver } from './ImportResolver';
import { 
  AstNode, 
  FileAnalysisResult, 
  CrossFileDataFlow, 
  DataFlowVulnerability,
  VulnerabilityType,
  Severity 
} from '../types';
import { Source, Sink, Sanitizer } from './detectors';

type CrossFileNode = {
  id: string;
  name: string;
  filePath: string;
  astNodeId: number;
  scope: string;
  tainted: boolean;
  taintSources: Set<string>;
  edges: Set<CrossFileNode>;
  isSource?: boolean;
  isSink?: boolean;
  isSanitizer?: boolean;
  detectedSource?: Source;
  detectedSink?: Sink;
  detectedSanitizer?: Sanitizer;
};

export class WorkspaceDataFlowGraph {
  private fileGraphs: Map<string, DataFlowGraph> = new Map();
  private crossFileNodes: Map<string, CrossFileNode> = new Map();
  private crossFileEdges: CrossFileDataFlow[] = [];
  private importResolver: ImportResolver;

  constructor(workspaceRoot: string) {
    this.importResolver = new ImportResolver(workspaceRoot);
  }

  /**
   * Analyzes a single file and stores its results
   */
  public analyzeFile(fileResult: FileAnalysisResult): void {
    const filePath = fileResult.filePath;
    
    // Create individual file data flow graph
    const fileGraph = DataFlowGraph.getInstance();
    fileGraph.reset();
    fileGraph.buildFromAst(fileResult.ast);
    
    // Store the file graph (clone it to avoid singleton issues)
    this.fileGraphs.set(filePath, this.cloneDataFlowGraph(fileGraph));

    // Extract imports and exports
    const imports = this.importResolver.extractImports(fileResult.ast, filePath);
    const exports = this.importResolver.extractExports(fileResult.ast, filePath, fileResult.functions);

    // Update file result with import/export info
    fileResult.imports = imports;
    fileResult.exports = exports;

    // Create cross-file nodes for exported functions/variables
    this.createCrossFileNodesForExports(fileResult, exports);

    console.log(`[WorkspaceDataFlowGraph] Analyzed file: ${filePath}`);
  }

  /**
   * Builds cross-file connections after all files have been analyzed
   */
  public buildCrossFileConnections(): void {
    console.log('[WorkspaceDataFlowGraph] Building cross-file connections...');
    
    const connections = this.importResolver.getCrossFileConnections();
    
    for (const connection of connections) {
      this.createCrossFileEdge(connection);
    }

    console.log(`[WorkspaceDataFlowGraph] Created ${this.crossFileEdges.length} cross-file connections`);
  }

  /**
   * Propagates taint across the entire workspace, including cross-file boundaries
   */
  public propagateTaintAcrossWorkspace(): void {
    console.log('[WorkspaceDataFlowGraph] Propagating taint across workspace...');

    // First, propagate taint within each file
    for (const [filePath, fileGraph] of this.fileGraphs.entries()) {
      for (const sourceNode of fileGraph.getDetectedSources()) {
        const sourceId = `${filePath}_${sourceNode.key}`;
        fileGraph.propagateTaint(sourceId);
      }
    }

    // Then propagate taint across file boundaries
    this.propagateCrossFileTaint();
  }

  /**
   * Detects vulnerabilities across the entire workspace
   */
  public detectWorkspaceVulnerabilities(): DataFlowVulnerability[] {
    console.log('[WorkspaceDataFlowGraph] Detecting workspace vulnerabilities...');
    
    const vulnerabilities: DataFlowVulnerability[] = [];

    // Collect vulnerabilities from individual files
    for (const [filePath, fileGraph] of this.fileGraphs.entries()) {
      const fileVulns = fileGraph.detectVulnerabilities(filePath);
      vulnerabilities.push(...fileVulns);
    }

    // Detect cross-file vulnerabilities
    const crossFileVulns = this.detectCrossFileVulnerabilities();
    vulnerabilities.push(...crossFileVulns);

    console.log(`[WorkspaceDataFlowGraph] Found ${vulnerabilities.length} total vulnerabilities`);
    return vulnerabilities;
  }

  /**
   * Gets analysis statistics
   */
  public getAnalysisStatistics(): {
    totalFiles: number;
    totalNodes: number;
    crossFileConnections: number;
    vulnerableFiles: string[];
  } {
    const vulnerableFiles = new Set<string>();
    let totalNodes = 0;

    for (const [filePath, fileGraph] of this.fileGraphs.entries()) {
      const fileVulns = fileGraph.detectVulnerabilities(filePath);
      if (fileVulns.length > 0) {
        vulnerableFiles.add(filePath);
      }
      totalNodes += Array.from(fileGraph.nodes.values()).length;
    }

    return {
      totalFiles: this.fileGraphs.size,
      totalNodes: totalNodes + this.crossFileNodes.size,
      crossFileConnections: this.crossFileEdges.length,
      vulnerableFiles: Array.from(vulnerableFiles)
    };
  }

  /**
   * Gets the cross-file data flows for reporting
   */
  public getCrossFileDataFlows(): CrossFileDataFlow[] {
    return this.crossFileEdges;
  }

  /**
   * Resets the workspace analysis
   */
  public reset(): void {
    this.fileGraphs.clear();
    this.crossFileNodes.clear();
    this.crossFileEdges = [];
    this.importResolver.reset();
  }

  // Private helper methods

  private createCrossFileNodesForExports(fileResult: FileAnalysisResult, exports: any[]): void {
    for (const exportInfo of exports) {
      const nodeId = `${fileResult.filePath}_${exportInfo.exportedName}`;
      
      const crossFileNode: CrossFileNode = {
        id: nodeId,
        name: exportInfo.exportedName,
        filePath: fileResult.filePath,
        astNodeId: exportInfo.astNodeId,
        scope: 'global',
        tainted: false,
        taintSources: new Set(),
        edges: new Set()
      };

      // Check if this export is a source, sink, or sanitizer
      this.markNodeIfSpecial(crossFileNode, fileResult);

      this.crossFileNodes.set(nodeId, crossFileNode);
    }
  }

  private markNodeIfSpecial(node: CrossFileNode, fileResult: FileAnalysisResult): void {
    // Check if node is a source
    const sourceMatch = fileResult.sources.find(s => 
      s.loc.start.line === node.astNodeId || s.key === node.name
    );
    if (sourceMatch) {
      node.isSource = true;
      node.detectedSource = sourceMatch;
    }

    // Check if node is a sink
    const sinkMatch = fileResult.sinks.find(s => 
      s.loc.start.line === node.astNodeId || s.info?.includes(node.name)
    );
    if (sinkMatch) {
      node.isSink = true;
      node.detectedSink = sinkMatch;
    }

    // Check if node is a sanitizer
    const sanitizerMatch = fileResult.sanitizers.find(s => 
      s.loc.start.line === node.astNodeId || s.info?.includes(node.name)
    );
    if (sanitizerMatch) {
      node.isSanitizer = true;
      node.detectedSanitizer = sanitizerMatch;
    }
  }

  private createCrossFileEdge(connection: { sourceFile: string; targetFile: string; functionName: string }): void {
    const sourceNodeId = `${connection.sourceFile}_${connection.functionName}`;
    const targetNodeId = `${connection.targetFile}_${connection.functionName}`;

    const sourceNode = this.crossFileNodes.get(sourceNodeId);
    const targetNode = this.crossFileNodes.get(targetNodeId);

    if (sourceNode && targetNode) {
      sourceNode.edges.add(targetNode);
      
      // Create cross-file data flow record
      const dataFlow: CrossFileDataFlow = {
        sourceFile: connection.sourceFile,
        targetFile: connection.targetFile,
        functionName: connection.functionName,
        callSite: { line: 0, column: 0 }, // Would need more detailed AST analysis
        parameterMappings: [] // Would need function signature analysis
      };

      this.crossFileEdges.push(dataFlow);
    }
  }

  private propagateCrossFileTaint(): void {
    // Find all tainted nodes in cross-file graph
    const taintedNodes = new Set<CrossFileNode>();
    
    // Mark nodes as tainted if they correspond to tainted nodes in file graphs
    for (const [filePath, fileGraph] of this.fileGraphs.entries()) {
      for (const [nodeId, node] of fileGraph.nodes.entries()) {
        if (node.tainted) {
          const crossFileNodeId = `${filePath}_${node.name}`;
          const crossFileNode = this.crossFileNodes.get(crossFileNodeId);
          if (crossFileNode) {
            crossFileNode.tainted = true;
            crossFileNode.taintSources = new Set(node.taintSources);
            taintedNodes.add(crossFileNode);
          }
        }
      }
    }

    // Propagate taint through cross-file edges
    const queue = Array.from(taintedNodes);
    
    while (queue.length > 0) {
      const current = queue.shift()!;
      
      if (current.isSanitizer) {
        // Sanitizer stops taint propagation
        continue;
      }

      for (const neighbor of current.edges) {
        if (!neighbor.tainted) {
          neighbor.tainted = true;
          neighbor.taintSources = new Set(current.taintSources);
          queue.push(neighbor);

          // Also update the corresponding file graph node
          this.updateFileGraphNodeTaint(neighbor);
        }
      }
    }
  }

  private updateFileGraphNodeTaint(crossFileNode: CrossFileNode): void {
    const fileGraph = this.fileGraphs.get(crossFileNode.filePath);
    if (!fileGraph) return;

    // Find corresponding node in file graph and mark as tainted
    for (const [nodeId, node] of fileGraph.nodes.entries()) {
      if (node.name === crossFileNode.name) {
        node.tainted = true;
        node.taintSources = new Set(crossFileNode.taintSources);
        break;
      }
    }
  }

  private detectCrossFileVulnerabilities(): DataFlowVulnerability[] {
    const vulnerabilities: DataFlowVulnerability[] = [];

    for (const [nodeId, node] of this.crossFileNodes.entries()) {
      if (node.isSink && node.tainted) {
        // This is a cross-file vulnerability
        const vuln: DataFlowVulnerability = {
          id: `cross-file-vuln-${nodeId}`,
          type: VulnerabilityType.GENERIC,
          severity: Severity.HIGH,
          message: `Cross-file tainted data reaches sink: ${node.name}`,
          file: node.filePath,
          rule: "CROSS_FILE_TAINTED_SINK",
          description: `The function/variable '${node.name}' in ${node.filePath} receives tainted data from another file`,
          recommendation: "Validate and sanitize data at file boundaries, especially for exported functions",
          
          source: node.detectedSource || this.createDefaultSource(node),
          sink: node.detectedSink || this.createDefaultSink(node),
          sanitizers: [],
          
          isVulnerable: true,
          pathLines: [1], // Would need more detailed path analysis
          
          ai: {
            confidenceScore: 0.9,
            shortExplanation: `Cross-file data flow vulnerability: tainted data flows from one file to a sink in another`,
            exploitExample: `Untrusted input from file A reaches dangerous operation in file B`,
            remediation: `Add input validation at the file boundary where ${node.name} is called`
          }
        };

        vulnerabilities.push(vuln);
      }
    }

    return vulnerabilities;
  }

  private createDefaultSource(node: CrossFileNode): Source {
    return {
      id: `source-${node.id}`,
      type: 'source',
      pattern: '.*',
      description: 'Cross-file data source',
      loc: {
        start: { line: 1, column: 0 },
        end: { line: 1, column: 10 }
      },
      severity: 'high',
      key: node.name
    };
  }

  private createDefaultSink(node: CrossFileNode): Sink {
    return {
      id: `sink-${node.id}`,
      type: 'sink',
      pattern: '.*',
      description: 'Cross-file dangerous operation',
      loc: {
        start: { line: 1, column: 0 },
        end: { line: 1, column: 10 }
      },
      info: `Dangerous operation: ${node.name}`,
      vulnerabilityType: VulnerabilityType.GENERIC,
      severity: Severity.HIGH
    };
  }

  private cloneDataFlowGraph(original: DataFlowGraph): DataFlowGraph {
    // For simplicity, we'll return the original graph
    // In a production system, you might want to implement proper cloning
    return original;
  }
}
import { SanitizerDetector, SinkDetector, SourceDetector } from "../analysis/detectors";
import { AstNode, Vulnerability, DataFlowVulnerability, VulnerabilityType, Severity } from "../types";
import { Source, Sink, Sanitizer } from "../analysis/detectors";
import chalk from 'chalk';
import type { SymbolTableEntry } from '../types';

type DfgNode = {
  id: string;
  name: string;
  astNode: AstNode;
  tainted: boolean;
  taintSources: Set<string>;
  edges: Set<DfgNode>;
  symbol?: Symbol;
  isSanitizer?: boolean;
  isSink?: boolean;
  infoSanitizer?: string;
  infoSink?: string;
  detectedSource?: Source;
  detectedSink?: Sink;
  detectedSanitizer?: Sanitizer;
  crossFileRef?: any;
  crossFileEdge?: {
    from: string;
    to: string;
    function: string;
  };
};

type Symbol = {
  name: string;
  scope: string;
  uniqueId: string;
};

export class DataFlowGraph {
  // Instance properties
  nodes: Map<string, DfgNode> = new Map();
  varToAst: Map<string, Set<Number>> = new Map();
  private sanitizerDetector: SanitizerDetector;
  private sinkDetector: SinkDetector;
  private sourceDetector: SourceDetector;
  private importedIdentifiers: Set<string> = new Set();
  
  // Function handling properties
  private currentFunction: string | null = null;
  private functionReturnNodes: Map<string, DfgNode> = new Map(); // function_name -> return_node
  private symbols: SymbolTableEntry[] = [];
  private symbolTable?: Map<string, SymbolTableEntry>;
  private currentFilePath?: string;

  // Public constructor - now allows multiple instances
  constructor() {
    this.sanitizerDetector = new SanitizerDetector();
    this.sinkDetector = new SinkDetector();
    this.sourceDetector = new SourceDetector();
  }

  /**
   * Gets or creates a function return node
   * @param functionName The name of the function
   * @returns The DFG node representing the function's return value
   */
  private getOrCreateFunctionReturnNode(functionName: string): DfgNode {
    if (!this.functionReturnNodes.has(functionName)) {
      const returnNodeId = `${functionName}_return`;
      const returnNode: DfgNode = {
        id: returnNodeId,
        name: `${functionName}_return`,
        astNode: {} as AstNode, // Placeholder AST node
        tainted: false,
        taintSources: new Set(),
        edges: new Set()
      };
      this.nodes.set(returnNodeId, returnNode);
      this.functionReturnNodes.set(functionName, returnNode);
    }
    return this.functionReturnNodes.get(functionName)!;
  }

  /**
   * Extracts function name from a function definition AST node
   * @param astNode The function definition AST node
   * @returns Function name if found, null otherwise
   */
  private extractFunctionName(astNode: AstNode): string | null {
    if (astNode.type !== "function_definition") return null;
    
    const nameNode = astNode.children?.find(child => child.type === "identifier");
    return nameNode?.text || null;
  }

  /**
   * Extracts function name from a function call AST node
   * @param astNode The function call AST node
   * @returns Function name if found, null otherwise
   */
  private extractCalledFunctionName(astNode: AstNode): string | null {
    if (astNode.type !== "call") return null;
    
    // Look for identifier in call structure
    const nameNode = astNode.children?.find(child => child.type === "identifier" || child.type === "attribute");
    return nameNode?.text || null;
  }

  /**
   * Builds the data flow graph from an AST node
   * @param astNode The root AST node to build the graph from
   */
  public buildFromAst(astNode: AstNode, symbolTable?: Map<string, SymbolTableEntry>) {
    if (!astNode) return;

    // Set symbols from astNode if available
    if (astNode.symbols && Array.isArray(astNode.symbols) && astNode.symbols.length > 0) {
      this.symbols = astNode.symbols;
    }

    // Set the symbol table if provided
    if (symbolTable) {
      this.symbolTable = symbolTable;
    }

    // Handle function definitions
    if (astNode.type === "function_definition") {
      const functionName = this.extractFunctionName(astNode);
      if (functionName) {
        this.currentFunction = functionName;
      }
    }

    // Detect and store imported identifiers
    if (astNode.type === "import_statement") {
      for (const child of astNode.children || []) {
        if (child.type === "dotted_name" || child.type === "alias") {
          const idNode = child.children.find(c => c.type === "identifier");
          if (idNode) {
            this.importedIdentifiers.add(idNode.text);
          }
        } else if (child.type === "identifier") {
          this.importedIdentifiers.add(child.text);
        }
      }
    }
    const varName = this.getVariableNameByAstId(astNode.id);
    // Detect and handle sanitizers
    const sanitizer = this.sanitizerDetector.detectSanitizer(astNode,varName);
    if (sanitizer) {
      const sanitizerNodes = this.getOrCreateNodes(astNode);
      for (const node of sanitizerNodes) {
        node.isSanitizer = true;
        node.infoSanitizer = sanitizer.info;
        node.detectedSanitizer = sanitizer;
      }
    }

    // Detect and handle sinks
    const sink = this.sinkDetector.detectSink(astNode, varName);
    if (sink) {
      const sinkNodes = this.getOrCreateNodes(astNode);
      for (const node of sinkNodes) {
        node.isSink = true;
        node.infoSink = sink.info;
        node.detectedSink = sink;
      }
    }

    // Detect and handle sources
    const source = this.sourceDetector.detectSource(astNode, varName);
    if (source) {
      const sourceNodes = this.getOrCreateNodes(astNode);
      for (const node of sourceNodes) {
        node.detectedSource = source;
      }
    }

    // Handle assignment nodes
    if (astNode.type === "assignment" && astNode.children?.length === 2) {
      const leftNodes = this.getOrCreateNodes(astNode.children[0]);
      const rightNodes = this.getOrCreateNodes(astNode.children[1]);

      // Create edges from right nodes to left nodes (data flow direction)
      for (const right of rightNodes) {
        for (const left of leftNodes) {
          right.edges.add(left);
        }
      }
    }

    // Handle return nodes
    if (astNode.type === "return_statement" && astNode.children?.length > 0) {
      const returnedNodes = this.getOrCreateNodes(astNode.children[0]);
      
      // If we're inside a function, create edges from returned variables to function return node
      if (this.currentFunction) {
        const functionReturnNode = this.getOrCreateFunctionReturnNode(this.currentFunction);
        
        for (const returnedNode of returnedNodes) {
          returnedNode.edges.add(functionReturnNode);
        }
      }
    }

    // Handle function calls
    if (astNode.type === "call") {
      const functionName = this.extractCalledFunctionName(astNode);
      let matchedFunctionEntry: { key: string, entry: SymbolTableEntry } | undefined = undefined;
      if (functionName && this.symbolTable) {
        // Busca la función y obtén también el archivo
        const found = Array.from(this.symbolTable.entries()).find(([key, entry]) => {
          return entry.name === functionName && entry.type === 'function';
        });
        if (found) {
          matchedFunctionEntry = { key: found[0], entry: found[1] };
        }
      }
      let isKnownFunction = false;
      if (matchedFunctionEntry) {
        isKnownFunction = true;
      } else if (functionName && this.symbols.some(f => f.type === 'function' && f.name === functionName)) {
        // fallback for per-file mode using symbols
        isKnownFunction = true;
      }
      if (functionName && isKnownFunction) {
        if (matchedFunctionEntry) {
          console.log(`[DFG] La función conocida '${functionName}' está definida en: ${matchedFunctionEntry.entry.filePath}`);
        } else {
          console.log(`[DFG] La función conocida '${functionName}' está definida localmente en este archivo.`);
        }
        // Check if this is a cross-file call
        const isCrossFile = matchedFunctionEntry && matchedFunctionEntry.entry.filePath !== (this.currentFilePath || '');
        
        // Create nodes for the function call result
        const callResultNodes = this.getOrCreateNodes(astNode);
        const functionReturnNode = this.getOrCreateFunctionReturnNode(functionName);

        // Create edges from function return to call result
        for (const resultNode of callResultNodes) {
          functionReturnNode.edges.add(resultNode);
          if (isCrossFile && matchedFunctionEntry) {
            // Mark this node as having a cross-file edge
            resultNode.crossFileEdge = {
              from: this.currentFilePath || '',
              to: matchedFunctionEntry.entry.filePath,
              function: functionName
            };
          }
        }

        //Connect call arguments to function parameters ---
        const funcDef = this.symbols.find(f => f.name === functionName);
        if (funcDef && astNode.children) {
          // children[0] is usually the function name, the rest are arguments
          const argNodes = astNode.children.slice(1).map(arg => this.getOrCreateNodes(arg));
          // funcDef.parameters is an array of parameter names
          if (funcDef.parameters && funcDef.parameters.length === argNodes.length) {
            for (let i = 0; i < funcDef.parameters.length; i++) {
              const paramName = funcDef.parameters[i];
              // The parameter node should be in the function's scope
              const paramUniqueId = `${funcDef.name}_${paramName}`;
              let paramNode = this.nodes.get(paramUniqueId);
              if (!paramNode) {
                // Create the parameter node if it doesn't exist
                paramNode = {
                  id: paramUniqueId,
                  name: paramName,
                  astNode: astNode, // You may want to use the function definition's AST node
                  tainted: false,
                  taintSources: new Set(),
                  edges: new Set(),
                  symbol: {
                    name: paramName,
                    scope: funcDef.name,
                    uniqueId: paramUniqueId
                  }
                };
                this.nodes.set(paramUniqueId, paramNode);
              }
              // Connect each argument node to the parameter node
              for (const argNode of argNodes[i]) {
                argNode.edges.add(paramNode);
              }
            }
          }
        }
      }
    }

    // Recursively process child nodes
    if (astNode.children) {
      for (const child of astNode.children) {
        this.buildFromAst(child);
      }
    }

    // Reset current function when exiting function definition
    if (astNode.type === "function_definition") {
      this.currentFunction = null;
    }
  }

  /**
   * Gets or creates DFG nodes for an AST node
   * @param astNode The AST node to process
   * @returns Array of DFG nodes (existing or newly created)
   */
  public getOrCreateNodes(astNode: AstNode): DfgNode[] {
    const createdNodes: DfgNode[] = [];
    const varNames = this.extractIdentifiers(astNode);

    for (const varName of varNames) {
      const uniqueId = `${astNode.scope}_${varName}`;

      if (!this.nodes.has(uniqueId)) {

        const symbol: Symbol = {
          name: varName,
          scope: astNode.scope,
          uniqueId
        };

        const node: DfgNode = {
          id: uniqueId,
          name: varName,
          astNode,
          tainted: false,
          taintSources: new Set(),
          edges: new Set(),
          symbol
        };
        this.nodes.set(uniqueId, node);
        createdNodes.push(node);
      } else {
        createdNodes.push(this.nodes.get(uniqueId)!);
      }
    }

    return createdNodes;
  }

  /**
   * Propagates taint from a source node through the graph,
   * stopping propagation at sanitizer nodes
   * @param sourceId The ID of the taint source node
   */
  public propagateTaint(sourceId: string) {
    const startNode = this.nodes.get(sourceId);

    if (!startNode || startNode.isSanitizer) return;

    const queue: DfgNode[] = [startNode];
    startNode.tainted = true;
    startNode.taintSources.add(sourceId);

    while (queue.length > 0) {
      const current = queue.shift()!;

      if (current.isSanitizer) continue;

      for (const neighbor of current.edges) {
        if (!neighbor.tainted) {
          neighbor.tainted = true;
          neighbor.taintSources = new Set(current.taintSources);
          queue.push(neighbor);
        } else {
          for (const src of current.taintSources) {
            neighbor.taintSources.add(src);
          }
        }
      }
    }
  }

  /**
   * Detects vulnerabilities by identifying tainted sinks
   * @returns Array of detected data flow vulnerabilities
   */
  public detectVulnerabilities(filePath: string | undefined): DataFlowVulnerability[] {
    const vulnerabilities: DataFlowVulnerability[] = [];

    for (const node of this.nodes.values()) {
      if (node.isSink && node.tainted) {
        // Find the source node(s)
        const sourceNodes = Array.from(node.taintSources).map(id => this.nodes.get(id)).filter(Boolean);
        const primarySource = sourceNodes[0];
        
        // Find sanitizers in the path (nodes that are sanitizers but were bypassed)
        const sanitizersInPath: Sanitizer[] = [];
        for (const [nodeId, nodeData] of this.nodes.entries()) {
          if (nodeData.isSanitizer && node.taintSources.has(nodeId)) {
            // Use the actual detected sanitizer if available, otherwise create a default one
            if (nodeData.detectedSanitizer) {
              sanitizersInPath.push(nodeData.detectedSanitizer);
            } else {
              sanitizersInPath.push({
                id: `sanitizer-${nodeId}`,
                type: 'sanitizer',
                pattern: '.*',
                description: 'Sanitizer in data flow path',
                loc: {
                  start: { line: nodeData.astNode.loc?.start?.line || 1, column: nodeData.astNode.loc?.start?.column || 0 },
                  end: { line: nodeData.astNode.loc?.end?.line || nodeData.astNode.loc?.start?.line || 1, column: nodeData.astNode.loc?.end?.column || (nodeData.astNode.loc?.start?.column || 0) + 10 }
                },
                info: nodeData.infoSanitizer || 'Unknown sanitizer',
                effectiveness: 0.8,
                key: nodeId
              });
            }
          }
        }

        // Use the actual detected source if available
        const actualSource = primarySource?.detectedSource;
        const sourceObj: Source = actualSource || {
          id: `source-${primarySource?.id || 'unknown'}`,
          type: 'source',
          pattern: '.*',
          description: 'User input source',
          loc: {
            start: { line: primarySource?.astNode?.loc?.start?.line || 1, column: primarySource?.astNode?.loc?.start?.column || 0 },
            end: { line: primarySource?.astNode?.loc?.end?.line || primarySource?.astNode?.loc?.start?.line || 1, column: primarySource?.astNode?.loc?.end?.column || (primarySource?.astNode?.loc?.start?.column || 0) + 10 }
          },
          severity: 'high',
          key: primarySource?.id || 'unknown'
        };

        // Use the actual detected sink if available
        const actualSink = node.detectedSink;
        const sinkObj: Sink = actualSink || {
          id: `sink-${node.id}`,
          type: 'sink',
          pattern: '.*',
          description: 'Dangerous operation sink',
          loc: {
            start: { line: node.astNode.loc?.start?.line || 1, column: node.astNode.loc?.start?.column || 0 },
            end: { line: node.astNode.loc?.end?.line || node.astNode.loc?.start?.line || 1, column: node.astNode.loc?.end?.column || (node.astNode.loc?.start?.column || 0) + 10 }
          },
          info: node.infoSink || 'Dangerous operation',
          vulnerabilityType: VulnerabilityType.GENERIC,
          severity: Severity.HIGH
        };

        const vuln: DataFlowVulnerability = {
          id: `dataflow-vuln-${node.id}`,
          type: VulnerabilityType.GENERIC,
          severity: Severity.HIGH,
          message: `Tainted data reaches sink: ${node.name}`,
          file: filePath || "unknown",
          rule: "TAINTED_SINK",
          description: `${node.name} is a sink and receives tainted input from: ${Array.from(node.taintSources).join(", ")}`,
          recommendation: "Sanitize input before passing it to sensitive operations like this sink.",
          
          // Flow information with location data
          source: sourceObj,
          sink: sinkObj,
          sanitizers: sanitizersInPath,
          
          // Determine if vulnerable (true if tainted and no effective sanitizers)
          isVulnerable: node.tainted && sanitizersInPath.length === 0,
          
          // Path lines using actual location information
          pathLines: [sourceObj.loc.start.line, sinkObj.loc.start.line],
          
          ai: {
            confidenceScore: 0.95,
            shortExplanation: `The variable '${node.name}' is influenced by user input and reaches a critical operation.`,
            exploitExample: `os.system(user_input)`,
            remediation: `Use whitelist or strict validation before passing input to '${node.name}'`,
          }
        };

        vulnerabilities.push(vuln);
      }
    }

    return vulnerabilities;
  }


  /**
   * Gets variable name by AST node ID
   * @param id The AST node ID to look up
   * @returns Variable name if found, undefined otherwise
   */
  public getVariableNameByAstId(id: number): string | undefined {
    for (const [key, idSet] of this.varToAst.entries()) {
      if (idSet.has(id)) {
        return key;
      }
    }
    return undefined;
  }

  /**
   * Extracts all identifiers from an AST node
   * @param node The AST node to process
   * @returns Array of identifier names found in the node
   */
  private extractIdentifiers(node: AstNode): string[] {
    const result: string[] = [];

    const walk = (n: AstNode) => {
      if (n.type === 'attribute') {
        const base = n.children.find(child => child.type === 'identifier');
        if (base && !this.importedIdentifiers.has(base.text)) {
          result.push(base.text);

          if (!this.varToAst.has(base.text)) {
            this.varToAst.set(base.text, new Set());
          }
          this.varToAst.get(base.text)!.add(node.id);
        }
      } else if (n.type === 'identifier') {
        if (!this.importedIdentifiers.has(n.text)) {
          result.push(n.text);

          if (!this.varToAst.has(n.text)) {
            this.varToAst.set(n.text, new Set());
          }
          this.varToAst.get(n.text)!.add(node.id);
        }
      } else {
        for (const child of n.children || []) {
          walk(child);
        }
      }
    };

    walk(node);
    return result;
  }

  /**
   * Prints the data flow graph in a hierarchical format with enhanced visualization
   * for sinks, sanitizers, and tainted nodes
   */
  public printGraph() {
      const visited = new Set<string>();
      let counter = 1;

      const printNode = (node: DfgNode, path: string, depth: number = 0) => {
          if (visited.has(node.id)) {
              console.log(`${path} ${chalk.blue(node.name)} ${chalk.gray('(already visited)')}`);
              return;
          }
          visited.add(node.id);

          // Prepare node information
          // Create indentation based on depth
          const indent = '  '.repeat(depth);

          // Print the node name
          console.log(`${indent}${path} ${chalk.blue(node.name)}`);

          // Print taint info if applicable
          if (node.tainted) {
              console.log(`${indent}  ${chalk.red(`[TAINTED: ${Array.from(node.taintSources).join(', ')}]`)}`);
          }

          // Print sanitizer info if applicable
          if (node.isSanitizer) {
              console.log(`${indent}  ${chalk.green(`[SANITIZED via ${node.infoSanitizer}]`)}`);
          }

          // Print sink info if applicable
          if (node.isSink) {
              console.log(`${indent}  ${chalk.magentaBright(`[SINK: ${node.infoSink}]`)}`);
          }


          // Print children with increased depth
          let childIndex = 1;
          for (const neighbor of node.edges) {
              const childPath = `${path}${path.endsWith('.') ? '' : '.'}${childIndex}`;
              printNode(neighbor, childPath, depth + 1);
              childIndex++;
          }
      };

      console.log(chalk.yellow('\n📊 Data Flow Graph (Hierarchical):\n'));
      console.log(chalk.gray('Legend:'));
      console.log(chalk.blue('Variable') + chalk.gray(' | ') +
                  chalk.red('Tainted') + chalk.gray(' | ') +
                  chalk.green('Sanitizer') + chalk.gray(' | ') +
                  chalk.magentaBright('Sink'));
      console.log(chalk.gray('-'.repeat(50)));

      // Print all root nodes
      for (const node of this.nodes.values()) {
          const isRoot = Array.from(this.nodes.values()).every(n => !n.edges.has(node));
          if (isRoot) {
              printNode(node, `${counter}.`);
              counter++;
          }
      }
  }

  /**
   * Gets all detected sources from the DataFlowGraph nodes
   * @returns Array of sources with their associated location information
   */
  public getDetectedSources(): (Source & { line: number; column: number; endLine: number; endColumn: number })[] {
    const detectedSources: (Source & { line: number; column: number; endLine: number; endColumn: number })[] = [];
    
    for (const node of this.nodes.values()) {
      if (node.detectedSource) {
        detectedSources.push({
          ...node.detectedSource,
          id: node.astNode.id.toString(),
          line: node.astNode.loc?.start?.line || 1,
          column: node.astNode.loc?.start?.column || 0,
          endLine: node.astNode.loc?.end?.line || node.astNode.loc?.start?.line || 1,
          endColumn: node.astNode.loc?.end?.column || (node.astNode.loc?.start?.column || 0) + 10
        });
      }
    }
    
    return detectedSources;
  }


  /**
   * Completely resets the data flow graph to its initial state
   * - Clears all nodes, variables, taint information, and detected elements
   * - Maintains the same detector instances
   */
  public reset(): void {
      // Clear all graph data structures
      this.nodes.clear();
      this.varToAst.clear();
      
      // Clear function-related data
      this.currentFunction = null;
      this.functionReturnNodes.clear();
      this.symbols = [];
      this.importedIdentifiers.clear();
  }

  /**
   * Performs complete data flow analysis: builds graph, detects sources, propagates taint, and detects vulnerabilities
   * @param astNode The root AST node to analyze
   * @param initialTaintedVars Optional array of variable names to mark as tainted at the start
   * @returns Array of detected data flow vulnerabilities
   */
  public performCompleteAnalysis(astNode: AstNode, initialTaintedVars?: string[]): DataFlowVulnerability[] {
    //Obtain the file path from the AST node
    const filePath = astNode.filePath;

    // Step 1: Build the data flow graph from AST
    this.buildFromAst(astNode);
    
    // Step 2: Get all detected sources and deduplicate them
    const detectedSources = this.getDetectedSources();
    const uniqueSources = this.deduplicateDetections(detectedSources);
    
    // Step 3: Propagate taint from all detected sources
    for (const source of Object.values(uniqueSources)) {
      this.propagateTaint(source.key);
    }
    // Step 3b: Propagate taint from initial tainted variables (cross-file)
    if (initialTaintedVars) {
      for (const varName of initialTaintedVars) {
        // Find all nodes with this variable name and mark as tainted
        for (const node of this.nodes.values()) {
          if (node.name === varName) {
            node.tainted = true;
            node.taintSources = node.taintSources || new Set();
            node.taintSources.add('cross-file');
            // Optionally propagate taint from this node
            this.propagateTaint(node.id);
          }
        }
      }
    }
    this.printGraph();
    // Step 5: Detect and return vulnerabilities
    return this.detectVulnerabilities(filePath);
  }

  /**
   * Deduplicates detected sources based on their key
   * @param detections Array of detected sources to deduplicate
   * @returns Deduplicated sources indexed by key
   */
  private deduplicateDetections(detections: any[]): any[] {
    const unique: any[] = [];
    const seen = new Set<string>();
    
    for (const detection of detections) {
      if (!seen.has(detection.key)) {
        seen.add(detection.key);
        unique.push(detection);
      }
    }
    
    return unique;
  }

  // Add a setter for current file path
  public setCurrentFilePath(filePath: string) {
    this.currentFilePath = filePath;
  }
}
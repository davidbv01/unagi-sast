import { SanitizerDetector, SinkDetector, SourceDetector } from "../analysis/detectors";
import { AstNode, DataFlowVulnerability, VulnerabilityType, Severity, Source, Sink, Sanitizer, SymbolTableEntry, DfgNode, Symbol } from "../types";
import chalk from 'chalk';

/**
 * Represents a data flow graph for taint analysis and vulnerability detection.
 */
export class DataFlowGraph {
  /** All nodes in the data flow graph, keyed by unique ID. */
  public readonly nodes: Map<string, DfgNode> = new Map();
  /** Maps variable names to AST node IDs. */
  public readonly varToAst: Map<string, Set<number>> = new Map();
  private readonly sanitizerDetector: SanitizerDetector;
  private readonly sinkDetector: SinkDetector;
  private readonly sourceDetector: SourceDetector;
  private readonly importedIdentifiers: Set<string> = new Set();
  private currentFunction: string | null = null;
  private readonly functionReturnNodes: Map<string, DfgNode> = new Map();
  private symbols: SymbolTableEntry[] = [];
  private symbolTable?: Map<string, SymbolTableEntry>;
  private currentFilePath?: string;

  /**
   * Creates a new DataFlowGraph instance.
   */
  constructor() {
    this.sanitizerDetector = new SanitizerDetector();
    this.sinkDetector = new SinkDetector();
    this.sourceDetector = new SourceDetector();
  }

  /**
   * Gets or creates a function return node.
   * @param functionName The name of the function.
   * @returns The DFG node representing the function's return value.
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
   * Extracts function name from a function definition AST node.
   * @param astNode The function definition AST node.
   * @returns Function name if found, null otherwise.
   */
  private extractFunctionName(astNode: AstNode): string | null {
    if (astNode.type !== "function_definition") return null;
    const nameNode = astNode.children?.find(child => child.type === "identifier");
    return nameNode?.text || null;
  }

  /**
   * Extracts function name from a function call AST node.
   * @param astNode The function call AST node.
   * @returns Function name if found, null otherwise.
   */
  private extractCalledFunctionName(astNode: AstNode): string | null {
    if (astNode.type !== "call") return null;
    const nameNode = astNode.children?.find(child => child.type === "identifier" || child.type === "attribute");
    return nameNode?.text || null;
  }

  /**
   * Builds the data flow graph from an AST node.
   * @param astNode The root AST node to build the graph from.
   * @param symbolTable Optional symbol table for cross-file analysis.
   */
  public buildFromAst(astNode: AstNode, symbolTable?: Map<string, SymbolTableEntry>) {
    if (!astNode) return;
    if (astNode.symbols && Array.isArray(astNode.symbols) && astNode.symbols.length > 0) {
      this.symbols = astNode.symbols;
    }
    if (symbolTable) {
      this.symbolTable = symbolTable;
    }
    // Function definitions
    if (astNode.type === "function_definition") {
      const functionName = this.extractFunctionName(astNode);
      if (functionName) {
        this.currentFunction = functionName;
        const parametersNode = astNode.children?.find(child => child.type === "parameters");
        if (parametersNode && parametersNode.children) {
          for (const paramChild of parametersNode.children) {
            if (paramChild.type === "identifier") {
              const paramName = paramChild.text;
              const paramUniqueId = `${functionName}_${paramName}`;
              if (!this.nodes.has(paramUniqueId)) {
                const paramNode: DfgNode = {
                  id: paramUniqueId,
                  name: paramName,
                  astNode: paramChild,
                  tainted: false,
                  taintSources: new Set(),
                  edges: new Set(),
                  symbol: {
                    name: paramName,
                    scope: functionName,
                    uniqueId: paramUniqueId
                  }
                };
                this.nodes.set(paramUniqueId, paramNode);
                console.log(`[DFG] Created parameter node: ${paramName} in function ${functionName}`);
              }
            }
          }
        }
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
    const sanitizer = this.sanitizerDetector.detectSanitizer(astNode, varName);
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
      for (const right of rightNodes) {
        for (const left of leftNodes) {
          right.edges.add(left);
        }
      }
    }
    // Handle return nodes
    if (astNode.type === "return_statement" && astNode.children?.length > 0) {
      const returnedNodes = this.getOrCreateNodes(astNode.children[0]);
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
        isKnownFunction = true;
      }
      if (functionName && isKnownFunction) {
        if (matchedFunctionEntry) {
          console.log(`[DFG] La función conocida '${functionName}' está definida en: ${matchedFunctionEntry.entry.filePath}`);
        } else {
          console.log(`[DFG] La función conocida '${functionName}' está definida localmente en este archivo.`);
        }
        const isCrossFile = matchedFunctionEntry && matchedFunctionEntry.entry.filePath !== (this.currentFilePath || '');
        const callResultNodes = this.getOrCreateNodes(astNode);
        const functionReturnNode = this.getOrCreateFunctionReturnNode(functionName);
        for (const resultNode of callResultNodes) {
          functionReturnNode.edges.add(resultNode);
          if (isCrossFile && matchedFunctionEntry) {
            resultNode.crossFileEdge = {
              from: this.currentFilePath || '',
              to: matchedFunctionEntry.entry.filePath,
              function: functionName
            };
          }
        }
        const funcDef = this.symbols.find(f => f.name === functionName);
        if (funcDef && astNode.children) {
          const argNodes = astNode.children.slice(1).map(arg => this.getOrCreateNodes(arg));
          if (isCrossFile) {
            const hasTaintedArg = argNodes.some(argNodeList =>
              argNodeList.some(argNode => argNode.tainted)
            );
            if (hasTaintedArg) {
              console.log(`[DFG] Cross-file call to ${functionName} has tainted arguments, marking result nodes`);
              for (const resultNode of callResultNodes) {
                for (const argNodeList of argNodes) {
                  for (const argNode of argNodeList) {
                    if (argNode.tainted) {
                      argNode.edges.add(resultNode);
                    }
                  }
                }
              }
            }
          }
          if (funcDef.parameters && funcDef.parameters.length === argNodes.length) {
            for (let i = 0; i < funcDef.parameters.length; i++) {
              const paramName = funcDef.parameters[i];
              const paramUniqueId = `${funcDef.name}_${paramName}`;
              let paramNode = this.nodes.get(paramUniqueId);
              if (!paramNode) {
                paramNode = {
                  id: paramUniqueId,
                  name: paramName,
                  astNode: astNode,
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
   * Gets or creates DFG nodes for an AST node.
   * @param astNode The AST node to process.
   * @returns Array of DFG nodes (existing or newly created).
   */
  public getOrCreateNodes(astNode: AstNode): DfgNode[] {
    const createdNodes: DfgNode[] = [];
    const varNames = this.extractIdentifiers(astNode);
    for (const varName of varNames) {
      if (this.currentFunction) {
        const paramUniqueId = `${this.currentFunction}_${varName}`;
        if (this.nodes.has(paramUniqueId)) {
          createdNodes.push(this.nodes.get(paramUniqueId)!);
          continue;
        }
      }
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
   * Propagates taint from a source node through the graph, stopping at sanitizers.
   * @param source The taint source node.
   */
  public propagateTaint(source: Source) {
    const startNode = this.nodes.get(source.key || source.id);
    if (!startNode || startNode.isSanitizer) return;
    const queue: DfgNode[] = [startNode];
    startNode.tainted = true;
    startNode.taintSources.add(source);
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
   * Detects vulnerabilities by identifying tainted sinks.
   * @param filePath The file path for context.
   * @returns Array of detected data flow vulnerabilities.
   */
  public detectVulnerabilities(filePath: string | undefined): DataFlowVulnerability[] {
    const vulnerabilities: DataFlowVulnerability[] = [];
    for (const node of this.nodes.values()) {
      if (node.isSink && node.tainted) {
        const uniqueSources = Array.from(node.taintSources);
        const primarySource = uniqueSources[0];
        const sourcesDescription = uniqueSources.map(s => s.description || s.id).join(', ');
        const sanitizersInPath: Sanitizer[] = [];
        for (const [nodeId, nodeData] of this.nodes.entries()) {
          if (nodeData.isSanitizer && Array.from(node.taintSources).some(s => s.id === nodeId)) {
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
                key: nodeId,
                filePath: nodeData.astNode.filePath || filePath || ''
              });
            }
          }
        }
        const sourceObj: Source = primarySource || {
          id: `source-unknown`,
          type: 'source',
          pattern: '.*',
          description: 'User input source',
          loc: {
            start: { line: 1, column: 0 },
            end: { line: 1, column: 10 }
          },
          severity: 'high',
          key: 'unknown',
          filePath: filePath || ''
        };
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
          severity: Severity.HIGH,
          filePath: node.astNode.filePath || filePath || ''
        };
        const vuln: DataFlowVulnerability = {
          id: `dataflow-vuln-${node.id}`,
          type: sinkObj.vulnerabilityType,
          severity: sinkObj.severity,
          message: `${node.name} is a sink and receives tainted input from: ${sourcesDescription}`,
          file: filePath || "unknown",
          rule: "TAINTED_SINK",
          description: sinkObj.description,
          recommendation: "Sanitize input before passing it to sensitive operations like this sink.",
          sources: uniqueSources,
          sink: sinkObj,
          sanitizers: sanitizersInPath,
          isVulnerable: node.tainted && sanitizersInPath.length === 0,
          pathLines: [uniqueSources[0]?.loc?.start?.line || 1, sinkObj.loc.start.line],
          ai: {
            confidenceScore: 0,
            shortExplanation: 'NA - AI analysis not executed',
            exploitExample: 'NA - AI analysis not executed',
            remediation: 'NA - AI analysis not executed',
          }
        };
        vulnerabilities.push(vuln);
      }
    }
    return vulnerabilities;
  }

  /**
   * Gets variable name by AST node ID.
   * @param id The AST node ID to look up.
   * @returns Variable name if found, undefined otherwise.
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
   * Extracts all identifiers from an AST node.
   * @param node The AST node to process.
   * @returns Array of identifier names found in the node.
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
   * Prints the data flow graph in a hierarchical format with enhanced visualization for sinks, sanitizers, and tainted nodes.
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
      const indent = '  '.repeat(depth);
      console.log(`${indent}${path} ${chalk.blue(node.name)}`);
      if (node.tainted) {
        console.log(`${indent}  ${chalk.red(`[TAINTED: ${Array.from(node.taintSources).map(s => s.id).join(', ')}]`)}`);
      }
      if (node.isSanitizer) {
        console.log(`${indent}  ${chalk.green(`[SANITIZED via ${node.infoSanitizer}]`)}`);
      }
      if (node.isSink) {
        console.log(`${indent}  ${chalk.magentaBright(`[SINK: ${node.infoSink}]`)}`);
      }
      let childIndex = 1;
      for (const neighbor of node.edges) {
        const childPath = `${path}${path.endsWith('.') ? '' : '.'}${childIndex}`;
        printNode(neighbor, childPath, depth + 1);
        childIndex++;
      }
    };
    console.log(chalk.yellow('\n📊 Data Flow Graph (Hierarchical):\n'));
    console.log(chalk.gray('Legend:'));
    console.log(chalk.blue('Variable') + chalk.gray(' | ') + chalk.red('Tainted') + chalk.gray(' | ') + chalk.green('Sanitizer') + chalk.gray(' | ') + chalk.magentaBright('Sink'));
    console.log(chalk.gray('-'.repeat(50)));
    for (const node of this.nodes.values()) {
      const isRoot = Array.from(this.nodes.values()).every(n => !n.edges.has(node));
      if (isRoot) {
        printNode(node, `${counter}.`);
        counter++;
      }
    }
  }

  /**
   * Gets all detected sources from the DataFlowGraph nodes.
   * @returns Array of sources with their associated location information.
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
   * Completely resets the data flow graph to its initial state.
   * Clears all nodes, variables, taint information, and detected elements.
   * Maintains the same detector instances.
   */
  public reset(): void {
    this.nodes.clear();
    this.varToAst.clear();
    this.currentFunction = null;
    this.functionReturnNodes.clear();
    this.symbols = [];
    this.importedIdentifiers.clear();
  }

  /**
   * Performs complete data flow analysis: builds graph, detects sources, propagates taint, and detects vulnerabilities.
   * @param astNode The root AST node to analyze.
   * @param initialTaintedVars Optional array of variable names to mark as tainted at the start.
   * @returns Array of detected data flow vulnerabilities.
   */
  public performCompleteAnalysis(astNode: AstNode, initialTaintedVars?: string[]): DataFlowVulnerability[] {
    const filePath = astNode.filePath;
    this.buildFromAst(astNode);
    const detectedSources = this.getDetectedSources();
    const uniqueSources = this.deduplicateDetections(detectedSources);
    for (const source of Object.values(uniqueSources)) {
      this.propagateTaint(source);
    }
    if (initialTaintedVars) {
      for (const varName of initialTaintedVars) {
        for (const node of this.nodes.values()) {
          if (node.name === varName) {
            node.tainted = true;
            if (node.detectedSource) {
              node.taintSources = new Set([node.detectedSource]);
              this.propagateTaint(node.detectedSource);
            }
          }
        }
      }
    }
    this.printGraph();
    return this.detectVulnerabilities(filePath);
  }

  /**
   * Deduplicates detected sources based on file and line location.
   * For the same file and line, keeps the one with the largest column span.
   * @param detections Array of detected sources to deduplicate.
   * @returns Deduplicated sources by file/line with largest column span.
   */
  private deduplicateDetections(detections: any[]): any[] {
    const fileLineMap = new Map<string, any>();
    for (const detection of detections) {
      if (detection.filePath && detection.loc && detection.loc.start) {
        const fileLineKey = `${detection.filePath}:${detection.loc.start.line}`;
        const colSpan = (detection.loc.end?.column ?? 0) - (detection.loc.start.column ?? 0);
        const key = detection.key ?? "";
        if (!fileLineMap.has(fileLineKey)) {
          fileLineMap.set(fileLineKey, { detection, colSpan });
        } else {
          const existing = fileLineMap.get(fileLineKey);
          const existingKey = existing.detection.key ?? "";
          if (existingKey === "" && key !== "") {
            fileLineMap.set(fileLineKey, { detection, colSpan });
          } else if (existingKey !== "" && key === "") {
          } else {
            if (colSpan > existing.colSpan) {
              fileLineMap.set(fileLineKey, { detection, colSpan });
            }
          }
        }
      }
    }
    return Array.from(fileLineMap.values()).map(item => item.detection);
  }

  /**
   * Sets the current file path for the graph (for cross-file analysis).
   * @param filePath The file path to set.
   */
  public setCurrentFilePath(filePath: string) {
    this.currentFilePath = filePath;
  }

  /**
   * Sets the symbol table for the graph (for cross-file analysis).
   * @param symbolTable The symbol table to set.
   */
  public setSymbolTable(symbolTable: Map<string, SymbolTableEntry>) {
    this.symbolTable = symbolTable;
  }
}
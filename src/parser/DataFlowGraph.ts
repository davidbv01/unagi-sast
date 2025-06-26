import { SanitizerDetector, SinkDetector } from "../analysis/detectors";
import { AstNode } from "../types";
import chalk from 'chalk';

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
};

type Symbol = {
  name: string;
  scope: string;
  uniqueId: string;
};

export class DataFlowGraph {
  // Singleton instance
  private static instance: DataFlowGraph;
  
  // Instance properties
  nodes: Map<string, DfgNode> = new Map();
  varToAst: Map<string, Set<Number>> = new Map();
  private sanitizerDetector: SanitizerDetector;
  private sinkDetector: SinkDetector;
  private importedIdentifiers: Set<string> = new Set();

  // Private constructor for singleton pattern
  private constructor() {
    this.sanitizerDetector = new SanitizerDetector();
    this.sinkDetector = new SinkDetector();
  }

  /**
   * Gets the singleton instance of DataFlowGraph
   */
  public static getInstance(): DataFlowGraph {
    if (!DataFlowGraph.instance) {
      DataFlowGraph.instance = new DataFlowGraph();
    }
    return DataFlowGraph.instance;
  }

  /**
   * Static shortcut to get variable name by AST ID
   * @param id The AST node ID to look up
   * @returns Variable name if found, undefined otherwise
   */
  public static getVariableNameByAstId(id: number): string | undefined {
    return DataFlowGraph.getInstance().getVariableNameByAstId(id);
  }

  /**
   * Builds the data flow graph from an AST node
   * @param astNode The root AST node to build the graph from
   */
  public buildFromAst(astNode: AstNode) {
    if (!astNode) return;

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
    
    // Detect and handle sanitizers
    const sanitizer = this.sanitizerDetector.detectSanitizer(astNode);
    if (sanitizer) {
      const sanitizerNodes = this.getOrCreateNodes(astNode);
      for (const node of sanitizerNodes) {
        node.isSanitizer = true;
        node.infoSanitizer = sanitizer.info;
        console.log(`Detected sanitizer: Node ${node.name} with id ${node.id}`);
      }
    }

    // Detect and handle sinks
    const sink = this.sinkDetector.detectSink(astNode);
    if (sink) {
      const sinkNodes = this.getOrCreateNodes(astNode);
      for (const node of sinkNodes) {
        node.isSink = true;
        node.infoSink = sink.info;
        console.log(`Detected sink: Node ${node.name} with id ${node.id}`);
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

    // Recursively process child nodes
    if (astNode.children) {
      for (const child of astNode.children) {
        this.buildFromAst(child);
      }
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
   */
  public detectVulnerabilities(): void {
    console.log(chalk.redBright('\n🚨 Detected Vulnerabilities:\n'));

    let found = false;

    for (const node of this.nodes.values()) {
      if (node.isSink && node.tainted) {
        found = true;
        console.log(`${chalk.magentaBright('Sink:')} ${chalk.blue(node.name)} (${node.infoSink})`);
        console.log(`  ${chalk.red('Tainted from:')} ${Array.from(node.taintSources).join(', ')}`);
        console.log('-'.repeat(40));
      }
    }

    if (!found) {
      console.log(chalk.green('✅ No tainted sinks found. No vulnerabilities detected.'));
    }
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
   * Completely resets the data flow graph to its initial state
   * - Clears all nodes, variables, taint information, and detected elements
   * - Maintains the same detector instances
   */
  public reset(): void {
      // Clear all graph data structures
      this.nodes.clear();
      this.varToAst.clear();
  }
}
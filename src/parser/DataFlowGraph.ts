import { SanitizerDetector } from "../analysis/detectors";
import { AstNode } from "../types";
import chalk from 'chalk';

type DfgNode = {
  id: string;
  name: string
  astNode: AstNode;
  tainted: boolean;
  taintSources: Set<string>;
  edges: Set<DfgNode>;
  symbol?: Symbol; 
};

type Symbol = {
  name: string;
  scope: string; 
  uniqueId: string; 
}


export class DataFlowGraph {
  nodes: Map<string, DfgNode> = new Map();
  varToAst: Map<string, Set<string>> = new Map(); 
  private sanitizerDetector: SanitizerDetector;
  sanitizers: Set<string> = new Set();
  

  constructor() {
    this.sanitizerDetector = new SanitizerDetector();
  }


  getOrCreateNodes(astNode: AstNode): DfgNode[] {
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


  buildFromAst(astNode: AstNode) {
    if (!astNode) return;

    const sanitizer = this.sanitizerDetector.detectSanitizer(astNode);
    if (sanitizer) {
      const sanitizerNodes = this.getOrCreateNodes(astNode);
      for (const node of sanitizerNodes) {
        this.sanitizers.add(node.id);
        console.log(`Sanitizer detectado: Nodo ${node.name} con id ${node.id}`);
      }
    }

    if (astNode.type === "assignment" && astNode.children?.length === 2) {
      const leftNodes = this.getOrCreateNodes(astNode.children[0]);
      const rightNodes = this.getOrCreateNodes(astNode.children[1]);

      // Data flows from each right node to each left node
      for (const right of rightNodes) {
        for (const left of leftNodes) {
          right.edges.add(left);
          console.log(`Nodo ${right.name} → ${left.name}`);
        }
      }
    }

    if (astNode.children) {
      for (const child of astNode.children) {
        this.buildFromAst(child);
      }
    }
  }


  private extractIdentifiers(node: AstNode): string[] {
    const result: string[] = [];

    const walk = (n: AstNode) => {
      if (n.type === 'attribute') {
        const base = n.children.find(child => child.type === 'identifier');
        if (base) {
          result.push(base.text);

          if (!this.varToAst.has(base.text)) {
            this.varToAst.set(base.text, new Set());
          }
          this.varToAst.get(base.text)!.add(node.id.toString());
        }
      } else if (n.type === 'identifier') {
        result.push(n.text);

        if (!this.varToAst.has(n.text)) {
          this.varToAst.set(n.text, new Set());
        }
        this.varToAst.get(n.text)!.add(node.id.toString());
      } else {
        for (const child of n.children || []) {
          walk(child);
        }
      }
    };

    walk(node);
    return result;
  }



  // Marks a variable or node as tainted and propagates the taint forward
  propagateTaint(sourceId: string, sanitizers: Set<string>) {
    const startNode = this.nodes.get(sourceId);
    if (!startNode) return;

    const queue: DfgNode[] = [startNode];
    startNode.tainted = true;
    startNode.taintSources.add(sourceId);

    while (queue.length > 0) {
      const current = queue.shift()!;

      // Si el nodo actual es un sanitizer, no propagamos más desde aquí
      if (sanitizers.has(current.id)) {
        continue;
      }

      for (const neighbor of current.edges) {
        if (!neighbor.tainted) {
          neighbor.tainted = true;
          neighbor.taintSources = new Set(current.taintSources);
          queue.push(neighbor);
        } else {
          // Si ya está tainted, añadir fuentes nuevas si hay
          for (const src of current.taintSources) {
            neighbor.taintSources.add(src);
          }
        }
      }
    }
  }

  printGraph() {
    const visited = new Set<string>();
    let counter = 1;

    const printNode = (node: DfgNode, path: string) => {
      const taintInfo = node.tainted
        ? chalk.red(` [TAINTED: ${Array.from(node.taintSources).join(', ')}]`)
        : '';
      const sanitizerInfo = this.sanitizers.has(node.id)
        ? chalk.green(' [SANITIZER]')
        : '';

      console.log(`${path} ${chalk.blue(node.name)}${taintInfo}${sanitizerInfo}`);

      let childIndex = 1;
      for (const neighbor of node.edges) {
        const childPath = `${path}${path.endsWith('.') ? '' : '.'}${childIndex}`;
        printNode(neighbor, childPath);
        childIndex++;
      }
    };

    console.log(chalk.yellow('\n📊 Data Flow Graph (Jerárquico):\n'));

    for (const node of this.nodes.values()) {
      const isRoot = Array.from(this.nodes.values()).every(n => !n.edges.has(node));
      if (isRoot) {
        printNode(node, `${counter}.`);
        counter++;
      }
    }
  }
}

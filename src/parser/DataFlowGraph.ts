import { AstNode } from "../types";

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

  getOrCreateNodes(astNode: AstNode): DfgNode[] {
    const createdNodes: DfgNode[] = [];
    const varNames = this.extractIdentifiers(astNode); // Uses a function that filters methods

    for (const varName of varNames) {
      const symbol: Symbol = {
        name: varName,
        scope: astNode.scope,
        uniqueId: `${astNode.scope}_${varName}`
      };

      const uniqueId = `${symbol.uniqueId}_${astNode.id}`;

      if (!this.nodes.has(uniqueId)) {
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


  // Builds the graph from the AST recursively
  buildFromAst(astNode: AstNode) {
    if (!astNode) return;

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
        const base = n.children?.find(child => child.type === 'identifier');
        if (base) result.push(base.text);
      } else if (n.type === 'identifier') {
        result.push(n.text);
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
  propagateTaint(sourceId: string) {
    const startNode = this.nodes.get(sourceId);
    if (!startNode) return;

    const queue: DfgNode[] = [startNode];
    startNode.tainted = true;
    startNode.taintSources.add(sourceId);

    while (queue.length > 0) {
      const current = queue.shift()!;
      for (const neighbor of current.edges) {
        if (!neighbor.tainted) {
          neighbor.tainted = true;
          neighbor.taintSources = new Set(current.taintSources);
          queue.push(neighbor);
        } else {
          // If already tainted, add taint sources
          for (const src of current.taintSources) {
            neighbor.taintSources.add(src);
          }
        }
      }
    }
  }
}

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
    const varNames = astNode.varNames || []; // Obtiene solo los nombres de variable

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
}

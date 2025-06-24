import { AstNode } from "../types";

type DfgNode = {
  id: string;
  astNode: AstNode;
  tainted: boolean;
  taintSources: Set<string>;
  edges: Set<DfgNode>;
};


export class DataFlowGraph {
  nodes: Map<string, DfgNode> = new Map();

  // Crear o recuperar nodo DFG para un astNode
  getOrCreateNode(astNode: AstNode): DfgNode {
    let id = astNode.id.toString() //TODO - Mirar si hace falta dejarlo en string o se puede cambiar a Number
    if (!this.nodes.has(id)) {
      this.nodes.set(id, {
        id,
        astNode,
        tainted: false,
        taintSources: new Set(),
        edges: new Set()
      });
    }
    return this.nodes.get(id)!;
  }

  // Construye el grafo a partir del AST recursivamente
  buildFromAst(astNode: AstNode) {
    if (!astNode) return;
    if (astNode.type === "assignment" && astNode.children && astNode.children) {
      const leftNode = this.getOrCreateNode(astNode.children[0]);
      const rightNode = this.getOrCreateNode(astNode.children[1]);
      // Datos fluyen de right a left
      rightNode.edges.add(leftNode);
    }

    if (astNode.children) {
      for (const child of astNode.children) {
        this.buildFromAst(child);
      }
    }
  }

  // Marca una variable o nodo como tainted y propaga el taint hacia adelante
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
          // Si ya está tainted, agrega fuentes de taint
          for (const src of current.taintSources) {
            neighbor.taintSources.add(src);
          }
        }
      }
    }
  }
}

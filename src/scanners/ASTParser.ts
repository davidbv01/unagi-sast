import Parser from 'tree-sitter';
import Python from 'tree-sitter-python';
import { Position } from '../types';

export class ASTParser {
  private parser: Parser;
  private tree: Parser.Tree | undefined;

  constructor() {
    this.parser = new Parser();
    this.parser.setLanguage(Python as any);
  }

  public parse(content: string, languageId: string, fileName: string): any {
    try {
      if (languageId !== 'python') return null;

      this.tree = this.parser.parse(content);
      const rootNode = this.tree.rootNode;

      const ast = this.nodeToDict(rootNode);

      return {
        ast,
        traverse: this.traverse.bind(this)
      };
    } catch (error) {
      console.error(`Tree-sitter failed to parse ${fileName}: ${error}`);
      return null;
    }
  }

  private nodeToDict(node: Parser.SyntaxNode): any {
    const children = node.namedChildren.map(child => this.nodeToDict(child));

    const result: any = {
      type: node.type,
      named: node.isNamed,
      children,
      loc: {
        start: { line: node.startPosition.row + 1, column: node.startPosition.column },
        end: { line: node.endPosition.row + 1, column: node.endPosition.column }
      }
    };

    // Add empty children array for leaf nodes
    if (children.length === 0) {
      result.children = [];
    }

    return result;
  }

  public getNodePosition(node: any): Position {
    return {
      line: node.loc?.start.line || 1,
      column: node.loc?.start.column || 1
    };
  }

  private traverse(ast: any, visitor: { enter?: (path: any) => void }): void {
    const walk = (node: any, parent: any = null) => {
      if (!node) return;

      const path = {
        node,
        parent,
        getParent: () => parent
      };

      if (visitor.enter) {
        visitor.enter(path);
      }

      for (const child of node.children || []) {
        walk(child, node);
      }
    };

    walk(ast);
  }
}
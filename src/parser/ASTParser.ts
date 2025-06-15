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

      // Return the AST structure directly
      return this.nodeToDict(rootNode);
    } catch (error) {
      console.error(`Tree-sitter failed to parse ${fileName}: ${error}`);
      return null;
    }
  }

  private nodeToDict(node: Parser.SyntaxNode): any {
    const children = node.namedChildren.map(child => this.nodeToDict(child));

    // Get raw positions from tree-sitter
    const startRow = node.startPosition.row;
    const startCol = node.startPosition.column;
    const endRow = node.endPosition.row;
    const endCol = node.endPosition.column;
    
    // Convert to 1-based line numbers and ensure valid positions
    const startLine = startRow + 1;
    const endLine = endRow + 1;

    // Validate and fix positions
    let finalStartLine = startLine;
    let finalStartCol = startCol;
    let finalEndLine = endLine;
    let finalEndCol = endCol;

    // If end position is before start position, use start position for end
    if (endRow < startRow || (endRow === startRow && endCol < startCol)) {
      console.warn(`[WARN] Invalid node positions for ${node.type}:`, {
        start: { line: startLine, col: startCol },
        end: { line: endLine, col: endCol }
      });
      finalEndLine = startLine;
      finalEndCol = startCol;
    }

    const result: any = {
      type: node.type,
      named: node.isNamed,
      children,
      loc: {
        start: { line: finalStartLine, column: finalStartCol },
        end: { line: finalEndLine, column: finalEndCol }
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

  public traverse(ast: any, visitor: { enter?: (path: any) => void }): void {
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
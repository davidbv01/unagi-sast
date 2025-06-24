import Parser from 'tree-sitter';
import Python from 'tree-sitter-python';
import { Position, PythonFunction, AstNode } from '../types';

export class ASTParser {
  private parser: Parser;
  private tree: Parser.Tree | undefined;
  private nodeCounter = 0;

  constructor() {
    this.parser = new Parser();
    this.parser.setLanguage(Python as any);
  }

  public parse(content: string, languageId: string, fileName: string): AstNode | undefined {
    try {
      if (languageId !== 'python') return undefined;

      this.tree = this.parser.parse(content);
      const rootNode = this.tree.rootNode;
      
      // Return the AST structure with functions and content included
      const ast = this.nodeToDict(rootNode, content);
      const functions = this.extractPythonFunctionsFromAST(ast);
      const contentWithoutComments = this.removeComments(content);
      ast.functions = functions;
      ast.content = contentWithoutComments;
      return ast;

    } catch (error) {
      console.error(`Tree-sitter failed to parse ${fileName}: ${error}`);
      return undefined;
    }
  }

  private nodeToDict(node: Parser.SyntaxNode, content?: string): any {
    const nodeId = this.nodeCounter++; // Generate a unique incremental ID

    const children = node.namedChildren.map(child => this.nodeToDict(child, content));

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

    // Extract the actual text content for this node
    let text = '';
    if (content) {
      const lines = content.split('\n');
      const startLineIndex = startRow; // 0-based for array access
      const endLineIndex = endRow; // 0-based for array access
      
      if (startLineIndex === endLineIndex) {
        // Single line
        if (lines[startLineIndex]) {
          text = lines[startLineIndex].substring(startCol, endCol);
        }
      } else {
        // Multi-line
        const result: string[] = [];
        if (lines[startLineIndex]) {
          result.push(lines[startLineIndex].substring(startCol));
        }
        for (let i = startLineIndex + 1; i < endLineIndex; i++) {
          if (lines[i]) {
            result.push(lines[i]);
          }
        }
        if (lines[endLineIndex]) {
          result.push(lines[endLineIndex].substring(0, endCol));
        }
        text = result.join('\n');
      }
    }

    const result: any = {
      id: nodeId,
      type: node.type,
      named: node.isNamed,
      text: text,
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

  public traverse(ast: AstNode, visitor: { enter?: (path: any) => void }): void {
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

  public extractPythonFunctionsFromAST(ast: AstNode): PythonFunction[] {
    const functions: PythonFunction[] = [];

    this.traverse(ast, {
      enter: (path) => {
        const node = path.node;

        if (node.type === 'function_definition') {
          const nameNode = node.children?.find(
            (child: any) => child.type === 'identifier'
          );

          functions.push({
            name: nameNode?.text || 'anonymous',
            startLine: node.loc.start.line,
            endLine: node.loc.end.line
          });
        }
      }
    });

    return functions;
  }
  
  public removeComments(content: string): string {
    if (!this.tree) return content;

    // Extraemos todos los nodos de comentario del árbol
    const commentNodes: Parser.SyntaxNode[] = [];

    const collectComments = (node: Parser.SyntaxNode) => {
      if (node.type === 'comment') {
        commentNodes.push(node);
      }
      for (let i = 0; i < node.namedChildCount; i++) {
        const child = node.namedChild(i);
        if (child !== null) {
          collectComments(child);
        }
      }
    };

    collectComments(this.tree.rootNode);

    if (commentNodes.length === 0) return content; // Sin comentarios

    // Convertir contenido en array de líneas para facilitar la manipulación
    const lines = content.split('\n');

    // Para cada comentario, eliminamos la parte correspondiente en lines
    commentNodes.forEach(node => {
      const { startPosition, endPosition } = node;
      const startLine = startPosition.row;
      const startCol = startPosition.column;
      const endLine = endPosition.row;
      const endCol = endPosition.column;

      if (startLine === endLine) {
        // Comentario en una sola línea: cortamos desde startCol hasta endCol
        lines[startLine] =
          lines[startLine].substring(0, startCol) + lines[startLine].substring(endCol);
      } else {
        // Comentario multi-línea (raro en Python pero puede ser docstring o multilinea)
        // Eliminamos líneas completas entre startLine+1 y endLine-1
        lines[startLine] = lines[startLine].substring(0, startCol);
        for (let i = startLine + 1; i < endLine; i++) {
          lines[i] = '';
        }
        lines[endLine] = lines[endLine].substring(endCol);
      }
    });

    // Unir líneas limpiadas y retornar
    return lines.join('\n');
  }

}
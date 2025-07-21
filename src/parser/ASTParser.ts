import Parser, { SyntaxNode, Tree } from 'tree-sitter';
import Python from 'tree-sitter-python';
import { AstNode, SymbolTableEntry } from '../types';

/**
 * ASTParser parses Python code into a custom AST structure using tree-sitter.
 */
export class ASTParser {
  private readonly parser: Parser;
  private tree?: Tree;
  private nodeCounter = 0;

  constructor() {
    this.parser = new Parser();
    this.parser.setLanguage(Python as any);
  }

  /**
   * Parses the given code content into an AstNode if the language is supported.
   * @param content The source code to parse.
   * @param languageId The language identifier (e.g., 'python').
   * @param fileName The file name for context.
   * @returns The root AstNode or undefined if parsing fails or language is unsupported.
   */
  public parse(content: string, languageId: string, fileName: string): AstNode | undefined {
    if (languageId !== 'python') { return undefined; }
    try {
      this.nodeCounter = 0;
      this.tree = this.parser.parse(content);
      const rootNode = this.tree.rootNode;
      const ast = this.nodeToAstNode(rootNode, content, [], fileName);
      ast.symbols = this.extractSymbols(ast, fileName);
      ast.content = this.removeComments(content);
      ast.filePath = fileName;
      return ast;
    } catch (error) {
      console.error(`Tree-sitter failed to parse ${fileName}: ${error}`);
      return undefined;
    }
  }

  /**
   * Converts a tree-sitter SyntaxNode to a custom AstNode recursively.
   * @param node The tree-sitter node.
   * @param content The file content.
   * @param scopeStack The current scope stack.
   * @param filePath The file path for context.
   * @returns The constructed AstNode.
   */
  private nodeToAstNode(node: SyntaxNode, content = '', scopeStack: string[] = [], filePath = ''): AstNode {
    const nodeId = this.nodeCounter++;
    const newScopeStack = this.updateScopeStack(node, scopeStack);
    const currentScope = newScopeStack.join('::') || 'global';
    const children = node.namedChildren.map(child => this.nodeToAstNode(child, content, newScopeStack, filePath));
    const { start, end } = this.getNodeLocation(node);
    const text = this.extractNodeText(node, content);
    return {
      id: nodeId,
      type: node.type,
      named: node.isNamed,
      text,
      children,
      scope: currentScope,
      loc: { start, end },
      symbols: [],
      content: '',
      filePath
    };
  }

  /**
   * Updates the scope stack if the node introduces a new scope.
   */
  private updateScopeStack(node: SyntaxNode, scopeStack: string[]): string[] {
    const newStack = [...scopeStack];
    if (node.type === 'function_definition' || node.type === 'class_definition') {
      const nameNode = node.namedChildren.find(child => child.type === 'identifier');
      if (nameNode?.text) { newStack.push(nameNode.text); }
    }
    return newStack;
  }

  /**
   * Gets the start and end positions for a node, ensuring valid positions.
   */
  private getNodeLocation(node: SyntaxNode): { start: { line: number; column: number }, end: { line: number; column: number } } {
    const startRow = node.startPosition.row;
    const startCol = node.startPosition.column;
    const endRow = node.endPosition.row;
    const endCol = node.endPosition.column;
    let finalStartLine = startRow + 1;
    let finalStartCol = startCol;
    let finalEndLine = endRow + 1;
    let finalEndCol = endCol;
    if (endRow < startRow || (endRow === startRow && endCol < startCol)) {
      console.warn(`[WARN] Invalid node positions for ${node.type}:`, {
        start: { line: finalStartLine, col: finalStartCol },
        end: { line: finalEndLine, col: finalEndCol }
      });
      finalEndLine = finalStartLine;
      finalEndCol = finalStartCol;
    }
    return {
      start: { line: finalStartLine, column: finalStartCol },
      end: { line: finalEndLine, column: finalEndCol }
    };
  }

  /**
   * Extracts the text content for a node from the file content.
   */
  private extractNodeText(node: SyntaxNode, content: string): string {
    if (!content) { return ''; }
    const lines = content.split('\n');
    const { row: startRow, column: startCol } = node.startPosition;
    const { row: endRow, column: endCol } = node.endPosition;
    if (startRow === endRow) {
      return lines[startRow]?.substring(startCol, endCol) || '';
    } else {
      const result: string[] = [];
      if (lines[startRow]) { result.push(lines[startRow].substring(startCol)); }
      for (let i = startRow + 1; i < endRow; i++) {
        if (lines[i]) { result.push(lines[i]); }
      }
      if (lines[endRow]) { result.push(lines[endRow].substring(0, endCol)); }
      return result.join('\n');
    }
  }

  /**
   * Traverses the AST and calls the visitor's enter method for each node.
   * @param ast The root AstNode.
   * @param visitor An object with an optional enter function.
   */
  public traverse(ast: AstNode, visitor: { enter?: (path: { node: AstNode, parent: AstNode | null, getParent: () => AstNode | null }) => void }): void {
    const walk = (node: AstNode, parent: AstNode | null = null) => {
      if (!node) { return; }
      const path = {
        node,
        parent,
        getParent: () => parent
      };
      visitor.enter?.(path);
      for (const child of node.children || []) {
        walk(child, node);
      }
    };
    walk(ast);
  }

  /**
   * Removes all comments from the given code content using the current tree.
   * @param content The code content.
   * @returns The content with comments removed.
   */
  public removeComments(content: string): string {
    if (!this.tree) { return content; }
    const commentNodes: SyntaxNode[] = [];
    const collectComments = (node: SyntaxNode) => {
      if (node.type === 'comment') { commentNodes.push(node); }
      for (let i = 0; i < node.namedChildCount; i++) {
        const child = node.namedChild(i);
        if (child) { collectComments(child); }
      }
    };
    collectComments(this.tree.rootNode);
    if (commentNodes.length === 0) { return content; }
    const lines = content.split('\n');
    commentNodes.forEach(node => {
      const { startPosition, endPosition } = node;
      const startLine = startPosition.row;
      const startCol = startPosition.column;
      const endLine = endPosition.row;
      const endCol = endPosition.column;
      if (startLine === endLine) {
        lines[startLine] = lines[startLine].substring(0, startCol) + lines[startLine].substring(endCol);
      } else {
        lines[startLine] = lines[startLine].substring(0, startCol);
        for (let i = startLine + 1; i < endLine; i++) { lines[i] = ''; }
        lines[endLine] = lines[endLine].substring(endCol);
      }
    });
    return lines.join('\n');
  }

  /**
   * Extracts all symbols (functions, classes, global variables) from the AST.
   * @param ast The root AstNode.
   * @param filePathArg Optional file path override.
   * @returns An array of SymbolTableEntry objects.
   */
  public extractSymbols(ast: AstNode, filePathArg?: string): SymbolTableEntry[] {
    const filePath = ast.filePath || filePathArg || '';
    const symbols: SymbolTableEntry[] = [];
    this.traverse(ast, {
      enter: ({ node }) => {
        if (node.type === 'function_definition') {
          const nameNode = node.children?.find(child => child.type === 'identifier');
          const paramsNode = node.children?.find(child => child.type === 'parameters');
          const parameters: string[] = paramsNode && paramsNode.children
            ? paramsNode.children.filter(child => child.type === 'identifier').map(child => child.text)
            : [];
          symbols.push({
            name: nameNode?.text || 'anonymous',
            filePath,
            node,
            type: 'function',
            parameters,
            loc: node.loc,
          });
        } else if (node.type === 'class_definition') {
          const nameNode = node.children?.find(child => child.type === 'identifier');
          symbols.push({
            name: nameNode?.text || 'anonymous',
            filePath,
            node,
            type: 'class',
            loc: node.loc,
          });
        } else if (node.type === 'assignment' && node.scope === 'global') {
          const leftNode = node.children?.find(child => child.type === 'identifier');
          if (leftNode) {
            symbols.push({
              name: leftNode.text,
              filePath,
              node,
              type: 'variable',
              loc: node.loc,
            });
          }
        }
      }
    });
    return symbols;
  }
}
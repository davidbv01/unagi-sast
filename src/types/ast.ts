export interface AstNode {
    id: number;
    children: AstNode[];
    type: string;
    named: boolean;
    text: string;
    loc:
    {
      start: { line: number, column: number },
      end: { line: number, column: number }
    };
    scope: string;
    symbols: SymbolTableEntry[];
    filePath: string;
    content: string
  };

  export interface SymbolTableEntry {
    name: string; // Symbol name (function, class, variable)
    filePath: string; // Relative file path
    node: AstNode; // AST node for the symbol
    scope?: string; // Optional: class or function scope
    parameters?: string[];
    type: 'function' | 'class' | 'variable';
    loc: {
      start: { line: number, column: number },
      end: { line: number, column: number }
    };
  }

  
export interface Position {
    line: number;
    column: number;
  }
  
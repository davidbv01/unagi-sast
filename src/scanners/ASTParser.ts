import * as parser from '@babel/parser';
import traverse from '@babel/traverse';
import * as t from '@babel/types';
import { parse as parseTypeScript } from '@typescript-eslint/parser';
import * as fs from 'fs';
import * as path from 'path';

export interface ParsedAST {
  ast: any;
  traverse: typeof traverse;
  types: typeof t;
  sourceCode: string;
}

export class ASTParser {
  
  private outputASTToFile(ast: any, fileName: string): void {
    try {
      const outputDir = path.join(process.cwd(), 'ast-debug');
      if (!fs.existsSync(outputDir)) {
        fs.mkdirSync(outputDir, { recursive: true });
      }
      
      const outputPath = path.join(outputDir, `${path.basename(fileName)}.ast.json`);
      fs.writeFileSync(outputPath, JSON.stringify(ast, null, 2));
      console.log(`AST debug output written to: ${outputPath}`);
    } catch (error) {
      console.error('Failed to write AST debug output:', error);
    }
  }

  private safeTraverse(ast: any): typeof traverse {
    const safeTraverseFn = (ast: any, visitor: any) => {
      try {
        return traverse(ast, visitor);
      } catch (error) {
        console.warn('Traverse failed, returning safe traverse function:', error);
        // Return a no-op traverse function that won't throw errors
        return {
          stop: () => {},
          skip: () => {},
          remove: () => {},
          replaceWith: () => {},
          insertBefore: () => {},
          insertAfter: () => {},
          skipKey: () => {}
        };
      }
    };

    // Copy all properties from the original traverse function
    Object.assign(safeTraverseFn, traverse);
    return safeTraverseFn as typeof traverse;
  }

  public parseJavaScript(code: string, fileName?: string): ParsedAST {
    try {
      const ast = parser.parse(code, {
        sourceType: 'module',
        allowImportExportEverywhere: true,
        allowAwaitOutsideFunction: true,
        allowSuperOutsideMethod: true,
        allowReturnOutsideFunction: true,
        plugins: [
          'jsx',
          'typescript',
          'decorators-legacy',
          'classProperties',
          'asyncGenerators',
          'functionBind',
          'exportDefaultFrom',
          'dynamicImport',
          'classPrivateProperties',
          'classPrivateMethods',
          'doExpressions',
          'exportNamespaceFrom',
          'functionSent',
          'logicalAssignment',
          'nullishCoalescingOperator',
          'numericSeparator',
          'objectRestSpread',
          'optionalCatchBinding',
          'optionalChaining',
          'pipelineOperator',
          'throwExpressions'
        ]
      });

      if (fileName) {
        this.outputASTToFile(ast, fileName);
      }

      return {
        ast,
        traverse: this.safeTraverse(ast),
        types: t,
        sourceCode: code
      };
    } catch (error) {
      console.error('Failed to parse JavaScript/TypeScript:', error);
      throw error;
    }
  }

  public parseTypeScript(code: string, fileName?: string): ParsedAST {
    try {
      // Try TypeScript parser first
      const ast = parseTypeScript(code, {
        loc: true,
        range: true,
        tokens: true,
        comments: true,
        errorOnUnknownASTType: false,
        errorOnTypeScriptSyntacticAndSemanticIssues: false,
        jsx: true,
        useJSXTextNode: true,
        project: './tsconfig.json'
      });

      if (fileName) {
        this.outputASTToFile(ast, fileName);
      }

      return {
        ast,
        traverse: this.safeTraverse(ast),
        types: t,
        sourceCode: code
      };
    } catch (error) {
      // Fallback to Babel parser
      console.warn('TypeScript parser failed, falling back to Babel:', error);
      return this.parseJavaScript(code, fileName);
    }
  }

  public parse(code: string, languageId: string, fileName?: string): ParsedAST | null {
    try {
      switch (languageId) {
        case 'javascript':
        case 'jsx':
          return this.parseJavaScript(code, fileName);
        
        case 'typescript':
        case 'tsx':
          return this.parseTypeScript(code, fileName);
        
        default:
          console.warn(`AST parsing not supported for language: ${languageId}`);
          return null;
      }
    } catch (error) {
      console.error(`Failed to parse code for language ${languageId}:`, error);
      return null;
    }
  }

  public getNodePosition(node: any, sourceCode: string): { line: number; column: number } {
    if (node.loc) {
      return {
        line: node.loc.start.line,
        column: node.loc.start.column
      };
    }
    
    // Fallback: calculate line/column from start position
    if (node.start !== undefined) {
      const lines = sourceCode.substring(0, node.start).split('\n');
      return {
        line: lines.length,
        column: lines[lines.length - 1].length
      };
    }

    return { line: 1, column: 0 };
  }

  public getNodeText(node: any, sourceCode: string): string {
    if (node.start !== undefined && node.end !== undefined) {
      return sourceCode.substring(node.start, node.end);
    }
    return '';
  }
}

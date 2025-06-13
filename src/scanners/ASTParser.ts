import * as child_process from 'child_process';
import { Position } from '../types';

export class ASTParser {
  private ast: any;

  public parse(content: string, languageId: string, fileName: string): any {
    try {
      if (languageId === 'python') {
        // Use Python's built-in ast module to parse the code
        const pythonScript = `
import ast
import json
import sys

def node_to_dict(node):
    if isinstance(node, ast.AST):
        fields = {}
        for field, value in ast.iter_fields(node):
            if isinstance(value, list):
                fields[field] = [node_to_dict(item) for item in value]
            else:
                fields[field] = node_to_dict(value)
        fields['type'] = node.__class__.__name__
        if hasattr(node, 'lineno'):
            fields['loc'] = {
                'start': {'line': node.lineno, 'column': node.col_offset},
                'end': {'line': node.end_lineno if hasattr(node, 'end_lineno') else node.lineno, 
                       'column': node.end_col_offset if hasattr(node, 'end_col_offset') else node.col_offset}
            }
        return fields
    elif isinstance(node, list):
        return [node_to_dict(item) for item in node]
    else:
        return node

try:
    # Read input from stdin instead of command line args
    content = sys.stdin.read()
    tree = ast.parse(content)
    result = node_to_dict(tree)
    # Ensure we're outputting valid JSON
    print(json.dumps(result, ensure_ascii=False))
except Exception as e:
    print(json.dumps({"error": str(e)}, ensure_ascii=False))
    sys.exit(1)
`;

        // Create a temporary file for the Python script
        const tempScriptPath = require('os').tmpdir() + '/ast_parser.py';
        require('fs').writeFileSync(tempScriptPath, pythonScript);

        // Execute Python script with content piped through stdin
        const result = child_process.execSync(`python "${tempScriptPath}"`, {
          input: content,
          encoding: 'utf-8',
          maxBuffer: 10 * 1024 * 1024 // 10MB buffer
        });

        // Clean up temporary file
        require('fs').unlinkSync(tempScriptPath);

        // Parse the JSON result
        const parsedResult = JSON.parse(result);
        
        if (parsedResult.error) {
          throw new Error(parsedResult.error);
        }

        this.ast = parsedResult;
        return {
          ast: this.ast,
          traverse: this.traverse.bind(this)
        };
      }
      return null;
    } catch (error) {
      console.error(`Failed to parse ${fileName}: ${error}`);
      return null;
    }
  }

  public getNodePosition(node: any, content: string): Position {
    if (!node || !node.loc) {
      return { line: 1, column: 1 };
    }

    return {
      line: node.loc.start.line,
      column: node.loc.start.column
    };
  }

  private traverse(ast: any, visitor: { enter?: (path: any) => void }): void {
    const traverse = (node: any, parent: any = null) => {
      if (!node) return;

      const path = {
        node,
        parent,
        getParent: () => parent
      };

      if (visitor.enter) {
        visitor.enter(path);
      }

      // Recursively traverse child nodes
      for (const key in node) {
        if (node[key] && typeof node[key] === 'object') {
          if (Array.isArray(node[key])) {
            node[key].forEach((child: any) => traverse(child, node));
          } else {
            traverse(node[key], node);
          }
        }
      }
    };

    traverse(ast);
  }
}

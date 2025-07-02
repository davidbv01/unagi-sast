import * as path from 'path';
import * as fs from 'fs';
import { AstNode, ImportInfo, ExportInfo, PythonFunction } from '../types';

export class ImportResolver {
  private importMap: Map<string, ImportInfo[]> = new Map(); // filePath -> imports
  private exportMap: Map<string, ExportInfo[]> = new Map(); // filePath -> exports
  private moduleResolutionCache: Map<string, string> = new Map(); // module_name -> resolved_path

  constructor(private workspaceRoot: string) {}

  /**
   * Extracts import information from an AST
   */
  public extractImports(ast: AstNode, filePath: string): ImportInfo[] {
    const imports: ImportInfo[] = [];
    
    this.traverse(ast, (node) => {
      if (node.type === 'import_statement' || node.type === 'import_from_statement') {
        const importInfo = this.parseImportNode(node, filePath);
        if (importInfo) {
          imports.push(...importInfo);
        }
      }
    });

    this.importMap.set(filePath, imports);
    return imports;
  }

  /**
   * Extracts export information from an AST (functions, classes, variables defined at module level)
   */
  public extractExports(ast: AstNode, filePath: string, functions: PythonFunction[]): ExportInfo[] {
    const exports: ExportInfo[] = [];
    
    // Extract function exports
    for (const func of functions) {
      if (this.isModuleLevelFunction(ast, func.name)) {
        exports.push({
          exportedName: func.name,
          filePath,
          exportType: 'function',
          line: func.startLine,
          column: 0,
          astNodeId: this.findFunctionNodeId(ast, func.name) || 0
        });
      }
    }

    // Extract class and variable exports at module level
    this.traverse(ast, (node) => {
      if (node.scope === 'global') {
        if (node.type === 'class_definition') {
          const nameNode = this.findChildByType(node, 'identifier');
          if (nameNode) {
            exports.push({
              exportedName: nameNode.text,
              filePath,
              exportType: 'class',
              line: node.loc.start.line,
              column: node.loc.start.column,
              astNodeId: node.id
            });
          }
        } else if (node.type === 'assignment') {
          // Extract variable assignments at module level
          const identifiers = this.extractAssignmentTargets(node);
          for (const identifier of identifiers) {
            exports.push({
              exportedName: identifier,
              filePath,
              exportType: 'variable',
              line: node.loc.start.line,
              column: node.loc.start.column,
              astNodeId: node.id
            });
          }
        }
      }
    });

    this.exportMap.set(filePath, exports);
    return exports;
  }

  /**
   * Resolves an import to its actual file path
   */
  public resolveImport(importInfo: ImportInfo): string | null {
    const cacheKey = `${importInfo.sourcePath}:${importInfo.importedName}`;
    
    if (this.moduleResolutionCache.has(cacheKey)) {
      return this.moduleResolutionCache.get(cacheKey)!;
    }

    let resolvedPath = this.attemptModuleResolution(importInfo);
    
    if (!resolvedPath) {
      // Try relative path resolution
      resolvedPath = this.attemptRelativeResolution(importInfo);
    }

    if (resolvedPath) {
      this.moduleResolutionCache.set(cacheKey, resolvedPath);
    }

    return resolvedPath;
  }

  /**
   * Gets all imports for a specific file
   */
  public getImportsForFile(filePath: string): ImportInfo[] {
    return this.importMap.get(filePath) || [];
  }

  /**
   * Gets all exports for a specific file
   */
  public getExportsForFile(filePath: string): ExportInfo[] {
    return this.exportMap.get(filePath) || [];
  }

  /**
   * Finds which file exports a specific function/class/variable
   */
  public findExportSource(exportName: string, excludeFile?: string): ExportInfo | null {
    for (const [filePath, exports] of this.exportMap.entries()) {
      if (excludeFile && filePath === excludeFile) continue;
      
      const exportInfo = exports.find(exp => exp.exportedName === exportName);
      if (exportInfo) {
        return exportInfo;
      }
    }
    return null;
  }

  /**
   * Gets cross-file function call relationships
   */
  public getCrossFileConnections(): { sourceFile: string; targetFile: string; functionName: string }[] {
    const connections: { sourceFile: string; targetFile: string; functionName: string }[] = [];
    
    for (const [sourceFile, imports] of this.importMap.entries()) {
      for (const importInfo of imports) {
        const targetFile = this.resolveImport(importInfo);
        if (targetFile && targetFile !== sourceFile) {
          connections.push({
            sourceFile,
            targetFile,
            functionName: importInfo.importedName
          });
        }
      }
    }
    
    return connections;
  }

  // Private helper methods

  private parseImportNode(node: AstNode, filePath: string): ImportInfo[] {
    const imports: ImportInfo[] = [];
    
    if (node.type === 'import_statement') {
      // import module
      // import module as alias
      const dotted_names = node.children?.filter(child => child.type === 'dotted_name' || child.type === 'aliased_import');
      for (const name_node of dotted_names || []) {
        const moduleName = this.extractModuleName(name_node);
        if (moduleName) {
          imports.push({
            importedName: moduleName,
            sourcePath: filePath,
            targetPath: '', // Will be resolved later
            importType: 'module',
            line: node.loc.start.line,
            column: node.loc.start.column
          });
        }
      }
    } else if (node.type === 'import_from_statement') {
      // from module import name
      const module_node = node.children?.find(child => child.type === 'dotted_name');
      const import_list = node.children?.find(child => child.type === 'import_list');
      
      if (module_node && import_list) {
        const moduleName = module_node.text;
        const imported_names = import_list.children?.filter(child => 
          child.type === 'identifier' || child.type === 'aliased_import'
        );
        
        for (const name_node of imported_names || []) {
          const importedName = this.extractImportedName(name_node);
          if (importedName) {
            imports.push({
              importedName,
              sourcePath: filePath,
              targetPath: moduleName,
              importType: 'function', // Could be function, class, or variable
              line: node.loc.start.line,
              column: node.loc.start.column
            });
          }
        }
      }
    }
    
    return imports;
  }

  private extractModuleName(node: AstNode): string | null {
    if (node.type === 'dotted_name') {
      return node.text;
    } else if (node.type === 'aliased_import') {
      const name_node = node.children?.find(child => child.type === 'dotted_name');
      return name_node?.text || null;
    }
    return null;
  }

  private extractImportedName(node: AstNode): string | null {
    if (node.type === 'identifier') {
      return node.text;
    } else if (node.type === 'aliased_import') {
      const name_node = node.children?.find(child => child.type === 'identifier');
      return name_node?.text || null;
    }
    return null;
  }

  private attemptModuleResolution(importInfo: ImportInfo): string | null {
    const modulePath = importInfo.targetPath || importInfo.importedName;
    
    // Try common Python file extensions
    const extensions = ['.py', '__init__.py'];
    const possiblePaths = [
      path.join(this.workspaceRoot, `${modulePath}.py`),
      path.join(this.workspaceRoot, modulePath, '__init__.py'),
      path.join(path.dirname(importInfo.sourcePath), `${modulePath}.py`),
      path.join(path.dirname(importInfo.sourcePath), modulePath, '__init__.py')
    ];

    for (const possiblePath of possiblePaths) {
      if (fs.existsSync(possiblePath)) {
        return possiblePath;
      }
    }

    return null;
  }

  private attemptRelativeResolution(importInfo: ImportInfo): string | null {
    const sourceDir = path.dirname(importInfo.sourcePath);
    const targetPath = importInfo.targetPath || importInfo.importedName;
    
    // Handle relative imports (starting with . or ..)
    if (targetPath.startsWith('.')) {
      const resolved = path.resolve(sourceDir, `${targetPath}.py`);
      if (fs.existsSync(resolved)) {
        return resolved;
      }
    }

    return null;
  }

  private traverse(node: AstNode, callback: (node: AstNode) => void): void {
    callback(node);
    for (const child of node.children || []) {
      this.traverse(child, callback);
    }
  }

  private findChildByType(node: AstNode, type: string): AstNode | null {
    return node.children?.find(child => child.type === type) || null;
  }

  private isModuleLevelFunction(ast: AstNode, functionName: string): boolean {
    // Check if function is defined at module level (global scope)
    let found = false;
    this.traverse(ast, (node) => {
      if (node.type === 'function_definition' && node.scope === 'global') {
        const nameNode = this.findChildByType(node, 'identifier');
        if (nameNode?.text === functionName) {
          found = true;
        }
      }
    });
    return found;
  }

  private findFunctionNodeId(ast: AstNode, functionName: string): number | null {
    let nodeId: number | null = null;
    this.traverse(ast, (node) => {
      if (node.type === 'function_definition') {
        const nameNode = this.findChildByType(node, 'identifier');
        if (nameNode?.text === functionName) {
          nodeId = node.id;
        }
      }
    });
    return nodeId;
  }

  private extractAssignmentTargets(node: AstNode): string[] {
    const targets: string[] = [];
    
    if (node.type === 'assignment' && node.children?.length >= 1) {
      const leftSide = node.children[0];
      this.traverse(leftSide, (child) => {
        if (child.type === 'identifier') {
          targets.push(child.text);
        }
      });
    }
    
    return targets;
  }

  public reset(): void {
    this.importMap.clear();
    this.exportMap.clear();
    this.moduleResolutionCache.clear();
  }
}
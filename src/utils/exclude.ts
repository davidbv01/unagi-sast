import * as vscode from 'vscode';

/**
 * Check if a file should be excluded from scanning
 */
export function shouldExcludeFile(filePath: string, excludePatterns: string[]): boolean {
  const relativePath = vscode.workspace.asRelativePath(filePath);
  return excludePatterns.some(pattern => {
    // Convert glob pattern to regex
    const regexPattern = pattern
      .replace(/\*\*/g, '.*')
      .replace(/\*/g, '[^/]*')
      .replace(/\?/g, '[^/]');
    const regex = new RegExp(regexPattern, 'i');
    return regex.test(relativePath);
  });
} 
import * as vscode from 'vscode';
import * as path from 'path';

export class FileUtils {
  /**
   * Check if a file should be excluded from scanning
   */
  public static shouldExcludeFile(filePath: string, excludePatterns: string[]): boolean {
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

  /**
   * Get supported file extensions for scanning
   */
  public static getSupportedExtensions(): string[] {
    return ['.py'];
  }

  /**
   * Check if file extension is supported
   */
  public static isSupportedFile(filePath: string): boolean {
    const ext = path.extname(filePath);
    return this.getSupportedExtensions().includes(ext);
  }

  /**
   * Get language ID from file extension
   */
  public static getLanguageFromExtension(filePath: string): string {
    const ext = path.extname(filePath);
    const languageMap: Record<string, string> = {
      '.py': 'python'
    };
    
    return languageMap[ext] || 'plaintext';
  }
}

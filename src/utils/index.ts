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

export class StringUtils {
  /**
   * Escape special regex characters in a string
   */
  public static escapeRegex(str: string): string {
    return str.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
  }

  /**
   * Truncate string to specified length
   */
  public static truncate(str: string, length: number): string {
    return str.length > length ? str.substring(0, length) + '...' : str;
  }

  /**
   * Get line content at specified line number
   */
  public static getLineContent(content: string, lineNumber: number): string {
    const lines = content.split('\n');
    return lines[lineNumber - 1] || '';
  }
}

export class SecurityUtils {
  /**
   * Check if a string contains potential secrets
   */
  public static containsPotentialSecret(str: string): boolean {
    const secretPatterns = [
      /[a-fA-F0-9]{32,}/,  // MD5-like hashes
      /[a-zA-Z0-9+/]{20,}={0,2}/,  // Base64-like strings
      /sk_[a-zA-Z0-9]{24,}/,  // Stripe secret keys
      /ghp_[a-zA-Z0-9]{36}/,  // GitHub personal access tokens
      /AIza[0-9A-Za-z-_]{35}/,  // Google API keys
      /AKIA[0-9A-Z]{16}/  // AWS access keys
    ];
    
    return secretPatterns.some(pattern => pattern.test(str));
  }

  /**
   * Calculate risk score based on vulnerabilities
   */
  public static calculateRiskScore(vulnerabilities: any[]): number {
    const weights = {
      critical: 10,
      high: 7,
      medium: 4,
      low: 1,
      info: 0.5
    };
    
    return vulnerabilities.reduce((score, vuln) => {
      return score + (weights[vuln.severity as keyof typeof weights] || 0);
    }, 0);
  }
}

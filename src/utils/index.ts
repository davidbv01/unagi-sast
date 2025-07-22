import * as path from 'path';

export class FileUtils {
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

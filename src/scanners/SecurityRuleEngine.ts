import { Vulnerability, VulnerabilityType, Severity } from '../types';
import { ASTSecurityEngine } from './ASTSecurityEngine';

export class SecurityRuleEngine {
  private astEngine: ASTSecurityEngine;

  constructor() {
    this.astEngine = new ASTSecurityEngine();
  }

  public async scanContent(content: string, languageId: string, fileName: string): Promise<Vulnerability[]> {
    // Only process Python files
    if (languageId === 'python') {
      return await this.astEngine.scanContent(content, languageId, fileName);
    }

    // Return empty array for non-Python files
    return [];
  }
}

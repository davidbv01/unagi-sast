import { Vulnerability, VulnerabilityType, Severity } from '../types';
import { ASTSecurityEngine } from './ASTSecurityEngine';
import { PythonSecurityRules } from './PythonSecurityRules';

export class SecurityRuleEngine {
  private astEngine: ASTSecurityEngine;
  private pythonRules: PythonSecurityRules;

  constructor() {
    this.astEngine = new ASTSecurityEngine();
    this.pythonRules = new PythonSecurityRules();
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

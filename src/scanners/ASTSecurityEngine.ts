import { Vulnerability, VulnerabilityType, Severity, ASTScanRule, ASTScanContext } from '../types';
import { ASTParser } from './ASTParser';
import { ASTSecurityRules } from './ASTSecurityRules';

export class ASTSecurityEngine {
  private parser: ASTParser;
  private securityRules: ASTSecurityRules;
  private rules: ASTScanRule[];

  constructor() {
    this.parser = new ASTParser();
    this.securityRules = new ASTSecurityRules();
    this.rules = this.securityRules.getASTRules();
  }

  public async scanContent(content: string, languageId: string, fileName: string): Promise<Vulnerability[]> {
    const vulnerabilities: Vulnerability[] = [];

    // Only process JavaScript/TypeScript for now
    if (!['javascript', 'typescript', 'jsx', 'tsx'].includes(languageId)) {
      return vulnerabilities;
    }

    try {
      const parsed = this.parser.parse(content, languageId, fileName);
      if (!parsed) {
        console.warn(`Could not parse AST for ${fileName}`);
        return vulnerabilities;
      }

      const context = this.createScanContext(content, languageId, fileName, parsed);
      const applicableRules = this.rules.filter(rule => 
        rule.enabled && rule.languages.includes(languageId)
      );

      // Traverse the AST and apply rules
      parsed.traverse(parsed.ast, {
        enter: (path: any) => {
          const node = path.node;
          
          for (const rule of applicableRules) {
            try {
              const match = rule.checker(node, context);
              if (match) {
                const position = this.parser.getNodePosition(node, content);
                const vulnerability: Vulnerability = {
                  id: `${rule.id}-${position.line}-${position.column}`,
                  type: rule.type,
                  severity: rule.severity,
                  message: match.message || rule.name,
                  file: fileName,
                  line: position.line,
                  column: position.column,
                  rule: rule.id,
                  description: rule.description,
                  recommendation: this.getRecommendation(rule.type)
                };
                vulnerabilities.push(vulnerability);
              }
            } catch (error) {
              console.error(`Error applying rule ${rule.id}:`, error);
            }
          }
        }
      });

    } catch (error) {
      console.error(`AST scanning failed for ${fileName}:`, error);
    }

    return vulnerabilities;
  }

  private createScanContext(content: string, languageId: string, fileName: string, parsed: any): ASTScanContext {
    return {
      fileName,
      sourceCode: content,
      languageId,
      isUserInput: (node: any) => {
        // Simplified heuristic - could be enhanced with data flow analysis
        return this.isLikelyUserInput(node);
      },
      isTainted: (node: any) => {
        // Simplified taint analysis - could be enhanced
        return this.isLikelyTainted(node);
      },
      getNodeText: (node: any) => {
        return this.parser.getNodeText(node, content);
      },
      getParentNodes: (node: any) => {
        // This would require path context from traverse - simplified for now
        return [];
      }
    };
  }

  private isLikelyUserInput(node: any): boolean {
    // Simplified heuristic to detect user input
    const nodeText = this.parser.getNodeText(node, '').toLowerCase();
    const userInputIndicators = [
      'req.body', 'req.query', 'req.params', 'request.',
      'input', 'user', 'param', 'query', 'body',
      'document.getElementById', 'getElementById',
      'prompt(', 'confirm(', 'window.location'
    ];
    
    return userInputIndicators.some(indicator => nodeText.includes(indicator));
  }

  private isLikelyTainted(node: any): boolean {
    // This would need proper data flow analysis
    // For now, we use simple heuristics
    return this.isLikelyUserInput(node);
  }

  private getRecommendation(type: VulnerabilityType): string {
    const recommendations: Record<VulnerabilityType, string> = {
      [VulnerabilityType.SQL_INJECTION]: 'Use parameterized queries or ORM methods to prevent SQL injection.',
      [VulnerabilityType.XSS]: 'Sanitize user input and use safe DOM manipulation methods like textContent.',
      [VulnerabilityType.HARDCODED_SECRET]: 'Store secrets in environment variables or secure configuration.',
      [VulnerabilityType.WEAK_CRYPTO]: 'Use strong cryptographic algorithms like SHA-256 or bcrypt.',
      [VulnerabilityType.COMMAND_INJECTION]: 'Validate input and use safe alternatives to exec/eval.',
      [VulnerabilityType.PATH_TRAVERSAL]: 'Validate file paths and use path.resolve() with proper checks.',
      [VulnerabilityType.CSRF]: 'Implement CSRF tokens and validate requests.',
      [VulnerabilityType.INSECURE_RANDOM]: 'Use cryptographically secure random number generators.',
      [VulnerabilityType.AUTHORIZATION]: 'Implement proper access controls and permission checks.',
      [VulnerabilityType.AUTHENTICATION]: 'Use secure authentication mechanisms and session management.'
    };
    
    return recommendations[type] || 'Review the code for potential security issues.';
  }

  public enableRule(ruleId: string): void {
    const rule = this.rules.find(r => r.id === ruleId);
    if (rule) {
      rule.enabled = true;
    }
  }

  public disableRule(ruleId: string): void {
    const rule = this.rules.find(r => r.id === ruleId);
    if (rule) {
      rule.enabled = false;
    }
  }

  public getAvailableRules(): ASTScanRule[] {
    return [...this.rules];
  }
}

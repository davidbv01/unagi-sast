import { Vulnerability, VulnerabilityType, Severity, ASTScanRule, ASTScanContext } from '../types';
import { ASTParser } from './ASTParser';
import { PythonSecurityRules } from './PythonSecurityRules';
import * as vscode from 'vscode';

export class ASTSecurityEngine {
  private parser: ASTParser;
  private pythonRules: PythonSecurityRules;
  private rules: ASTScanRule[];
  private outputChannel: vscode.OutputChannel;

  constructor() {
    this.parser = new ASTParser();
    this.pythonRules = new PythonSecurityRules();
    this.rules = this.pythonRules.getPythonRules();
    this.outputChannel = vscode.window.createOutputChannel('Unagi SAST Debug');
  }

  public async scanContent(content: string, languageId: string, fileName: string): Promise<Vulnerability[]> {
    const vulnerabilities: Vulnerability[] = [];
    this.outputChannel.appendLine(`[DEBUG] Starting AST scan for ${fileName} (${languageId})`);

    // Only process Python files
    if (languageId !== 'python') {
      this.outputChannel.appendLine(`[DEBUG] Skipping non-Python file: ${fileName}`);
      return vulnerabilities;
    }

    try {
      this.outputChannel.appendLine(`[DEBUG] Parsing content for ${fileName}`);
      const parsed = this.parser.parse(content, languageId, fileName);
      if (!parsed) {
        this.outputChannel.appendLine(`[DEBUG] Failed to parse AST for ${fileName}`);
        return vulnerabilities;
      }
      this.outputChannel.appendLine(`[DEBUG] Successfully parsed AST for ${fileName}`);

      const context = this.createScanContext(content, languageId, fileName, parsed);
      const applicableRules = this.rules.filter(rule => 
        rule.enabled && rule.languages.includes(languageId)
      );
      this.outputChannel.appendLine(`[DEBUG] Found ${applicableRules.length} applicable rules for ${fileName}`);
      this.outputChannel.appendLine(`[DEBUG] Rules: ${applicableRules.map(r => r.id).join(', ')}`);

      // Traverse the AST and apply rules
      this.outputChannel.appendLine(`[DEBUG] Starting AST traversal for ${fileName}`);
      parsed.traverse(parsed.ast, {
        enter: (path: any) => {
          const node = path.node;
          this.outputChannel.appendLine(`[DEBUG] Processing node type: ${node.type}`);
          
          for (const rule of applicableRules) {
            try {
              this.outputChannel.appendLine(`[DEBUG] Applying rule ${rule.id} to node type ${node.type}`);
              const match = rule.checker(node, context);
              if (match) {
                this.outputChannel.appendLine(`[DEBUG] Found vulnerability match for rule ${rule.id}`);
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
                this.outputChannel.appendLine(`[DEBUG] Added vulnerability: ${vulnerability.message} at line ${vulnerability.line}`);
              }
            } catch (error) {
              this.outputChannel.appendLine(`[DEBUG] Error applying rule ${rule.id}: ${error}`);
            }
          }
        }
      });

      this.outputChannel.appendLine(`[DEBUG] Completed AST traversal for ${fileName}. Found ${vulnerabilities.length} vulnerabilities`);

    } catch (error) {
      this.outputChannel.appendLine(`[DEBUG] Error scanning file ${fileName}: ${error}`);
    }

    return vulnerabilities;
  }

  private createScanContext(content: string, languageId: string, fileName: string, parsed: any): ASTScanContext {
    return {
      fileName,
      sourceCode: content,
      languageId,
      getNodeText: (node: any) => {
        return content.substring(node.start, node.end);
      },
      isUserInput: (node: any) => {
        // Check if node represents user input (e.g., function parameters, form values)
        return node.type === 'Identifier' || node.type === 'MemberExpression';
      },
      isTainted: (node: any) => {
        // Check if node represents potentially tainted data
        return this.isUserInput(node) || this.containsVariableExpression(node);
      },
      getParentNodes: (node: any) => {
        const parents: any[] = [];
        let current = node;
        while (current.parent) {
          parents.push(current.parent);
          current = current.parent;
        }
        return parents;
      }
    };
  }

  private getRecommendation(type: VulnerabilityType): string {
    const recommendations: Record<VulnerabilityType, string> = {
      [VulnerabilityType.SQL_INJECTION]: 'Use parameterized queries or an ORM',
      [VulnerabilityType.COMMAND_INJECTION]: 'Avoid using shell=True and validate/sanitize input',
      [VulnerabilityType.PATH_TRAVERSAL]: 'Validate and sanitize file paths',
      [VulnerabilityType.INSECURE_DESERIALIZATION]: 'Use safe deserialization methods or validate input',
      [VulnerabilityType.HARDCODED_SECRET]: 'Use environment variables or secure secret management',
      [VulnerabilityType.INSECURE_PERMISSIONS]: 'Use more restrictive file permissions',
      [VulnerabilityType.INSECURE_DIRECT_OBJECT_REFERENCE]: 'Implement proper access controls',
      [VulnerabilityType.XSS]: 'Sanitize user input and use proper output encoding',
      [VulnerabilityType.WEAK_CRYPTO]: 'Use strong cryptographic algorithms and proper key management',
      [VulnerabilityType.INSECURE_COMMUNICATION]: 'Use secure communication protocols (HTTPS, TLS)',
      [VulnerabilityType.CSRF]: 'Implement CSRF tokens and validate requests',
      [VulnerabilityType.INSECURE_RANDOM]: 'Use cryptographically secure random number generators',
      [VulnerabilityType.AUTHORIZATION]: 'Implement proper authorization checks',
      [VulnerabilityType.AUTHENTICATION]: 'Use secure authentication methods',
      [VulnerabilityType.IDOR]: 'Implement proper access controls and object reference validation',
      [VulnerabilityType.GENERIC]: 'Review and fix the identified security issue'
    };
    return recommendations[type] || recommendations[VulnerabilityType.GENERIC];
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

  private isUserInput(node: any): boolean {
    return node.type === 'Identifier' || node.type === 'MemberExpression';
  }

  private containsVariableExpression(node: any): boolean {
    if (!node) return false;
    
    if (this.isUserInput(node)) {
      return true;
    }
    
    if (node.type === 'BinaryExpression') {
      return this.containsVariableExpression(node.left) || 
             this.containsVariableExpression(node.right);
    }
    
    if (node.type === 'CallExpression') {
      return true; // Function calls might return user input
    }
    
    return false;
  }
}

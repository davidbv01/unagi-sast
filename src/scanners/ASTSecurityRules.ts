import * as t from '@babel/types';
import { ASTScanRule, VulnerabilityType, Severity, ASTScanContext, ASTVulnerabilityMatch } from '../types';

export class ASTSecurityRules {

  public getASTRules(): ASTScanRule[] {
    return [
      this.sqlInjectionRule(),
      this.xssRule(),
      this.hardcodedSecretRule(),
      this.commandInjectionRule(),
      this.pathTraversalRule(),
      this.weakCryptoRule(),
      this.evalUsageRule(),
      this.dangerousAssignmentRule()
    ];
  }

  private sqlInjectionRule(): ASTScanRule {
    return {
      id: 'ast-sql-injection-1',
      name: 'SQL Injection via String Concatenation',
      description: 'Detected SQL query built with string concatenation',
      severity: Severity.HIGH,
      type: VulnerabilityType.SQL_INJECTION,
      languages: ['javascript', 'typescript'],
      enabled: true,
      checker: (node: any, context: ASTScanContext): ASTVulnerabilityMatch | null => {
        // Look for string concatenation with SQL keywords
        if (t.isBinaryExpression(node) && node.operator === '+') {
          const nodeText = context.getNodeText(node).toLowerCase();
          const sqlKeywords = ['select', 'insert', 'update', 'delete', 'drop', 'create', 'alter'];
          
          if (sqlKeywords.some(keyword => nodeText.includes(keyword))) {
            // Check if any part involves variables (potential user input)
            if (this.containsVariableExpression(node)) {
              return {
                node,
                message: 'SQL query constructed with string concatenation - use parameterized queries',
                additionalInfo: { sqlPattern: nodeText }
              };
            }
          }
        }
        return null;
      }
    };
  }

  private xssRule(): ASTScanRule {
    return {
      id: 'ast-xss-1',
      name: 'DOM XSS via innerHTML',
      description: 'Unsafe assignment to innerHTML with user input',
      severity: Severity.MEDIUM,
      type: VulnerabilityType.XSS,
      languages: ['javascript', 'typescript'],
      enabled: true,
      checker: (node: any, context: ASTScanContext): ASTVulnerabilityMatch | null => {
        // Look for assignments to innerHTML
        if (t.isAssignmentExpression(node) && 
            t.isMemberExpression(node.left) &&
            t.isIdentifier(node.left.property) &&
            node.left.property.name === 'innerHTML') {
          
          // Check if the assigned value contains concatenation or variables
          if (this.containsVariableExpression(node.right)) {
            return {
              node,
              message: 'Unsafe innerHTML assignment - sanitize user input',
              additionalInfo: { property: 'innerHTML' }
            };
          }
        }
        return null;
      }
    };
  }

  private hardcodedSecretRule(): ASTScanRule {
    return {
      id: 'ast-hardcoded-secret-1',
      name: 'Hardcoded API Key or Secret',
      description: 'Potential hardcoded secret found in assignment',
      severity: Severity.CRITICAL,
      type: VulnerabilityType.HARDCODED_SECRET,
      languages: ['javascript', 'typescript'],
      enabled: true,      checker: (node: any, context: ASTScanContext): ASTVulnerabilityMatch | null => {
        // Look for variable assignments or object properties
        let value: any = null;
        let keyName: string = '';
        
        if (t.isVariableDeclarator(node) && t.isStringLiteral(node.init)) {
          value = node.init.value;
          keyName = this.getKeyName(node);
        } else if (t.isObjectProperty(node) && t.isStringLiteral(node.value)) {
          value = node.value.value;
          keyName = this.getKeyName(node);
        }
        
        if (value && keyName) {
          // Check for suspicious key names and long string values
          const suspiciousNames = ['api_key', 'apikey', 'secret', 'token', 'password', 'pass'];
          if (suspiciousNames.some(name => keyName.toLowerCase().includes(name))) {
            if (typeof value === 'string' && value.length >= 16 && /^[a-zA-Z0-9+/=]+$/.test(value)) {
              return {
                node,
                message: `Potential hardcoded secret in '${keyName}' - use environment variables`,
                additionalInfo: { keyName, valueLength: value.length }
              };
            }
          }
        }
        return null;
      }
    };
  }

  private commandInjectionRule(): ASTScanRule {
    return {
      id: 'ast-command-injection-1',
      name: 'Command Injection Risk',
      description: 'Dangerous function call with user input',
      severity: Severity.HIGH,
      type: VulnerabilityType.COMMAND_INJECTION,
      languages: ['javascript', 'typescript'],
      enabled: true,
      checker: (node: any, context: ASTScanContext): ASTVulnerabilityMatch | null => {
        if (t.isCallExpression(node)) {
          const funcName = this.getFunctionName(node);
          const dangerousFunctions = ['exec', 'spawn', 'execSync', 'spawnSync', 'eval', 'execFile'];
          
          if (dangerousFunctions.includes(funcName)) {
            // Check if arguments contain variables or concatenation
            if (node.arguments.some((arg: any) => this.containsVariableExpression(arg))) {
              return {
                node,
                message: `Dangerous '${funcName}' call with user input - validate and sanitize`,
                additionalInfo: { functionName: funcName }
              };
            }
          }
        }
        return null;
      }
    };
  }

  private pathTraversalRule(): ASTScanRule {
    return {
      id: 'ast-path-traversal-1',
      name: 'Path Traversal Risk',
      description: 'File path construction with user input',
      severity: Severity.MEDIUM,
      type: VulnerabilityType.PATH_TRAVERSAL,
      languages: ['javascript', 'typescript'],
      enabled: true,
      checker: (node: any, context: ASTScanContext): ASTVulnerabilityMatch | null => {
        // Look for path operations
        if (t.isCallExpression(node)) {
          const funcName = this.getFunctionName(node);
          const pathFunctions = ['readFile', 'writeFile', 'readFileSync', 'writeFileSync', 'join', 'resolve'];
          
          if (pathFunctions.includes(funcName)) {
            // Check for string literals containing ../ or ..\
            const hasTraversalPattern = node.arguments.some((arg: any) => {
              if (t.isStringLiteral(arg)) {
                return /\.\.[\\/]/.test(arg.value);
              }
              return false;
            });
            
            if (hasTraversalPattern || 
                node.arguments.some((arg: any) => this.containsVariableExpression(arg))) {
              return {
                node,
                message: `Path traversal risk in '${funcName}' - validate file paths`,
                additionalInfo: { functionName: funcName }
              };
            }
          }
        }
        return null;
      }
    };
  }

  private weakCryptoRule(): ASTScanRule {
    return {
      id: 'ast-weak-crypto-1',
      name: 'Weak Cryptographic Algorithm',
      description: 'Use of weak hashing algorithm',
      severity: Severity.MEDIUM,
      type: VulnerabilityType.WEAK_CRYPTO,
      languages: ['javascript', 'typescript'],
      enabled: true,
      checker: (node: any, context: ASTScanContext): ASTVulnerabilityMatch | null => {
        if (t.isCallExpression(node)) {
          const nodeText = context.getNodeText(node).toLowerCase();
          const weakAlgorithms = ['md5', 'sha1'];
          
          const usedWeakAlgo = weakAlgorithms.find(algo => nodeText.includes(algo));
          if (usedWeakAlgo) {
            return {
              node,
              message: `Weak cryptographic algorithm '${usedWeakAlgo}' - use SHA-256 or stronger`,
              additionalInfo: { algorithm: usedWeakAlgo }
            };
          }
        }
        return null;
      }
    };
  }

  private evalUsageRule(): ASTScanRule {
    return {
      id: 'ast-eval-usage-1',
      name: 'Dangerous eval() Usage',
      description: 'Use of eval() function',
      severity: Severity.HIGH,
      type: VulnerabilityType.COMMAND_INJECTION,
      languages: ['javascript', 'typescript'],
      enabled: true,
      checker: (node: any, context: ASTScanContext): ASTVulnerabilityMatch | null => {
        if (t.isCallExpression(node) && 
            t.isIdentifier(node.callee) && 
            node.callee.name === 'eval') {
          return {
            node,
            message: 'Dangerous eval() usage - avoid dynamic code execution',
            additionalInfo: { functionName: 'eval' }
          };
        }
        return null;
      }
    };
  }

  private dangerousAssignmentRule(): ASTScanRule {
    return {
      id: 'ast-dangerous-assignment-1',
      name: 'Dangerous Property Assignment',
      description: 'Assignment to dangerous properties',
      severity: Severity.MEDIUM,
      type: VulnerabilityType.XSS,
      languages: ['javascript', 'typescript'],
      enabled: true,
      checker: (node: any, context: ASTScanContext): ASTVulnerabilityMatch | null => {
        if (t.isAssignmentExpression(node) && t.isMemberExpression(node.left)) {
          const propertyName = this.getPropertyName(node.left);
          const dangerousProperties = ['innerHTML', 'outerHTML', 'insertAdjacentHTML'];
          
          if (dangerousProperties.includes(propertyName)) {
            return {
              node,
              message: `Dangerous assignment to '${propertyName}' - validate and sanitize input`,
              additionalInfo: { property: propertyName }
            };
          }
        }
        return null;
      }
    };
  }

  // Helper methods
  private containsVariableExpression(node: any): boolean {
    if (!node) return false;
    
    if (t.isIdentifier(node) || t.isMemberExpression(node)) {
      return true;
    }
    
    if (t.isBinaryExpression(node)) {
      return this.containsVariableExpression(node.left) || 
             this.containsVariableExpression(node.right);
    }
    
    if (t.isCallExpression(node)) {
      return true; // Function calls might return user input
    }
    
    return false;
  }

  private getFunctionName(node: any): string {
    if (t.isCallExpression(node)) {
      if (t.isIdentifier(node.callee)) {
        return node.callee.name;
      }
      if (t.isMemberExpression(node.callee) && t.isIdentifier(node.callee.property)) {
        return node.callee.property.name;
      }
    }
    return '';
  }

  private getPropertyName(node: any): string {
    if (t.isMemberExpression(node) && t.isIdentifier(node.property)) {
      return node.property.name;
    }
    return '';
  }

  private getKeyName(node: any): string {
    if (t.isVariableDeclarator(node) && t.isIdentifier(node.id)) {
      return node.id.name;
    }
    if (t.isObjectProperty(node)) {
      if (t.isIdentifier(node.key)) {
        return node.key.name;
      }
      if (t.isStringLiteral(node.key)) {
        return node.key.value;
      }
    }
    return '';
  }
}

import { ASTScanRule, VulnerabilityType, Severity, ASTScanContext, ASTVulnerabilityMatch } from '../types';

export class PythonSecurityRules {
  public getPythonRules(): ASTScanRule[] {
    return [
      this.sqlInjectionRule(),
      this.commandInjectionRule(),
      this.pathTraversalRule(),
      this.insecureDeserializationRule(),
      this.hardcodedSecretRule(),
      this.insecureFilePermissionsRule(),
      this.insecureDirectObjectReferenceRule()
    ];
  }

  private sqlInjectionRule(): ASTScanRule {
    return {
      id: 'py-sql-injection-1',
      name: 'SQL Injection via String Formatting',
      description: 'Detected SQL query built with string formatting',
      severity: Severity.HIGH,
      type: VulnerabilityType.SQL_INJECTION,
      languages: ['python'],
      enabled: true,
      checker: (node: any, context: ASTScanContext): ASTVulnerabilityMatch | null => {
        // Look for f-strings or string formatting with SQL keywords
        if (node.type === 'JoinedStr' || 
            (node.type === 'Call' && node.func?.id?.name === 'format')) {
          const nodeText = context.getNodeText(node).toLowerCase();
          const sqlKeywords = ['select', 'insert', 'update', 'delete', 'drop', 'create', 'alter'];
          
          if (sqlKeywords.some(keyword => nodeText.includes(keyword))) {
            return {
              node,
              message: 'SQL query constructed with string formatting - use parameterized queries',
              additionalInfo: { sqlPattern: nodeText }
            };
          }
        }
        return null;
      }
    };
  }

  private commandInjectionRule(): ASTScanRule {
    return {
      id: 'py-command-injection-1',
      name: 'Command Injection Risk',
      description: 'Dangerous command execution with user input',
      severity: Severity.HIGH,
      type: VulnerabilityType.COMMAND_INJECTION,
      languages: ['python'],
      enabled: true,
      checker: (node: any, context: ASTScanContext): ASTVulnerabilityMatch | null => {
        if (node.type === 'Call') {
          const funcName = this.getFunctionName(node);
          const dangerousFunctions = ['check_output', 'call', 'Popen', 'system', 'spawn'];
          
          if (dangerousFunctions.includes(funcName)) {
            // Check for shell=True or direct command execution
            const hasShellTrue = node.keywords?.some((kw: any) => 
              kw.arg === 'shell' && kw.value.value === true
            );
            
            if (hasShellTrue || this.containsVariableExpression(node)) {
              return {
                node,
                message: `Dangerous '${funcName}' call with shell=True - validate and sanitize input`,
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
      id: 'py-path-traversal-1',
      name: 'Path Traversal Risk',
      description: 'File path construction with user input',
      severity: Severity.MEDIUM,
      type: VulnerabilityType.PATH_TRAVERSAL,
      languages: ['python'],
      enabled: true,
      checker: (node: any, context: ASTScanContext): ASTVulnerabilityMatch | null => {
        if (node.type === 'JoinedStr' || 
            (node.type === 'Call' && node.func?.id?.name === 'format')) {
          const nodeText = context.getNodeText(node);
          if (nodeText.includes('../') || nodeText.includes('..\\')) {
            return {
              node,
              message: 'Path traversal risk - validate and sanitize file paths',
              additionalInfo: { pathPattern: nodeText }
            };
          }
        }
        return null;
      }
    };
  }

  private insecureDeserializationRule(): ASTScanRule {
    return {
      id: 'py-insecure-deserialization-1',
      name: 'Insecure Deserialization',
      description: 'Unsafe deserialization of user input',
      severity: Severity.HIGH,
      type: VulnerabilityType.INSECURE_DESERIALIZATION,
      languages: ['python'],
      enabled: true,
      checker: (node: any, context: ASTScanContext): ASTVulnerabilityMatch | null => {
        if (node.type === 'Call') {
          const funcName = this.getFunctionName(node);
          const dangerousFunctions = ['loads', 'load', 'unpickle'];
          
          if (dangerousFunctions.includes(funcName)) {
            return {
              node,
              message: `Dangerous deserialization with '${funcName}' - validate input or use safe alternatives`,
              additionalInfo: { functionName: funcName }
            };
          }
        }
        return null;
      }
    };
  }

  private hardcodedSecretRule(): ASTScanRule {
    return {
      id: 'py-hardcoded-secret-1',
      name: 'Hardcoded Secret',
      description: 'Potential hardcoded secret found',
      severity: Severity.CRITICAL,
      type: VulnerabilityType.HARDCODED_SECRET,
      languages: ['python'],
      enabled: true,
      checker: (node: any, context: ASTScanContext): ASTVulnerabilityMatch | null => {
        if (node.type === 'Assign') {
          const targetName = this.getVariableName(node.targets[0]);
          const suspiciousNames = ['password', 'secret', 'key', 'token', 'credential'];
          
          if (suspiciousNames.some(name => targetName.toLowerCase().includes(name))) {
            const value = node.value.value;
            if (typeof value === 'string' && value.length >= 16) {
              return {
                node,
                message: `Hardcoded secret in '${targetName}' - use environment variables or secure storage`,
                additionalInfo: { variableName: targetName }
              };
            }
          }
        }
        return null;
      }
    };
  }

  private insecureFilePermissionsRule(): ASTScanRule {
    return {
      id: 'py-insecure-permissions-1',
      name: 'Insecure File Permissions',
      description: 'Overly permissive file permissions',
      severity: Severity.MEDIUM,
      type: VulnerabilityType.INSECURE_PERMISSIONS,
      languages: ['python'],
      enabled: true,
      checker: (node: any, context: ASTScanContext): ASTVulnerabilityMatch | null => {
        if (node.type === 'Call' && this.getFunctionName(node) === 'chmod') {
          const mode = node.args[1]?.value;
          if (mode && (mode & 0o777) > 0o600) {
            return {
              node,
              message: 'Overly permissive file permissions - use more restrictive permissions',
              additionalInfo: { mode: mode.toString(8) }
            };
          }
        }
        return null;
      }
    };
  }

  private insecureDirectObjectReferenceRule(): ASTScanRule {
    return {
      id: 'py-idor-1',
      name: 'Insecure Direct Object Reference',
      description: 'Potential IDOR vulnerability in route handler',
      severity: Severity.HIGH,
      type: VulnerabilityType.INSECURE_DIRECT_OBJECT_REFERENCE,
      languages: ['python'],
      enabled: true,
      checker: (node: any, context: ASTScanContext): ASTVulnerabilityMatch | null => {
        if (node.type === 'FunctionDef' && 
            node.decorator_list?.some((d: any) => 
              d.func?.attr === 'route' || d.func?.id?.name === 'route')) {
          return {
            node,
            message: 'Route handler may be vulnerable to IDOR - implement proper access controls',
            additionalInfo: { route: node.name }
          };
        }
        return null;
      }
    };
  }

  // Helper methods
  private getFunctionName(node: any): string {
    if (node.func?.id?.name) {
      return node.func.id.name;
    }
    if (node.func?.attr) {
      return node.func.attr;
    }
    return '';
  }

  private getVariableName(node: any): string {
    if (node.id?.name) {
      return node.id.name;
    }
    return '';
  }

  private containsVariableExpression(node: any): boolean {
    if (!node) return false;
    
    if (node.type === 'Name') {
      return true;
    }
    
    if (node.type === 'JoinedStr') {
      return true;
    }
    
    if (node.type === 'Call') {
      return true;
    }
    
    return false;
  }

  private getPathParameters(node: any): string[] {
    const params: string[] = [];
    if (node.args && node.args[0]?.value) {
      const path = node.args[0].value;
      const matches = path.match(/<([^>]+)>/g) || [];
      params.push(...matches.map((m: string) => m.slice(1, -1)));
    }
    return params;
  }
} 
import { ASTScanRule, ASTScanContext, ASTVulnerabilityMatch, Severity, VulnerabilityType } from '../types';
import * as t from '@babel/types';

export class ASTSecurityRules {
  public getRules(): ASTScanRule[] {
    return [
      this.sqlInjectionRule(),
      this.commandInjectionRule(),
      this.insecureDeserializationRule()
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

  private getFunctionName(node: any): string {
    if (node.func?.id?.name) {
      return node.func.id.name;
    }
    if (node.func?.attr) {
      return node.func.attr;
    }
    return '';
  }

  private containsVariableExpression(node: any): boolean {
    if (!node) return false;
    
    if (node.type === 'Name') {
      return true;
    }
    
    for (const key in node) {
      if (node[key] && typeof node[key] === 'object') {
        if (Array.isArray(node[key])) {
          if (node[key].some((child: any) => this.containsVariableExpression(child))) {
            return true;
          }
        } else if (this.containsVariableExpression(node[key])) {
          return true;
        }
      }
    }
    
    return false;
  }
}

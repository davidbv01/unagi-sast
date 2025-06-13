import { ASTScanRule, VulnerabilityType, Severity, ASTScanContext, ASTVulnerabilityMatch } from '../types';
import * as vscode from 'vscode';

export class PythonSecurityRules {
  private outputChannel: vscode.OutputChannel;

  constructor() {
    this.outputChannel = vscode.window.createOutputChannel('Unagi SAST Rules');
  }

  public getPythonRules(): ASTScanRule[] {
    console.log('[DEBUG] Loading Python security rules');
    this.outputChannel.appendLine('[DEBUG] Loading Python security rules');
    
    const rules = [
      this.sqlInjectionRule(),
      this.commandInjectionRule(),
      this.pathTraversalRule(),
      this.insecureDeserializationRule(),
      this.hardcodedSecretRule(),
      this.insecureFilePermissionsRule(),
      this.insecureDirectObjectReferenceRule()
    ];

    console.log(`[DEBUG] Loaded ${rules.length} Python security rules`);
    this.outputChannel.appendLine(`[DEBUG] Loaded ${rules.length} Python security rules`);
    return rules;
  }

  private sqlInjectionRule(): ASTScanRule {
    console.log('[DEBUG] Creating SQL injection rule');
    this.outputChannel.appendLine('[DEBUG] Creating SQL injection rule');
    
    return {
      id: 'py-sql-injection-1',
      name: 'SQL Injection via String Formatting',
      description: 'Detected SQL query built with string formatting',
      severity: Severity.HIGH,
      type: VulnerabilityType.SQL_INJECTION,
      languages: ['python'],
      enabled: true,
      checker: (node: any, context: ASTScanContext): ASTVulnerabilityMatch | null => {
        console.log(`[DEBUG] Checking SQL injection rule on node type: ${node.type}`);
        this.outputChannel.appendLine(`[DEBUG] Checking SQL injection rule on node type: ${node.type}`);
        
        // Check for f-strings, string formatting, or string concatenation with SQL keywords
        if (node.type === 'JoinedStr' || 
            (node.type === 'BinOp' && node.op.type === 'Add') ||
            (node.type === 'Call' && node.func?.attr === 'format')) {
          const nodeText = context.getNodeText(node).toLowerCase();
          this.outputChannel.appendLine(`[DEBUG] Found string formatting node with text: ${nodeText}`);
          const sqlKeywords = ['select', 'insert', 'update', 'delete', 'drop', 'create', 'alter'];
          
          if (sqlKeywords.some(keyword => nodeText.includes(keyword))) {
            console.log('[DEBUG] Found SQL keyword in node text');
            this.outputChannel.appendLine('[DEBUG] Found SQL keyword in node text');
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
    console.log('[DEBUG] Creating command injection rule');
    this.outputChannel.appendLine('[DEBUG] Creating command injection rule');
    
    return {
      id: 'py-command-injection-1',
      name: 'Command Injection Risk',
      description: 'Dangerous command execution with user input',
      severity: Severity.HIGH,
      type: VulnerabilityType.COMMAND_INJECTION,
      languages: ['python'],
      enabled: true,
      checker: (node: any, context: ASTScanContext): ASTVulnerabilityMatch | null => {
        console.log(`[DEBUG] Checking command injection rule on node type: ${node.type}`);
        this.outputChannel.appendLine(`[DEBUG] Checking command injection rule on node type: ${node.type}`);
        
        if (node.type === 'Call') {
          const funcName = this.getFunctionName(node);
          this.outputChannel.appendLine(`[DEBUG] Found function call: ${funcName}`);
          
          console.log(`[DEBUG] Checking function call: ${funcName}`);
          this.outputChannel.appendLine(`[DEBUG] Checking function call: ${funcName}`);
          
          const dangerousFunctions = ['check_output', 'call', 'Popen', 'system', 'spawn'];
          
          if (dangerousFunctions.includes(funcName)) {
            console.log(`[DEBUG] Found dangerous function: ${funcName}`);
            this.outputChannel.appendLine(`[DEBUG] Found dangerous function: ${funcName}`);
            
            // Check for shell=True or direct command execution
            const hasShellTrue = node.keywords?.some((kw: any) => 
              kw.arg === 'shell' && kw.value.value === true
            );
            
            if (hasShellTrue || this.containsVariableExpression(node)) {
              console.log(`[DEBUG] Found shell=True or variable expression in dangerous function call`);
              this.outputChannel.appendLine(`[DEBUG] Found shell=True or variable expression in dangerous function call`);
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
    console.log('[DEBUG] Creating path traversal rule');
    this.outputChannel.appendLine('[DEBUG] Creating path traversal rule');
    
    return {
      id: 'py-path-traversal-1',
      name: 'Path Traversal Risk',
      description: 'File path construction with user input',
      severity: Severity.MEDIUM,
      type: VulnerabilityType.PATH_TRAVERSAL,
      languages: ['python'],
      enabled: true,
      checker: (node: any, context: ASTScanContext): ASTVulnerabilityMatch | null => {
        console.log(`[DEBUG] Checking path traversal rule for node type: ${node.type}`);
        this.outputChannel.appendLine(`[DEBUG] Checking path traversal rule for node type: ${node.type}`);
        
        if (node.type === 'JoinedStr' || 
            (node.type === 'BinOp' && node.op.type === 'Add') ||
            (node.type === 'Call' && node.func?.attr === 'join')) {
          const nodeText = context.getNodeText(node);
          this.outputChannel.appendLine(`[DEBUG] Found string formatting node with text: ${nodeText}`);
          
          console.log(`[DEBUG] Checking path: ${nodeText}`);
          this.outputChannel.appendLine(`[DEBUG] Checking path: ${nodeText}`);
          
          if (nodeText.includes('../') || nodeText.includes('..\\')) {
            console.log('[DEBUG] Found path traversal pattern in node text');
            this.outputChannel.appendLine('[DEBUG] Found path traversal pattern in node text');
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
    console.log('[DEBUG] Creating insecure deserialization rule');
    this.outputChannel.appendLine('[DEBUG] Creating insecure deserialization rule');
    
    return {
      id: 'py-insecure-deserialization-1',
      name: 'Insecure Deserialization',
      description: 'Unsafe deserialization of user input',
      severity: Severity.HIGH,
      type: VulnerabilityType.INSECURE_DESERIALIZATION,
      languages: ['python'],
      enabled: true,
      checker: (node: any, context: ASTScanContext): ASTVulnerabilityMatch | null => {
        console.log(`[DEBUG] Checking insecure deserialization rule for node type: ${node.type}`);
        this.outputChannel.appendLine(`[DEBUG] Checking insecure deserialization rule for node type: ${node.type}`);
        
        if (node.type === 'Call') {
          const funcName = this.getFunctionName(node);
          this.outputChannel.appendLine(`[DEBUG] Found function call: ${funcName}`);
          
          console.log(`[DEBUG] Checking function call: ${funcName}`);
          this.outputChannel.appendLine(`[DEBUG] Checking function call: ${funcName}`);
          
          const dangerousFunctions = ['loads', 'load', 'unpickle'];
          
          if (dangerousFunctions.includes(funcName)) {
            console.log(`[DEBUG] Found dangerous deserialization function: ${funcName}`);
            this.outputChannel.appendLine(`[DEBUG] Found dangerous deserialization function: ${funcName}`);
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
    console.log('[DEBUG] Creating hardcoded secrets rule');
    this.outputChannel.appendLine('[DEBUG] Creating hardcoded secrets rule');
    
    return {
      id: 'py-hardcoded-secret-1',
      name: 'Hardcoded Secret',
      description: 'Potential hardcoded secret found',
      severity: Severity.CRITICAL,
      type: VulnerabilityType.HARDCODED_SECRET,
      languages: ['python'],
      enabled: true,
      checker: (node: any, context: ASTScanContext): ASTVulnerabilityMatch | null => {
        console.log(`[DEBUG] Checking hardcoded secrets rule for node type: ${node.type}`);
        this.outputChannel.appendLine(`[DEBUG] Checking hardcoded secrets rule for node type: ${node.type}`);
        
        if (node.type === 'Assign') {
          const targetName = this.getVariableName(node.targets[0]);
          this.outputChannel.appendLine(`[DEBUG] Found assignment to variable: ${targetName}`);
          
          console.log(`[DEBUG] Checking variable name: ${targetName}`);
          this.outputChannel.appendLine(`[DEBUG] Checking variable name: ${targetName}`);
          
          const suspiciousNames = ['password', 'secret', 'key', 'token', 'credential'];
          
          if (suspiciousNames.some(name => targetName.toLowerCase().includes(name))) {
            console.log(`[DEBUG] Found suspicious variable name: ${targetName}`);
            this.outputChannel.appendLine(`[DEBUG] Found suspicious variable name: ${targetName}`);
            
            const value = node.value.value;
            if (typeof value === 'string' && value.length >= 16) {
              console.log(`[DEBUG] Found potential hardcoded secret in ${targetName}`);
              this.outputChannel.appendLine(`[DEBUG] Found potential hardcoded secret in ${targetName}`);
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
    console.log('[DEBUG] Creating insecure file permissions rule');
    this.outputChannel.appendLine('[DEBUG] Creating insecure file permissions rule');
    
    return {
      id: 'py-insecure-permissions-1',
      name: 'Insecure File Permissions',
      description: 'Overly permissive file permissions',
      severity: Severity.MEDIUM,
      type: VulnerabilityType.INSECURE_PERMISSIONS,
      languages: ['python'],
      enabled: true,
      checker: (node: any, context: ASTScanContext): ASTVulnerabilityMatch | null => {
        console.log(`[DEBUG] Checking insecure file permissions rule for node type: ${node.type}`);
        this.outputChannel.appendLine(`[DEBUG] Checking insecure file permissions rule for node type: ${node.type}`);
        
        if (node.type === 'Call' && this.getFunctionName(node) === 'chmod') {
          console.log('[DEBUG] Found chmod call');
          this.outputChannel.appendLine('[DEBUG] Found chmod call');
          
          const mode = node.args[1]?.value;
          if (mode && (mode & 0o777) > 0o600) {
            console.log(`[DEBUG] Found overly permissive file mode: ${mode.toString(8)}`);
            this.outputChannel.appendLine(`[DEBUG] Found overly permissive file mode: ${mode.toString(8)}`);
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
    console.log('[DEBUG] Creating insecure direct object reference rule');
    this.outputChannel.appendLine('[DEBUG] Creating insecure direct object reference rule');
    
    return {
      id: 'py-idor-1',
      name: 'Insecure Direct Object Reference',
      description: 'Potential IDOR vulnerability in route handler',
      severity: Severity.HIGH,
      type: VulnerabilityType.INSECURE_DIRECT_OBJECT_REFERENCE,
      languages: ['python'],
      enabled: true,
      checker: (node: any, context: ASTScanContext): ASTVulnerabilityMatch | null => {
        console.log(`[DEBUG] Checking IDOR rule for node type: ${node.type}`);
        this.outputChannel.appendLine(`[DEBUG] Checking IDOR rule for node type: ${node.type}`);
        
        if (node.type === 'FunctionDef' && 
            node.decorator_list?.some((d: any) => 
              d.func?.attr === 'route' || d.func?.id?.name === 'route')) {
          console.log(`[DEBUG] Found route handler: ${node.name}`);
          this.outputChannel.appendLine(`[DEBUG] Found route handler: ${node.name}`);
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
    if (node.func?.value?.id?.name) {
      return node.func.value.id.name;
    }
    if (node.func?.value?.attr) {
      return node.func.value.attr;
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
    
    if (node.type === 'BinOp') {
      return this.containsVariableExpression(node.left) || 
             this.containsVariableExpression(node.right);
    }
    
    if (node.type === 'Attribute') {
      return this.containsVariableExpression(node.value);
    }
    
    return false;
  }
} 
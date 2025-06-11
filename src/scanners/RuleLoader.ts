import * as fs from 'fs';
import * as path from 'path';
import * as yaml from 'js-yaml';
import { ASTScanRule, Severity, VulnerabilityType } from '../types';

interface YAMLRule {
  id: string;
  patterns: { pattern: string }[];
  message: string;
  languages: string[];
  severity: string;
  metadata?: {
    category?: string;
    description?: string;
    references?: string[];
    cwe?: string;
  };
}

interface YAMLRuleFile {
  rules: YAMLRule[];
}

interface PatternMatch {
  matched: boolean;
  metavars: Map<string, any>;
}

export class RuleLoader {
  private rules: Map<string, ASTScanRule> = new Map();

  constructor() {
    this.loadRules();
  }

  private loadRules(): void {
    const rulesDir = path.join(__dirname, '../../rules');
    this.loadRulesFromDirectory(rulesDir);
  }

  private loadRulesFromDirectory(dir: string): void {
    const files = fs.readdirSync(dir);
    
    for (const file of files) {
      const filePath = path.join(dir, file);
      const stat = fs.statSync(filePath);
      
      if (stat.isDirectory()) {
        this.loadRulesFromDirectory(filePath);
      } else if (file.endsWith('.yaml') || file.endsWith('.yml')) {
        this.loadRulesFromFile(filePath);
      }
    }
  }

  private loadRulesFromFile(filePath: string): void {
    try {
      const fileContent = fs.readFileSync(filePath, 'utf8');
      const ruleFile = yaml.load(fileContent) as YAMLRuleFile;
      
      if (ruleFile && ruleFile.rules) {
        for (const rule of ruleFile.rules) {
          this.convertAndAddRule(rule);
        }
      }
    } catch (error) {
      console.error(`Error loading rules from ${filePath}:`, error);
    }
  }

  private convertAndAddRule(yamlRule: YAMLRule): void {
    const astRule: ASTScanRule = {
      id: yamlRule.id,
      name: yamlRule.id,
      description: yamlRule.metadata?.description || yamlRule.message,
      severity: this.convertSeverity(yamlRule.severity),
      type: this.determineVulnerabilityType(yamlRule),
      languages: yamlRule.languages,
      enabled: true,
      checker: this.createPatternChecker(yamlRule)
    };

    this.rules.set(yamlRule.id, astRule);
  }

  private convertSeverity(severity: string): Severity {
    const severityMap: Record<string, Severity> = {
      'ERROR': Severity.CRITICAL,
      'WARNING': Severity.HIGH,
      'INFO': Severity.MEDIUM
    };
    return severityMap[severity] || Severity.MEDIUM;
  }

  private determineVulnerabilityType(rule: YAMLRule): VulnerabilityType {
    const typeMap: Record<string, VulnerabilityType> = {
      'no-auth-over-http': VulnerabilityType.INSECURE_COMMUNICATION,
      'sql-injection-string-format': VulnerabilityType.SQL_INJECTION,
      'command-injection-shell': VulnerabilityType.COMMAND_INJECTION
    };
    return typeMap[rule.id] || VulnerabilityType.GENERIC;
  }

  private createPatternChecker(rule: YAMLRule): (node: any, context: any) => any {
    return (node: any, context: any) => {
      for (const pattern of rule.patterns) {
        const match = this.matchesPattern(node, pattern.pattern, context);
        if (match.matched) {
          return {
            node,
            message: this.interpolateMessage(rule.message, match.metavars),
            additionalInfo: {
              ruleId: rule.id,
              cwe: rule.metadata?.cwe,
              metavars: Object.fromEntries(match.metavars)
            }
          };
        }
      }
      return null;
    };
  }

  private matchesPattern(node: any, pattern: string, context: any): PatternMatch {
    const metavars = new Map<string, any>();
    
    // Parse the pattern into a tree structure
    const patternTree = this.parsePattern(pattern);
    
    // Match the pattern against the AST node
    const matched = this.matchNode(node, patternTree, metavars, context);
    
    return {
      matched,
      metavars
    };
  }

  private parsePattern(pattern: string): any {
    // Remove any leading/trailing whitespace and newlines
    pattern = pattern.trim();
    
    // Handle function calls
    if (pattern.includes('(')) {
      const [funcPart, argsPart] = pattern.split('(');
      const funcName = funcPart.trim();
      const args = argsPart.slice(0, -1).split(',').map(arg => arg.trim());
      
      return {
        type: 'Call',
        func: this.parsePattern(funcName),
        args: args.map(arg => this.parsePattern(arg))
      };
    }
    
    // Handle attribute access (e.g., requests.get)
    if (pattern.includes('.')) {
      const [obj, attr] = pattern.split('.');
      return {
        type: 'MemberExpression',
        object: this.parsePattern(obj),
        property: this.parsePattern(attr)
      };
    }
    
    // Handle metavariables (e.g., $FUNC, $URL)
    if (pattern.startsWith('$')) {
      return {
        type: 'MetaVar',
        name: pattern
      };
    }
    
    // Handle string literals
    if (pattern.startsWith('"') || pattern.startsWith("'")) {
      return {
        type: 'StringLiteral',
        value: pattern.slice(1, -1)
      };
    }
    
    // Handle identifiers
    return {
      type: 'Identifier',
      name: pattern
    };
  }

  private matchNode(node: any, pattern: any, metavars: Map<string, any>, context: any): boolean {
    // Handle metavariables
    if (pattern.type === 'MetaVar') {
      const varName = pattern.name;
      if (!metavars.has(varName)) {
        metavars.set(varName, node);
        return true;
      }
      return this.areNodesEqual(node, metavars.get(varName));
    }
    
    // Handle function calls
    if (pattern.type === 'Call') {
      if (node.type !== 'CallExpression') return false;
      
      const funcMatch = this.matchNode(node.callee, pattern.func, metavars, context);
      if (!funcMatch) return false;
      
      if (pattern.args.length !== node.arguments.length) return false;
      
      return pattern.args.every((argPattern: any, index: number) => 
        this.matchNode(node.arguments[index], argPattern, metavars, context)
      );
    }
    
    // Handle member expressions
    if (pattern.type === 'MemberExpression') {
      if (node.type !== 'MemberExpression') return false;
      
      const objMatch = this.matchNode(node.object, pattern.object, metavars, context);
      if (!objMatch) return false;
      
      return this.matchNode(node.property, pattern.property, metavars, context);
    }
    
    // Handle string literals
    if (pattern.type === 'StringLiteral') {
      if (node.type !== 'StringLiteral') return false;
      return node.value === pattern.value;
    }
    
    // Handle identifiers
    if (pattern.type === 'Identifier') {
      if (node.type !== 'Identifier') return false;
      return node.name === pattern.name;
    }
    
    return false;
  }

  private areNodesEqual(node1: any, node2: any): boolean {
    if (node1.type !== node2.type) return false;
    
    switch (node1.type) {
      case 'Identifier':
        return node1.name === node2.name;
      case 'StringLiteral':
        return node1.value === node2.value;
      case 'CallExpression':
        return this.areNodesEqual(node1.callee, node2.callee) &&
               node1.arguments.length === node2.arguments.length &&
               node1.arguments.every((arg: any, i: number) => 
                 this.areNodesEqual(arg, node2.arguments[i])
               );
      case 'MemberExpression':
        return this.areNodesEqual(node1.object, node2.object) &&
               this.areNodesEqual(node1.property, node2.property);
      default:
        return false;
    }
  }

  private interpolateMessage(message: string, metavars: Map<string, any>): string {
    let result = message;
    metavars.forEach((value, key) => {
      const varName = key.slice(1); // Remove the $ prefix
      result = result.replace(new RegExp(`\\$${varName}`, 'g'), this.getNodeText(value));
    });
    return result;
  }

  private getNodeText(node: any): string {
    if (!node) return '';
    
    switch (node.type) {
      case 'Identifier':
        return node.name;
      case 'StringLiteral':
        return node.value;
      case 'CallExpression':
        return `${this.getNodeText(node.callee)}(${node.arguments.map(this.getNodeText).join(', ')})`;
      case 'MemberExpression':
        return `${this.getNodeText(node.object)}.${this.getNodeText(node.property)}`;
      default:
        return '';
    }
  }

  public getRules(): ASTScanRule[] {
    return Array.from(this.rules.values());
  }

  public getRule(id: string): ASTScanRule | undefined {
    return this.rules.get(id);
  }
} 
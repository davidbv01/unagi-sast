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
    // Map rule IDs to vulnerability types
    const typeMap: Record<string, VulnerabilityType> = {
      'no-auth-over-http': VulnerabilityType.INSECURE_COMMUNICATION,
      'sql-injection-string-format': VulnerabilityType.SQL_INJECTION,
      'command-injection-shell': VulnerabilityType.COMMAND_INJECTION
    };
    return typeMap[rule.id] || VulnerabilityType.GENERIC;
  }

  private createPatternChecker(rule: YAMLRule): (node: any, context: any) => any {
    return (node: any, context: any) => {
      // Convert YAML patterns to AST pattern matching logic
      // This is a simplified version - you'll need to implement proper pattern matching
      for (const pattern of rule.patterns) {
        if (this.matchesPattern(node, pattern.pattern, context)) {
          return {
            node,
            message: rule.message,
            additionalInfo: {
              ruleId: rule.id,
              cwe: rule.metadata?.cwe
            }
          };
        }
      }
      return null;
    };
  }

  private matchesPattern(node: any, pattern: string, context: any): boolean {
    // Implement pattern matching logic here
    // This is a placeholder - you'll need to implement proper pattern matching
    // based on your AST structure and the pattern syntax
    return false;
  }

  public getRules(): ASTScanRule[] {
    return Array.from(this.rules.values());
  }

  public getRule(id: string): ASTScanRule | undefined {
    return this.rules.get(id);
  }
} 
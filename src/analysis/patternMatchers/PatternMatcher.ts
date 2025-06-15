import { Vulnerability, VulnerabilityType, Severity } from '../../types';
import { RuleLoader, Rule } from '../rules/RuleLoader';
import * as path from 'path';

interface PatternRule extends Rule {
  patterns: {
    id: string;
    pattern: string;
    message: string;
    recommendation: string;
  }[];
}

export class PatternMatcher extends RuleLoader {
  constructor() {
    super(path.join(__dirname, '../rules/patterns'));
    this.loadRules();
  }

  public findPatterns(content: string, file: string): Vulnerability[] {
    const vulnerabilities: Vulnerability[] = [];

    for (const rule of this.getAllRules() as PatternRule[]) {
      for (const pattern of rule.patterns) {
        const regex = new RegExp(pattern.pattern, 'gi');
        let match;

        while ((match = regex.exec(content)) !== null) {
          const lineNumber = this.getLineNumber(content, match.index);
          const columnNumber = this.getColumnNumber(content, match.index);

          vulnerabilities.push({
            id: `${pattern.id}-${lineNumber}`,
            type: rule.type as VulnerabilityType,
            severity: rule.severity as Severity,
            message: pattern.message,
            file,
            line: lineNumber,
            column: columnNumber,
            rule: pattern.id,
            description: rule.description,
            recommendation: pattern.recommendation
          });
        }
      }
    }

    return vulnerabilities;
  }

  private getLineNumber(content: string, index: number): number {
    return content.substring(0, index).split('\n').length;
  }

  private getColumnNumber(content: string, index: number): number {
    const lines = content.substring(0, index).split('\n');
    const lastLine = lines[lines.length - 1];
    return lastLine.length + 1;
  }

  public getAllPatterns(): PatternRule[] {
    return this.getAllRules() as PatternRule[];
  }

  public addPattern(pattern: PatternRule): void {
    this.addRule(pattern);
  }

  public removePattern(patternId: string): void {
    this.removeRule(patternId);
  }
} 
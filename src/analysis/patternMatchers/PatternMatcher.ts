import { Vulnerability, VulnerabilityType, Severity } from '../../types';
import { Rule, RuleLoader } from '../rules/RuleLoader';

export interface Pattern {
  id: string;
  pattern: string;
  message: string;
  recommendation: string;
  severity?: string;
}

export interface PatternRule extends Rule {
  patterns: Pattern[];
}

export class PatternMatcher extends RuleLoader {
  constructor() {
    super('patterns');
  }

  public matchPatterns(content: string): Vulnerability[] {
    const vulnerabilities: Vulnerability[] = [];
    const rules = this.getAllRules();

    for (const rule of rules) {
      const patternRule = rule as PatternRule;
      if (!patternRule.patterns) continue;

      for (const pattern of patternRule.patterns) {
        const regex = new RegExp(pattern.pattern, 'g');
        let match;

        while ((match = regex.exec(content)) !== null) {
          const lineNumber = this.getLineNumber(content, match.index);
          const column = this.getColumn(content, match.index);

          vulnerabilities.push({
            id: `${patternRule.id}-${pattern.id}-${lineNumber}`,
            type: patternRule.type as VulnerabilityType,
            severity: (pattern.severity || patternRule.severity) as Severity,
            message: pattern.message,
            file: '', // This should be set by the caller
            line: lineNumber,
            column: column,
            rule: patternRule.id,
            description: pattern.message,
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

  private getColumn(content: string, index: number): number {
    const lastNewline = content.substring(0, index).lastIndexOf('\n');
    return index - lastNewline;
  }

  public getAllPatternRules(): PatternRule[] {
    return this.getAllRules() as PatternRule[];
  }

  public addPatternRule(pattern: PatternRule): void {
    this.addRule(pattern);
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
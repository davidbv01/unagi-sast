import { PatternVulnerability, VulnerabilityType, Severity, PatternRule } from '../../types';
import { RuleLoader } from '../rules/RuleLoader';

/**
 * Matches code patterns against loaded pattern rules to detect vulnerabilities.
 */
export class PatternMatcher {
  private readonly ruleLoader: RuleLoader;

  /**
   * Creates a new PatternMatcher instance.
   */
  constructor() {
    this.ruleLoader = RuleLoader.getInstance('patterns');
  }

  /**
   * Matches all loaded pattern rules against the given content.
   * @param content The file content to scan.
   * @returns Array of detected vulnerabilities.
   */
  public matchPatterns(content: string, filePath: string): PatternVulnerability[] {
    const vulnerabilities: PatternVulnerability[] = [];
    const rules = this.ruleLoader.getAllRules();

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
            filePath: filePath,
            line: lineNumber,
            column: column,
            isVulnerable: true,
            rule: patternRule.id,
            description: pattern.message,
            recommendation: pattern.recommendation
          });
        }
      }
    }

    return vulnerabilities;
  }

  /**
   * Gets the line number for a given index in the content.
   * @param content The file content.
   * @param index The character index.
   * @returns The line number (1-based).
   */
  private getLineNumber(content: string, index: number): number {
    return content.substring(0, index).split('\n').length;
  }

  /**
   * Gets the column number for a given index in the content.
   * @param content The file content.
   * @param index The character index.
   * @returns The column number (1-based).
   */
  private getColumn(content: string, index: number): number {
    const lastNewline = content.substring(0, index).lastIndexOf('\n');
    return index - lastNewline;
  }

  /**
   * Gets all loaded pattern rules.
   * @returns Array of PatternRule objects.
   */
  public getAllPatternRules(): PatternRule[] {
    return this.ruleLoader.getAllRules() as PatternRule[];
  }

  /**
   * Adds a new pattern rule.
   * @param pattern The PatternRule to add.
   */
  public addPatternRule(pattern: PatternRule): void {
    this.ruleLoader.addRule(pattern);
  }

  /**
   * Gets all loaded pattern rules (alias for getAllPatternRules).
   * @returns Array of PatternRule objects.
   */
  public getAllPatterns(): PatternRule[] {
    return this.ruleLoader.getAllRules() as PatternRule[];
  }

  /**
   * Adds a new pattern rule (alias for addPatternRule).
   * @param pattern The PatternRule to add.
   */
  public addPattern(pattern: PatternRule): void {
    this.ruleLoader.addRule(pattern);
  }

  /**
   * Removes a pattern rule by its ID.
   * @param patternId The ID of the pattern rule to remove.
   */
  public removePattern(patternId: string): void {
    this.ruleLoader.removeRule(patternId);
  }

  /**
   * Reloads all pattern rules from the rules directory.
   */
  public reloadRules(): void {
    this.ruleLoader.reloadRules();
  }
} 
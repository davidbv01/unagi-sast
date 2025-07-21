import { RuleLoader } from '../rules/RuleLoader';
import { DetectorUtils } from './detectorUtils';
import { AstNode, Sanitizer, SanitizerRule } from '../../types';

/**
 * Detects sanitizer nodes in an AST using loaded sanitizer rules.
 */
export class SanitizerDetector {
  private readonly ruleLoader: RuleLoader;

  /**
   * Creates a new SanitizerDetector instance.
   */
  constructor() {
    this.ruleLoader = RuleLoader.getInstance('sanitizers');
  }

  /**
   * Detects if the given AST node is a sanitizer according to loaded rules.
   * @param node The AST node to check.
   * @param varName The variable name (optional).
   * @returns The detected Sanitizer object, or null if not detected.
   */
  public detectSanitizer(node: AstNode, varName: string = ""): Sanitizer | null {
    if (node.type === 'call') {
      const rules = this.ruleLoader.getAllRules() as SanitizerRule[];
      const sanitizers = DetectorUtils.getAllItems(rules, 'sanitizers', node.filePath || '');
      const detectedItem = DetectorUtils.detectItem(node, sanitizers);
      const key = DetectorUtils.createKey(node.scope, varName);
      if (detectedItem) {
        return {
          ...detectedItem,
          loc: {
            start: { line: node.loc?.start?.line || 1, column: node.loc?.start?.column || 0 },
            end: { line: node.loc?.end?.line || node.loc?.start?.line || 1, column: node.loc?.end?.column || (node.loc?.start?.column || 0) + 10 }
          },
          effectiveness: this.getEffectivenessForSanitizer(detectedItem.id, rules),
          key: key,
          info: node.text
        };
      }
    }
    return null;
  }

  /**
   * Gets the effectiveness for a sanitizer by its ID from the loaded rules.
   * @param sanitizerId The sanitizer ID.
   * @param rules The loaded sanitizer rules.
   * @returns The effectiveness value (0-1).
   */
  private getEffectivenessForSanitizer(sanitizerId: string, rules: SanitizerRule[]): number {
    for (const rule of rules) {
      const sanitizer = rule.sanitizers.find(s => s.id === sanitizerId);
      if (sanitizer) {
        return (sanitizer as any).effectiveness || 0.5; // Default to 0.5 if not specified
      }
    }
    return 0.5; // Default effectiveness
  }

  /**
   * Calculates the combined effectiveness of multiple sanitizers.
   * @param sanitizers Array of Sanitizer objects.
   * @returns The combined effectiveness value (0-1).
   */
  public calculateSanitizationEffectiveness(sanitizers: Sanitizer[]): number {
    if (sanitizers.length === 0) { return 0; }
    // 1 - (1 - e1) * (1 - e2) * ... * (1 - en)
    return 1 - sanitizers.reduce(
      (acc, sanitizer) => acc * (1 - sanitizer.effectiveness),
      1
    );
  }

  /**
   * Reloads all sanitizer rules from the rules directory.
   */
  public reloadRules(): void {
    this.ruleLoader.reloadRules();
  }

  /**
   * Gets all sanitizers from all loaded sanitizer rules.
   * @returns Array of Sanitizer objects with effectiveness.
   */
  public getAllSanitizers(): Sanitizer[] {
    const rules = this.ruleLoader.getAllRules() as SanitizerRule[];
    const sanitizers = DetectorUtils.getAllItems(rules, 'sanitizers', '');
    return sanitizers.map(sanitizer => ({
      ...sanitizer,
      effectiveness: this.getEffectivenessForSanitizer(sanitizer.id, rules),
      info: '',
    }));
  }
} 
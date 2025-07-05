import { RuleLoader } from '../rules/RuleLoader';
import { DetectorUtils } from './detectorUtils';
import { AstNode, Sanitizer, BaseDetectorItem, BaseRule } from '../../types';

interface SanitizerRule extends BaseRule {
  sanitizers: BaseDetectorItem[];
}

export class SanitizerDetector {
  private ruleLoader: RuleLoader;
  constructor() {
    this.ruleLoader = RuleLoader.getInstance('sanitizers');
  }

  public detectSanitizer(node: AstNode, varName: String = ""): Sanitizer | null {
    if (node.type === 'call') {
      const rules = this.ruleLoader.getAllRules() as SanitizerRule[];
      const sanitizers = DetectorUtils.getAllItems(rules, 'sanitizers', node.filePath || '');
      const detectedItem = DetectorUtils.detectItem(node, sanitizers);
      const key = DetectorUtils.createKey(node.scope,varName);
      
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

  private getEffectivenessForSanitizer(sanitizerId: string, rules: SanitizerRule[]): number {
    for (const rule of rules) {
      const sanitizer = rule.sanitizers.find(s => s.id === sanitizerId);
      if (sanitizer) {
        return (sanitizer as any).effectiveness || 0.5; // Default to 0.5 if not specified
      }
    }
    return 0.5; // Default effectiveness
  }

  public calculateSanitizationEffectiveness(sanitizers: Sanitizer[]): number {
    if (sanitizers.length === 0) return 0;
    
    // Calculate combined effectiveness using the formula:
    // 1 - (1 - e1) * (1 - e2) * ... * (1 - en)
    // where e1, e2, ..., en are individual effectiveness values
    return 1 - sanitizers.reduce(
      (acc, sanitizer) => acc * (1 - sanitizer.effectiveness),
      1
    );
  }

  public reloadRules(): void {
    this.ruleLoader.reloadRules();
  }

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
import { RuleLoader, Rule } from '../rules/RuleLoader';
import { DetectorUtils, BaseDetectorItem, BaseRule } from './detectorUtils';
import * as path from 'path';

interface SanitizerRule extends BaseRule {
  sanitizers: BaseDetectorItem[];
}

export interface Sanitizer extends BaseDetectorItem {
  effectiveness: number;
}

export class SanitizerDetector extends RuleLoader {
  constructor() {
    super('sanitizers');
  }

  public detectSanitizer(node: any, content: string): Sanitizer | null {
    const rules = this.getAllRules() as SanitizerRule[];
    const sanitizers = DetectorUtils.getAllItems(rules, 'sanitizers');
    const detectedItem = DetectorUtils.detectItem(node, content, sanitizers);
    
    if (detectedItem) {
      return {
        ...detectedItem,
        effectiveness: this.getEffectivenessForSanitizer(detectedItem.id, rules)
      };
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

  public getAllSanitizers(): Sanitizer[] {
    const rules = this.getAllRules() as SanitizerRule[];
    const sanitizers = DetectorUtils.getAllItems(rules, 'sanitizers');
    return sanitizers.map(sanitizer => ({
      ...sanitizer,
      effectiveness: this.getEffectivenessForSanitizer(sanitizer.id, rules)
    }));
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
} 
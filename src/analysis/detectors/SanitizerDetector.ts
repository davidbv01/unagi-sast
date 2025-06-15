import { RuleLoader, Rule } from '../rules/RuleLoader';
import * as path from 'path';

interface SanitizerRule extends Rule {
  sanitizers: {
    id: string;
    pattern: string;
    message: string;
    description: string;
    effectiveness: number;
  }[];
}

export interface Sanitizer {
  id: string;
  type: string;
  pattern: string;
  description: string;
  effectiveness: number; // 0-1 scale of how effective the sanitization is
}

export class SanitizerDetector extends RuleLoader {
  constructor() {
    super('sanitizers');
    this.loadRules();
  }

  public detectSanitizer(node: any, content: string): Sanitizer | null {
    for (const rule of this.getAllRules() as SanitizerRule[]) {
      for (const sanitizer of rule.sanitizers) {
        const regex = new RegExp(sanitizer.pattern);
        const nodeText = this.getNodeText(node, content);
        
        if (regex.test(nodeText)) {
          return {
            id: sanitizer.id,
            type: rule.type,
            pattern: sanitizer.pattern,
            description: sanitizer.description,
            effectiveness: sanitizer.effectiveness
          };
        }
      }
    }
    return null;
  }

  private getNodeText(node: any, content: string): string {
    if (!node || !node.loc) return '';
    const start = node.loc.start.offset;
    const end = node.loc.end.offset;
    return content.substring(start, end);
  }

  public getAllSanitizers(): Sanitizer[] {
    const sanitizers: Sanitizer[] = [];
    for (const rule of this.getAllRules() as SanitizerRule[]) {
      for (const sanitizer of rule.sanitizers) {
        sanitizers.push({
          id: sanitizer.id,
          type: rule.type,
          pattern: sanitizer.pattern,
          description: sanitizer.description,
          effectiveness: sanitizer.effectiveness
        });
      }
    }
    return sanitizers;
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
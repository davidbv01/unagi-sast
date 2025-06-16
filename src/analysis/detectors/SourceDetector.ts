import { RuleLoader } from '../rules/RuleLoader';
import { DetectorUtils, BaseDetectorItem, BaseRule } from './detectorUtils';

interface SourceRule extends BaseRule {
  sources: BaseDetectorItem[];
}

export interface Source extends BaseDetectorItem {
  severity: string;
}

export class SourceDetector extends RuleLoader {
  constructor() {
    super('sources');
  }

  public detectSource(node: any): Source | null {
    if (node.type === 'call' || node.type === 'expression_statement') {
      const rules = this.getAllRules() as SourceRule[];
      const sources = DetectorUtils.getAllItems(rules, 'sources');
      const detectedItem = DetectorUtils.detectItem(node, sources);
    
    
      if (detectedItem) {
        return {
          ...detectedItem,
          severity: this.getSeverityForSource(detectedItem.id, rules)
        };
      }
    }
    return null;
  }

  private getSeverityForSource(sourceId: string, rules: SourceRule[]): string {
    for (const rule of rules) {
      const source = rule.sources.find(s => s.id === sourceId);
      if (source) {
        return rule.severity;
      }
    }
    return 'medium'; // Default severity
  }

  public getAllSources(): Source[] {
    const rules = this.getAllRules() as SourceRule[];
    const sources = DetectorUtils.getAllItems(rules, 'sources');
    return sources.map(source => ({
      ...source,
      severity: this.getSeverityForSource(source.id, rules)
    }));
  }
} 
import { RuleLoader } from '../rules/RuleLoader';
import { DetectorUtils, BaseDetectorItem, BaseRule } from './detectorUtils';
import { AstNode } from '../../types';

interface SourceRule extends BaseRule {
  sources: BaseDetectorItem[];
}

export interface Source extends BaseDetectorItem {
  severity: string;
  key?: string;
}

export class SourceDetector extends RuleLoader {
  constructor() {
    super('sources');
  }

  public detectSource(node: AstNode, varName: String = ""): Source | null {
    if (node.type === 'call' || node.type === 'expression_statement' || node.type == 'return_statement') {
      const rules = this.getAllRules() as SourceRule[];
      const sources = DetectorUtils.getAllItems(rules, 'sources');
      const detectedItem = DetectorUtils.detectItem(node, sources);
      const key = DetectorUtils.createKey(node.scope,varName)

      if (detectedItem) {
        return {
          ...detectedItem,
          loc: {
            start: { line: node.loc?.start?.line || 1, column: node.loc?.start?.column || 0 },
            end: { line: node.loc?.end?.line || node.loc?.start?.line || 1, column: node.loc?.end?.column || (node.loc?.start?.column || 0) + 10 }
          },
          severity: this.getSeverityForSource(detectedItem.id, rules),
          key:  key
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
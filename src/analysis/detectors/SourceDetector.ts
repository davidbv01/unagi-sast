import { RuleLoader } from '../rules/RuleLoader';
import { DetectorUtils } from './detectorUtils';
import { AstNode, Source, Severity, SourceRule } from '../../types';

export class SourceDetector {
  private ruleLoader: RuleLoader;
  constructor() {
    this.ruleLoader = RuleLoader.getInstance('sources');
  }

  public detectSource(node: AstNode, varName: String = ""): Source | null {
    if (node.type === 'call' || node.type === 'expression_statement' || node.type == 'return_statement') {
      const rules = this.ruleLoader.getAllRules() as SourceRule[];
      const sources = DetectorUtils.getAllItems(rules, 'sources', node.filePath || '');
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

  private getSeverityForSource(sourceId: string, rules: SourceRule[]): Severity {
    for (const rule of rules) {
      const source = rule.sources.find(s => s.id === sourceId);
      if (source) {
        return rule.severity as Severity;
      }
    }
    return Severity.MEDIUM;
  }

  public getAllSources(): Source[] {
    const rules = this.ruleLoader.getAllRules() as SourceRule[];
    const sources = DetectorUtils.getAllItems(rules, 'sources', '');
    return sources.map(source => ({
      ...source,
      severity: this.getSeverityForSource(source.id, rules)
    }));
  }

  public reloadRules(): void {
    this.ruleLoader.reloadRules();
  }
} 
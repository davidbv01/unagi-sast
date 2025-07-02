import { VulnerabilityType, Severity } from '../../types';
import { RuleLoader } from '../rules/RuleLoader';
import { DetectorUtils, BaseDetectorItem, BaseRule } from './detectorUtils';
import { AstNode } from '../../types';

interface SinkRule extends BaseRule {
  sinks: BaseDetectorItem[];
}

export interface Sink extends BaseDetectorItem {
  info: string;
  vulnerabilityType: VulnerabilityType;
  severity: Severity;
  key?: string;
}

export class SinkDetector extends RuleLoader {
  constructor() {
    super('sinks');
  }

  public detectSink(node: AstNode, varName: String = ""): Sink | null {
    if (node.type === 'call') {
      const rules = this.getAllRules() as SinkRule[];
      const sinks = DetectorUtils.getAllItems(rules, 'sinks');
      const detectedItem = DetectorUtils.detectItem(node, sinks);
      const key = DetectorUtils.createKey(node.scope, varName);
      
      if (detectedItem) {
        return {
          ...detectedItem,
          loc: {
            start: { line: node.loc?.start?.line || 1, column: node.loc?.start?.column || 0 },
            end: { line: node.loc?.end?.line || node.loc?.start?.line || 1, column: node.loc?.end?.column || (node.loc?.start?.column || 0) + 10 }
          },
          vulnerabilityType: this.getVulnerabilityTypeForSink(detectedItem.id, rules),
          severity: this.getSeverityForSink(detectedItem.id, rules),
          info: node.text,
          key: key
        };
      }
    }
    return null;
  }

  private getVulnerabilityTypeForSink(sinkId: string, rules: SinkRule[]): VulnerabilityType {
    for (const rule of rules) {
      const sink = rule.sinks.find(s => s.id === sinkId);
      if (sink) {
        return rule.type as VulnerabilityType;
      }
    }
    return VulnerabilityType.GENERIC;
  }

  private getSeverityForSink(sinkId: string, rules: SinkRule[]): Severity {
    for (const rule of rules) {
      const sink = rule.sinks.find(s => s.id === sinkId);
      if (sink) {
        return rule.severity as Severity;
      }
    }
    return Severity.MEDIUM;
  }
} 
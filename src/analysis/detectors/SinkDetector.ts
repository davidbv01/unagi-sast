import { VulnerabilityType, Severity } from '../../types';
import { RuleLoader } from '../rules/RuleLoader';
import { DetectorUtils, BaseDetectorItem, BaseRule } from './detectorUtils';

interface SinkRule extends BaseRule {
  sinks: BaseDetectorItem[];
}

export interface Sink extends BaseDetectorItem {
  info: string;
  vulnerabilityType: VulnerabilityType;
  severity: Severity;
}

export class SinkDetector extends RuleLoader {
  constructor() {
    super('sinks');
  }

  public detectSink(node: any): Sink | null {
    if (node.type === 'call') {
      const rules = this.getAllRules() as SinkRule[];
      const sinks = DetectorUtils.getAllItems(rules, 'sinks');
      const detectedItem = DetectorUtils.detectItem(node, sinks);
      
      if (detectedItem) {
        return {
          ...detectedItem,
          loc: {
            start: { line: node.loc?.start?.line || 1, column: node.loc?.start?.column || 0 },
            end: { line: node.loc?.end?.line || node.loc?.start?.line || 1, column: node.loc?.end?.column || (node.loc?.start?.column || 0) + 10 }
          },
          vulnerabilityType: this.getVulnerabilityTypeForSink(detectedItem.id, rules),
          severity: this.getSeverityForSink(detectedItem.id, rules),
          info: node.text
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
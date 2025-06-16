import { VulnerabilityType, Severity } from '../../types';
import { RuleLoader } from '../rules/RuleLoader';
import { DetectorUtils, BaseDetectorItem, BaseRule } from './detectorUtils';

interface SinkRule extends BaseRule {
  sinks: BaseDetectorItem[];
}

export interface Sink extends BaseDetectorItem {
  vulnerabilityType: VulnerabilityType;
  severity: Severity;
}

export class SinkDetector extends RuleLoader {
  constructor() {
    super('sinks');
  }

  public detectSink(node: any, content: string): Sink | null {
    if (node.type === 'call' || node.type === 'expression_statement') {
      const rules = this.getAllRules() as SinkRule[];
      const sinks = DetectorUtils.getAllItems(rules, 'sinks');
      const detectedItem = DetectorUtils.detectItem(node, content, sinks);
      
      if (detectedItem) {
        return {
          ...detectedItem,
          vulnerabilityType: this.getVulnerabilityTypeForSink(detectedItem.id, rules),
          severity: this.getSeverityForSink(detectedItem.id, rules)
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

  public getAllSinks(): Sink[] {
    const rules = this.getAllRules() as SinkRule[];
    const sinks = DetectorUtils.getAllItems(rules, 'sinks');
    return sinks.map(sink => ({
      ...sink,
      vulnerabilityType: this.getVulnerabilityTypeForSink(sink.id, rules),
      severity: this.getSeverityForSink(sink.id, rules)
    }));
  }
} 
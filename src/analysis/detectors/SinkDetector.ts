import { VulnerabilityType, Severity } from '../../types';
import { RuleLoader, Rule } from '../rules/RuleLoader';
import * as path from 'path';

interface SinkRule extends Rule {
  sinks: {
    id: string;
    pattern: string;
    message: string;
    description: string;
    vulnerabilityType: string;
    severity: string;
  }[];
}

export interface Sink {
  id: string;
  type: string;
  pattern: string;
  description: string;
  vulnerabilityType: VulnerabilityType;
  severity: Severity;
}

export class SinkDetector extends RuleLoader {
  constructor() {
    super('sinks');
    this.loadRules();
  }

  public detectSink(node: any, content: string): Sink | null {
    for (const rule of this.getAllRules() as SinkRule[]) {
      for (const sink of rule.sinks) {
        const regex = new RegExp(sink.pattern);
        const nodeText = this.getNodeText(node, content);
        
        if (regex.test(nodeText)) {
          return {
            id: sink.id,
            type: rule.type,
            pattern: sink.pattern,
            description: sink.description,
            vulnerabilityType: sink.vulnerabilityType as VulnerabilityType,
            severity: sink.severity as Severity
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

  public getAllSinks(): Sink[] {
    const sinks: Sink[] = [];
    for (const rule of this.getAllRules() as SinkRule[]) {
      for (const sink of rule.sinks) {
        sinks.push({
          id: sink.id,
          type: rule.type,
          pattern: sink.pattern,
          description: sink.description,
          vulnerabilityType: sink.vulnerabilityType as VulnerabilityType,
          severity: sink.severity as Severity
        });
      }
    }
    return sinks;
  }
} 
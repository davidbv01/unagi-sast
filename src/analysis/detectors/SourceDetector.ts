import { RuleLoader, Rule } from '../rules/RuleLoader';
import * as path from 'path';

interface SourceRule extends Rule {
  sources: {
    id: string;
    pattern: string;
    message: string;
    description: string;
    severity: string;
  }[];
}

export interface Source {
  id: string;
  type: string;
  pattern: string;
  description: string;
  severity: string;
}

export class SourceDetector extends RuleLoader {
  constructor() {
    super('sources');
    this.loadRules();
  }

  public detectSource(node: any, content: string): Source | null {
    for (const rule of this.getAllRules() as SourceRule[]) {
      for (const source of rule.sources) {
        const regex = new RegExp(source.pattern);
        const nodeText = this.getNodeText(node, content);
        
        if (regex.test(nodeText)) {
          return {
            id: source.id,
            type: rule.type,
            pattern: source.pattern,
            description: source.description,
            severity: source.severity
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

  public getAllSources(): Source[] {
    const sources: Source[] = [];
    for (const rule of this.getAllRules() as SourceRule[]) {
      for (const source of rule.sources) {
        sources.push({
          id: source.id,
          type: rule.type,
          pattern: source.pattern,
          description: source.description,
          severity: source.severity
        });
      }
    }
    return sources;
  }
} 
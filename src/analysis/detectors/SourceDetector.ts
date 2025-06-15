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
        
        // Only check nodes that are likely to be function calls
        if (node.type === 'call' || node.type === 'Call') {
          if (regex.test(nodeText)) {
            console.log(`[DEBUG] Matched source pattern: ${source.pattern} with text: ${nodeText}`);
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
    }
    return null;
  }

  private getNodeText(node: any, content: string): string {
    if (!node || !node.loc) return '';
    
    const lines = content.split('\n');
    const startLine = node.loc.start.line - 1; // Convert to 0-based
    const endLine = node.loc.end.line - 1;     // Convert to 0-based
    const startCol = node.loc.start.column;
    const endCol = node.loc.end.column;

    // Debug logging
    console.log(`[DEBUG] Node type: ${node.type}, Line: ${startLine + 1}, Text:`, {
      startLine,
      endLine,
      startCol,
      endCol,
      nodeText: lines[startLine]?.substring(startCol, endCol)
    });

    if (startLine === endLine) {
      // Single line
      return lines[startLine]?.substring(startCol, endCol) || '';
    } else {
      // Multiple lines
      const firstLine = lines[startLine]?.substring(startCol) || '';
      const middleLines = lines.slice(startLine + 1, endLine);
      const lastLine = lines[endLine]?.substring(0, endCol) || '';
      return [firstLine, ...middleLines, lastLine].join('\n');
    }
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
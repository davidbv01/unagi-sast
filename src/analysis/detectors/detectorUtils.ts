import { Rule } from '../rules/RuleLoader';

export interface BaseDetectorItem {
  id: string;
  type: string;
  pattern: string;
  description: string;
}

export interface BaseRule extends Rule {
  sources?: BaseDetectorItem[];
  sinks?: BaseDetectorItem[];
  sanitizers?: BaseDetectorItem[];
}

/**
 * Common utility functions for source, sink, and sanitizer detection
 */
export class DetectorUtils {
  /**
   * Gets the text content of a node from the source code
   */
  public static getNodeText(node: any, content: string): string {
    if (!node || !node.loc) return '';
    
    // Split content into lines
    const lines = content.split('\n');
    
    // Get start and end positions
    const startLine = node.loc.start.line - 1; // Convert to 0-based index
    const startCol = node.loc.start.column;
    const endLine = node.loc.end.line - 1; // Convert to 0-based index
    const endCol = node.loc.end.column;
    
    // If it's a single line
    if (startLine === endLine) {
      return lines[startLine].substring(startCol, endCol);
    }
    
    // For multi-line nodes
    const firstLine = lines[startLine].substring(startCol);
    const lastLine = lines[endLine].substring(0, endCol);
    const middleLines = lines.slice(startLine + 1, endLine);
    
    return [firstLine, ...middleLines, lastLine].join('\n');
  }

  /**
   * Detects if a node matches any of the given patterns
   */
  public static detectItem(node: any, content: string, items: BaseDetectorItem[]): BaseDetectorItem | null {
    for (const item of items) {
      const regex = new RegExp(item.pattern);
      const nodeText = this.getNodeText(node, content);
      
      if (regex.test(nodeText)) {
        return item;
      }
    }
    return null;
  }

  /**
   * Gets all items of a specific type from rules
   */
  public static getAllItems(rules: BaseRule[], itemType: 'sources' | 'sinks' | 'sanitizers'): BaseDetectorItem[] {
    const items: BaseDetectorItem[] = [];
    for (const rule of rules) {
      const ruleItems = rule[itemType] || [];
      for (const item of ruleItems) {
        items.push({
          id: item.id,
          type: rule.type,
          pattern: item.pattern,
          description: item.description
        });
      }
    }
    return items;
  }
} 
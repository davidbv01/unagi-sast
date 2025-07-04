import { Rule } from '../rules/RuleLoader';

export interface BaseDetectorItem {
  id: string;
  type: string;
  pattern: string;
  description: string;
  loc:
  {
    start: { line: number, column: number },
    end: { line: number, column: number }
  }
  filePath: string;
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
   * Detects if a node matches any of the given patterns
   */
  public static detectItem(node: any, items: BaseDetectorItem[]): BaseDetectorItem | null {
    for (const item of items) {
      const regex = new RegExp(item.pattern);
      if (regex.test(node.text)) {
        return item;
      }
    }
    return null;
  }

  /**
   * Gets all items of a specific type from rules
   * @param rules The rules array
   * @param itemType The type of items to extract (sources, sinks, sanitizers)
   * @param filePath The file path to assign to each item
   */
  public static getAllItems(
    rules: BaseRule[],
    itemType: 'sources' | 'sinks' | 'sanitizers',
    filePath: string = ''
  ): BaseDetectorItem[] {
    const items: BaseDetectorItem[] = [];
    for (const rule of rules) {
      const ruleItems = rule[itemType] || [];
      for (const item of ruleItems) {
        items.push({
          id: item.id,
          type: rule.type,
          pattern: item.pattern,
          description: item.description,
          loc: {
            start: { line: 0, column: 0 },
            end: { line: 0, column: 0 }
          },
          filePath: item.filePath || filePath || ''
        });
      }
    }
    return items;
  }

  /**
   * Creates a unique key combining scope and variable name
   * @param scope The scope where the variable is defined
   * @param astId The AST node ID to look up
   * @returns Formatted key "{scope}_{variableName}" or empty string if variable not found
   */
  public static createKey(scope: String, varName: String): string {
      
      // Return empty string if variable name is undefined or empty
      if (!varName || varName.trim() === "") {
          return "";
      }
      
      return `${scope}_${varName}`;
  }
} 
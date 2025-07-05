import { BaseDetectorItem, BaseRule } from '../../types';

/**
 * Common utility functions for source, sink, and sanitizer detection.
 */
export class DetectorUtils {
  /**
   * Detects if a node matches any of the given patterns.
   * @param node The AST node or object with a 'text' property.
   * @param items The list of detector items to match against.
   * @returns The matching item, or null if none match.
   */
  public static detectItem(node: { text: string }, items: BaseDetectorItem[]): BaseDetectorItem | null {
    for (const item of items) {
      const regex = new RegExp(item.pattern);
      if (regex.test(node.text)) {
        return item;
      }
    }
    return null;
  }

  /**
   * Gets all items of a specific type from rules.
   * @param rules The rules array.
   * @param itemType The type of items to extract ('sources', 'sinks', 'sanitizers').
   * @param filePath The file path to assign to each item.
   * @returns Array of detector items with file path and info.
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
          filePath: item.filePath || filePath || '',
          info: item.info || ''
        });
      }
    }
    return items;
  }

  /**
   * Creates a unique key combining scope and variable name.
   * @param scope The scope where the variable is defined.
   * @param varName The variable name.
   * @returns Formatted key "{scope}_{variableName}" or empty string if variable not found.
   */
  public static createKey(scope: string, varName: string): string {
    if (!varName || varName.trim() === "") {
      return "";
    }
    return `${scope}_${varName}`;
  }
} 
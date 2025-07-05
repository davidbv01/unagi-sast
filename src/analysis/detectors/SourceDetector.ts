import { RuleLoader } from '../rules/RuleLoader';
import { DetectorUtils } from './detectorUtils';
import { AstNode, Source, Severity, SourceRule } from '../../types';

/**
 * Detects source nodes in an AST using loaded source rules.
 */
export class SourceDetector {
  private readonly ruleLoader: RuleLoader;

  /**
   * Creates a new SourceDetector instance.
   */
  constructor() {
    this.ruleLoader = RuleLoader.getInstance('sources');
  }

  /**
   * Detects if the given AST node is a source according to loaded rules.
   * @param node The AST node to check.
   * @param varName The variable name (optional).
   * @returns The detected Source object, or null if not detected.
   */
  public detectSource(node: AstNode, varName: string = ""): Source | null {
    if (node.type === 'call' || node.type === 'expression_statement' || node.type === 'return_statement') {
      const rules = this.ruleLoader.getAllRules() as SourceRule[];
      const sources = DetectorUtils.getAllItems(rules, 'sources', node.filePath || '');
      const detectedItem = DetectorUtils.detectItem(node, sources);
      const key = DetectorUtils.createKey(node.scope, varName);
      if (detectedItem) {
        return {
          ...detectedItem,
          loc: {
            start: { line: node.loc?.start?.line || 1, column: node.loc?.start?.column || 0 },
            end: { line: node.loc?.end?.line || node.loc?.start?.line || 1, column: node.loc?.end?.column || (node.loc?.start?.column || 0) + 10 }
          },
          severity: this.getSeverityForSource(detectedItem.id, rules),
          key: key
        };
      }
    }
    return null;
  }

  /**
   * Gets the severity for a source by its ID from the loaded rules.
   * @param sourceId The source ID.
   * @param rules The loaded source rules.
   * @returns The severity for the source.
   */
  private getSeverityForSource(sourceId: string, rules: SourceRule[]): Severity {
    for (const rule of rules) {
      const source = rule.sources.find(s => s.id === sourceId);
      if (source) {
        const sev = (typeof rule.severity === 'string' ? rule.severity.toUpperCase() : rule.severity) as Severity;
        if (Object.values(Severity).includes(sev)) {
          return sev as Severity;
        }
      }
    }
    return Severity.MEDIUM;
  }

  /**
   * Gets all sources from all loaded source rules.
   * @returns Array of Source objects with severity.
   */
  public getAllSources(): Source[] {
    const rules = this.ruleLoader.getAllRules() as SourceRule[];
    const sources = DetectorUtils.getAllItems(rules, 'sources', '');
    return sources.map(source => ({
      ...source,
      severity: this.getSeverityForSource(source.id, rules)
    }));
  }

  /**
   * Reloads all source rules from the rules directory.
   */
  public reloadRules(): void {
    this.ruleLoader.reloadRules();
  }
} 
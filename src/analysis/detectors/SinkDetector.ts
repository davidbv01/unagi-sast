import { VulnerabilityType, Severity, Sink } from '../../types';
import { RuleLoader } from '../rules/RuleLoader';
import { DetectorUtils } from './detectorUtils';
import { AstNode, SinkRule } from '../../types';

/**
 * Detects sink nodes in an AST using loaded sink rules.
 */
export class SinkDetector {
  private readonly ruleLoader: RuleLoader;

  /**
   * Creates a new SinkDetector instance.
   */
  constructor() {
    this.ruleLoader = RuleLoader.getInstance('sinks');
  }

  /**
   * Detects if the given AST node is a sink according to loaded rules.
   * @param node The AST node to check.
   * @param varName The variable name (optional).
   * @returns The detected Sink object, or null if not detected.
   */
  public detectSink(node: AstNode, varName: string = ""): Sink | null {
    if (node.type === 'call') {
      const rules = this.ruleLoader.getAllRules() as SinkRule[];
      const sinks = DetectorUtils.getAllItems(rules, 'sinks', node.filePath || '');
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

  /**
   * Gets the vulnerability type for a sink by its ID from the loaded rules.
   * @param sinkId The sink ID.
   * @param rules The loaded sink rules.
   * @returns The vulnerability type for the sink.
   */
  private getVulnerabilityTypeForSink(sinkId: string, rules: SinkRule[]): VulnerabilityType {
    for (const rule of rules) {
      const sink = rule.sinks.find(s => s.id === sinkId);
      if (sink) {
        return rule.type as VulnerabilityType;
      }
    }
    return VulnerabilityType.GENERIC;
  }

  /**
   * Gets the severity for a sink by its ID from the loaded rules.
   * @param sinkId The sink ID.
   * @param rules The loaded sink rules.
   * @returns The severity for the sink.
   */
  private getSeverityForSink(sinkId: string, rules: SinkRule[]): Severity {
    for (const rule of rules) {
      const sink = rule.sinks.find(s => s.id === sinkId);
      if (sink) {
        return rule.severity as Severity;
      }
    }
    return Severity.MEDIUM;
  }

  /**
   * Reloads all sink rules from the rules directory.
   */
  public reloadRules(): void {
    this.ruleLoader.reloadRules();
  }

  /**
   * Gets all sinks from all loaded sink rules.
   * @returns Array of Sink objects with severity and vulnerability type.
   */
  public getAllSinks(): Sink[] {
    const rules = this.ruleLoader.getAllRules() as SinkRule[];
    const sinks = DetectorUtils.getAllItems(rules, 'sinks', '');
    return sinks.map(sink => ({
      ...sink,
      severity: this.getSeverityForSink(sink.id, rules),
      vulnerabilityType: this.getVulnerabilityTypeForSink(sink.id, rules),
      info: '',
    }));
  }
} 
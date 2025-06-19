import { Vulnerability, Severity } from "../types";
import { Source } from '../analysis/detectors/SourceDetector';
import { Sink } from '../analysis/detectors/SinkDetector';
import { Sanitizer } from '../analysis/detectors/SanitizerDetector';

        

export class TaintEngine {

    /**
   * Performs taint analysis to detect vulnerabilities in data flow between sources and sinks
   */
  public performTaintAnalysis(
    sources: (Source & { id: number; loc: any })[],
    sinks: (Sink & { id: number; vulnerabilityType: string; loc: any; severity: Severity })[],
    sanitizers: (Sanitizer & { id: number })[],
    ast: any,
    file: string
  ): Vulnerability[] {
    const vulnerabilities: Vulnerability[] = [];
  
    for (const source of sources) {
      for (const sink of sinks) {
        // Ensure sink appears after source in the AST (by structural order)
        if (this.isNodeAfter(source.id, sink.id, ast)) {
          const pathNodes = this.findPathBetweenNodes(ast, source.id, sink.id);
          const pathSanitizers = sanitizers.filter(s =>
            pathNodes.some(n => n.id === s.id)
          );
  
          const isEffectivelySanitized = this.isSanitizationEffective(pathSanitizers);
  
          if (!isEffectivelySanitized) {
            vulnerabilities.push({
              id: `${source.id}->${sink.id}`,
              type: sink.vulnerabilityType,
              severity: sink.severity,
              message: `Unvalidated data from source "${source.type}" reaches sink "${sink.type}"`,
              file,
              line: sink.loc?.start?.line,
              column: sink.loc?.start?.column,
              rule: 'taint-analysis',
              description: 'Taint analysis detected an unvalidated data flow from source to sink.',
              recommendation: 'Add proper sanitization or validation between source and sink.',
              pathLines: pathNodes.map(n => n.loc?.start?.line).filter(Boolean),
              sourceId: source.id,
              sinkId: sink.id,
              sanitizerIds: pathSanitizers.map(s => s.id)
            });            
          }
        }
      }
    }
  
    return vulnerabilities;
  }

  private isNodeAfter(idA: number, idB: number, ast: any): boolean {
    const nodeOrder: number[] = [];
  
    const collectIds = (node: any) => {
      nodeOrder.push(node.id);
      for (const child of node.children || []) {
        collectIds(child);
      }
    };
  
    collectIds(ast);
  
    return nodeOrder.indexOf(idB) > nodeOrder.indexOf(idA);
  }


  private findPathBetweenNodes(ast: any, startId: number, endId: number): any[] {
    const path: any[] = [];
    let inRange = false;
  
    const walk = (node: any) => {
      if (node.id === startId) inRange = true;
      if (inRange) path.push(node);
      if (node.id === endId) inRange = false;
  
      for (const child of node.children || []) {
        walk(child);
      }
    };
  
    walk(ast);
    return path;
  }


  /**
   * Evaluates if sanitization is effective against specific vulnerability types
   */
  private isSanitizationEffective(
    sanitizers: (Sanitizer & { id: number })[]
  ): boolean {
    if (sanitizers.length === 0) return false;
    
    // Check if any sanitizer is effective for this vulnerability type
    for (const sanitizer of sanitizers) {
      // High effectiveness threshold
      if (sanitizer.effectiveness >= 0.8) return true;
      
    }
    
    // Multiple sanitizers might combine to be effective
    const totalEffectiveness = sanitizers.reduce((sum, s) => sum + s.effectiveness, 0);
    const averageEffectiveness = totalEffectiveness / sanitizers.length;
    
    if (averageEffectiveness >= 0.7) return true;
    
    return false;
  }


}
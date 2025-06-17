import { Vulnerability } from '../types';
import { PatternMatcher } from '../analysis/patternMatchers/PatternMatcher';
import { SourceDetector } from '../analysis/detectors/SourceDetector';
import { SinkDetector } from '../analysis/detectors/SinkDetector';
import { SanitizerDetector } from '../analysis/detectors/SanitizerDetector';
import { Source } from '../analysis/detectors/SourceDetector';
import { Sink } from '../analysis/detectors/SinkDetector';
import { Sanitizer } from '../analysis/detectors/SanitizerDetector';
import * as vscode from 'vscode';

export interface AnalysisResult {
  vulnerabilities: Vulnerability[];
  sources: (Source & { line: number; column: number; endLine: number; endColumn: number })[];
  sinks: (Sink & { line: number; column: number; endLine: number; endColumn: number })[];
  sanitizers: (Sanitizer & { line: number; column: number; endLine: number; endColumn: number })[];
}

export class SecurityRuleEngine {
  private patternMatcher: PatternMatcher;
  private sourceDetector: SourceDetector;
  private sinkDetector: SinkDetector;
  private sanitizerDetector: SanitizerDetector;

  constructor() {
    this.patternMatcher = new PatternMatcher();
    this.sourceDetector = new SourceDetector();
    this.sinkDetector = new SinkDetector();
    this.sanitizerDetector = new SanitizerDetector();
      }

  public analyzeFile(ast: any, languageId: string, file: string, content: string): AnalysisResult {
    try {
      console.log(`[DEBUG] 🔍 Starting security analysis for file: ${file}`);
      console.log(`[DEBUG] 📄 Language: ${languageId}`);
      
      // Detect sources, sinks, and sanitizers by traversing the AST
      console.log('[DEBUG] 🔍 Detecting sources, sinks, and sanitizers');
      const detectedSources: (Source & { line: number; column: number; endLine: number; endColumn: number })[] = [];
      const detectedSinks: (Sink & { line: number; column: number; endLine: number; endColumn: number })[] = [];
      const detectedSanitizers: (Sanitizer & { line: number; column: number; endLine: number; endColumn: number })[] = [];
      
      const traverse = (node: any) => {
        if (!node) return;
        
        // Check for sources
        const source = this.sourceDetector.detectSource(node);
        if (source) {
          detectedSources.push({
            ...source,
            line: node.loc?.start?.line || 1,
            column: node.loc?.start?.column || 0,
            endLine: node.loc?.end?.line || node.loc?.start?.line || 1,
            endColumn: node.loc?.end?.column || (node.loc?.start?.column || 0) + 10
          });
        }
        
        // Check for sinks
        const sink = this.sinkDetector.detectSink(node);
        if (sink) {
          detectedSinks.push({
            ...sink,
            line: node.loc?.start?.line || 1,
            column: node.loc?.start?.column || 0,
            endLine: node.loc?.end?.line || node.loc?.start?.line || 1,
            endColumn: node.loc?.end?.column || (node.loc?.start?.column || 0) + 10
          });
        }
        
        // Check for sanitizers
        const sanitizer = this.sanitizerDetector.detectSanitizer(node);
        if (sanitizer) {
          detectedSanitizers.push({
            ...sanitizer,
            line: node.loc?.start?.line || 1,
            column: node.loc?.start?.column || 0,
            endLine: node.loc?.end?.line || node.loc?.start?.line || 1,
            endColumn: node.loc?.end?.column || (node.loc?.start?.column || 0) + 10
          });
        }
        
        // Recursively traverse children
        if (node.children) {
          for (const child of node.children) {
            traverse(child);
          }
        }
      };
      
      traverse(ast);
      
      // Deduplicate sources, sinks, and sanitizers
      const uniqueSources = this.deduplicateDetections(detectedSources);
      const uniqueSinks = this.deduplicateDetections(detectedSinks);
      const uniqueSanitizers = this.deduplicateDetections(detectedSanitizers);
      
      console.log(`[DEBUG] 📌 Found ${uniqueSources.length} unique sources (${detectedSources.length - uniqueSources.length} duplicates removed):`);
      uniqueSources.forEach((source, index) => {
        console.log(`[DEBUG]   ${index + 1}. ${source.type} - ${source.description} (Line: ${source.line}, Column: ${source.column})`);
      });
      
      console.log(`[DEBUG] 📌 Found ${uniqueSinks.length} unique sinks (${detectedSinks.length - uniqueSinks.length} duplicates removed):`);
      uniqueSinks.forEach((sink, index) => {
        console.log(`[DEBUG]   ${index + 1}. ${sink.type} - ${sink.description} (Line: ${sink.line}, Column: ${sink.column})`);
      });
      
      console.log(`[DEBUG] 📌 Found ${uniqueSanitizers.length} unique sanitizers (${detectedSanitizers.length - uniqueSanitizers.length} duplicates removed):`);
      uniqueSanitizers.forEach((sanitizer, index) => {
        console.log(`[DEBUG]   ${index + 1}. ${sanitizer.type} - ${sanitizer.description} (Line: ${sanitizer.line}, Column: ${sanitizer.column})`);
      });
        // Pattern-based analysis
      console.log('[DEBUG] 📊 Running pattern-based analysis');
      const patternVulnerabilities = this.patternMatcher.matchPatterns(content);
      console.log(`[DEBUG] 📌 Found ${patternVulnerabilities.length} pattern-based vulnerabilities`);

      // Set file path for pattern vulnerabilities
      patternVulnerabilities.forEach(vuln => {
        vuln.file = file;
      });      // Taint analysis - check for unsanitized paths between sources and sinks
      console.log('[DEBUG] 🧬 Running taint analysis');
      const taintVulnerabilities = this.performTaintAnalysis(uniqueSources, uniqueSinks, uniqueSanitizers, file, content);
      
      // Enhanced data flow analysis (for more sophisticated tracking)
      console.log('[DEBUG] 🔬 Running enhanced data flow analysis');
      try {
        const dataFlows = this.analyzeDataFlow(ast, uniqueSources, uniqueSinks, uniqueSanitizers);
        console.log(`[DEBUG] 📊 Enhanced analysis found ${dataFlows.length} data flow paths`);
        
        // Add vulnerabilities from enhanced analysis
        for (const flow of dataFlows) {
          if (!flow.sanitized) {
            const enhancedVuln = this.createTaintVulnerability(
              flow.sourceNode, 
              flow.sinkNode, 
              file, 
              []
            );
            enhancedVuln.id = `ENHANCED_${enhancedVuln.id}`;
            enhancedVuln.message = `Enhanced analysis: ${enhancedVuln.message}`;
            taintVulnerabilities.push(enhancedVuln);
            
            console.log(`[VULNERABILITY] 🔬 Enhanced Taint Analysis Vulnerability:`);
            console.log(`  📁 File: ${file}`);
            console.log(`  🔗 Data flow path detected through variable tracking`);
            console.log(`  📍 Source: ${flow.sourceNode.type} at line ${flow.sourceNode.line}`);
            console.log(`  🎯 Sink: ${flow.sinkNode.type} at line ${flow.sinkNode.line}`);
            console.log(`  🔒 Sanitization: None detected in variable flow`);
          }
        }
      } catch (error) {
        console.log('[DEBUG] ⚠️ Enhanced data flow analysis failed, continuing with basic analysis');
        console.log(`[DEBUG] Error: ${error}`);
      }
      
      console.log(`[DEBUG] 📌 Found ${taintVulnerabilities.length} taint-based vulnerabilities`);

      // Combine all vulnerabilities
      const allVulnerabilities = [...patternVulnerabilities, ...taintVulnerabilities];

      console.log(`[DEBUG] ✅ Analysis complete. Found ${allVulnerabilities.length} total vulnerabilities, ${uniqueSources.length} sources, ${uniqueSinks.length} sinks, ${uniqueSanitizers.length} sanitizers`);

      return {
        vulnerabilities: allVulnerabilities,
        sources: uniqueSources,
        sinks: uniqueSinks,
        sanitizers: uniqueSanitizers
      };
    } catch (error) {
      console.error(`[ERROR] Failed to analyze file ${file}:`, error);
      vscode.window.showErrorMessage(`Failed to analyze file: ${file}`);
      return {
        vulnerabilities: [],
        sources: [],
        sinks: [],
        sanitizers: []
      };
    }
  }

  public reloadRules(): void {
    try {
      console.log('[DEBUG] 🔄 Reloading all security rules');
      this.patternMatcher.reloadRules();
      this.sourceDetector.reloadRules();
      this.sinkDetector.reloadRules();
      this.sanitizerDetector.reloadRules();
      console.log('[DEBUG] ✅ Rules reloaded successfully');
    } catch (error) {
      console.error('[ERROR] Failed to reload rules:', error);
      vscode.window.showErrorMessage('Failed to reload security rules');
    }
  }

  public getSourceDetector(): SourceDetector {
    return this.sourceDetector;
  }

  public getSinkDetector(): SinkDetector {
    return this.sinkDetector;
  }

  public getSanitizerDetector(): SanitizerDetector {
    return this.sanitizerDetector;
  }

  public getPatternMatcher(): PatternMatcher {
    return this.patternMatcher;
  }
  /**
   * Performs taint analysis to detect vulnerabilities in data flow between sources and sinks
   */
  private performTaintAnalysis(
    sources: (Source & { line: number; column: number; endLine: number; endColumn: number })[],
    sinks: (Sink & { line: number; column: number; endLine: number; endColumn: number })[],
    sanitizers: (Sanitizer & { line: number; column: number; endLine: number; endColumn: number })[],
    file: string,
    content: string
  ): Vulnerability[] {
    const vulnerabilities: Vulnerability[] = [];
    
    console.log('[DEBUG] 🧬 Starting taint analysis');
    console.log(`[DEBUG] 📊 Analyzing ${sources.length} sources and ${sinks.length} sinks`);
    
    // Basic line-based analysis
    for (const source of sources) {
      console.log(`[DEBUG] 🔍 Analyzing source: ${source.type} at line ${source.line}`);
      
      for (const sink of sinks) {
        console.log(`[DEBUG] 🎯 Checking sink: ${sink.type} at line ${sink.line}`);
        
        // Simple heuristic: if sink is after source in the same file, consider it a potential path
        if (sink.line > source.line) {
          console.log(`[DEBUG] 🛤️ Found potential data flow from source (line ${source.line}) to sink (line ${sink.line})`);
          
          // Check if there are sanitizers between source and sink
          const pathSanitizers = this.findSanitizersInPath(source, sink, sanitizers);
          
          // Evaluate sanitization effectiveness
          const isEffectivelySanitized = this.isSanitizationEffective(pathSanitizers, sink.vulnerabilityType);
          
          if (!isEffectivelySanitized) {
            // No effective sanitization found - this is a vulnerability
            console.log(`[DEBUG] ⚠️ VULNERABILITY DETECTED: Unsanitized data flow from ${source.type} to ${sink.type}`);
            
            const vulnerability = this.createTaintVulnerability(source, sink, file, pathSanitizers);
            vulnerabilities.push(vulnerability);
            
            // Log vulnerability details to console as requested
            console.log(`[VULNERABILITY] 🚨 Taint Analysis Vulnerability Detected:`);
            console.log(`  📁 File: ${file}`);
            console.log(`  📍 Source: ${source.type} (${source.description}) at line ${source.line}`);
            console.log(`  🎯 Sink: ${sink.type} (${sink.description}) at line ${sink.line}`);
            console.log(`  🔒 Sanitizers: ${pathSanitizers.length > 0 ? `${pathSanitizers.length} found but insufficient` : 'None found in path'}`);
            if (pathSanitizers.length > 0) {
              pathSanitizers.forEach((sanitizer, index) => {
                console.log(`    ${index + 1}. ${sanitizer.type} (effectiveness: ${sanitizer.effectiveness}) at line ${sanitizer.line}`);
              });
            }
            console.log(`  ⚡ Vulnerability Type: ${sink.vulnerabilityType}`);
            console.log(`  📊 Severity: ${sink.severity}`);
            console.log(`  💡 Recommendation: Add or improve sanitization between source and sink`);
            
          } else {
            console.log(`[DEBUG] ✅ Path is adequately sanitized with ${pathSanitizers.length} sanitizer(s)`);
            pathSanitizers.forEach((sanitizer, index) => {
              console.log(`[DEBUG]   ${index + 1}. ${sanitizer.type} (effectiveness: ${sanitizer.effectiveness}) at line ${sanitizer.line}`);
            });
          }
        }
      }
    }
    
    console.log(`[DEBUG] 🧬 Taint analysis complete. Found ${vulnerabilities.length} taint vulnerabilities`);
    return vulnerabilities;
  }

  /**
   * Finds sanitizers that exist between a source and sink in the code path
   */
  private findSanitizersInPath(
    source: { line: number; column: number },
    sink: { line: number; column: number },
    sanitizers: (Sanitizer & { line: number; column: number; endLine: number; endColumn: number })[]
  ): (Sanitizer & { line: number; column: number; endLine: number; endColumn: number })[] {
    return sanitizers.filter(sanitizer => {
      // Simple heuristic: sanitizer is in path if it's between source and sink lines
      return sanitizer.line > source.line && sanitizer.line < sink.line;
    });
  }
  /**
   * Creates a vulnerability object for taint analysis findings
   */
  private createTaintVulnerability(
    source: Source & { line: number; column: number },
    sink: Sink & { line: number; column: number },
    file: string,
    sanitizers?: (Sanitizer & { line: number; column: number; endLine: number; endColumn: number })[]
  ): Vulnerability {
    const vulnerabilityId = `TAINT_${source.type}_TO_${sink.type}_${source.line}_${sink.line}`;
    
    let sanitizerInfo = '';
    if (sanitizers && sanitizers.length > 0) {
      sanitizerInfo = ` Existing sanitizers (${sanitizers.map(s => s.type).join(', ')}) are insufficient for this vulnerability type.`;
    }
    
    return {
      id: vulnerabilityId,
      type: sink.vulnerabilityType,
      severity: sink.severity,
      message: `Untrusted data from ${source.type} flows to ${sink.type} without adequate sanitization`,
      file: file,
      line: sink.line,
      column: sink.column,
      rule: 'taint-analysis',
      description: `Data from untrusted source '${source.description}' at line ${source.line} flows to sensitive sink '${sink.description}' at line ${sink.line} without being adequately sanitized.${sanitizerInfo} This could lead to ${sink.vulnerabilityType} vulnerabilities.`,
      recommendation: `Sanitize the data between the source (line ${source.line}) and sink (line ${sink.line}) using appropriate validation and encoding functions. Consider input validation, output encoding, or parameterized queries depending on the context. ${sanitizers && sanitizers.length > 0 ? 'Improve existing sanitization methods or add additional layers of protection.' : 'Add proper sanitization functions.'}`
    };
  }

  /**
   * Enhanced taint analysis that considers variable tracking and data flow
   */
  private analyzeDataFlow(
    ast: any,
    sources: (Source & { line: number; column: number; endLine: number; endColumn: number })[],
    sinks: (Sink & { line: number; column: number; endLine: number; endColumn: number })[],
    sanitizers: (Sanitizer & { line: number; column: number; endLine: number; endColumn: number })[]
  ): { sourceNode: any; sinkNode: any; path: any[]; sanitized: boolean }[] {
    const dataFlows: { sourceNode: any; sinkNode: any; path: any[]; sanitized: boolean }[] = [];
    const variables = new Map<string, { source?: any; sanitized: boolean; line: number }>();
    
    // Simple variable tracking through AST traversal
    const trackVariables = (node: any) => {
      if (!node) return;
      
      // Track variable assignments from sources
      if (node.type === 'assignment' || node.type === 'variable_declaration') {
        const varName = this.extractVariableName(node);
        if (varName) {
          // Check if the assignment involves a source
          const sourceInAssignment = sources.find(s => 
            Math.abs(s.line - (node.loc?.start?.line || 0)) <= 1
          );
          
          if (sourceInAssignment) {
            variables.set(varName, {
              source: sourceInAssignment,
              sanitized: false,
              line: node.loc?.start?.line || 0
            });
            console.log(`[DEBUG] 📝 Tracked tainted variable: ${varName} from source ${sourceInAssignment.type}`);
          }
          
          // Check if the assignment involves sanitization
          const sanitizerInAssignment = sanitizers.find(s => 
            Math.abs(s.line - (node.loc?.start?.line || 0)) <= 1
          );
          
          if (sanitizerInAssignment && variables.has(varName)) {
            const varInfo = variables.get(varName)!;
            varInfo.sanitized = true;
            console.log(`[DEBUG] 🧼 Variable ${varName} sanitized with ${sanitizerInAssignment.type}`);
          }
        }
      }
      
      // Check if sinks use tracked variables
      if (node.type === 'call' || node.type === 'expression_statement') {
        const sinkAtNode = sinks.find(s => 
          Math.abs(s.line - (node.loc?.start?.line || 0)) <= 1
        );
        
        if (sinkAtNode) {
          const usedVars = this.extractUsedVariables(node);
          for (const varName of usedVars) {
            const varInfo = variables.get(varName);
            if (varInfo && varInfo.source) {
              dataFlows.push({
                sourceNode: varInfo.source,
                sinkNode: sinkAtNode,
                path: [varInfo.source, sinkAtNode],
                sanitized: varInfo.sanitized
              });
              console.log(`[DEBUG] 🔗 Data flow detected: ${varName} from ${varInfo.source.type} to ${sinkAtNode.type} (sanitized: ${varInfo.sanitized})`);
            }
          }
        }
      }
      
      // Recursively process children
      if (node.children) {
        for (const child of node.children) {
          trackVariables(child);
        }
      }
    };
    
    trackVariables(ast);
    return dataFlows;
  }

  /**
   * Extracts variable name from assignment or declaration nodes
   */
  private extractVariableName(node: any): string | null {
    // This is a simplified implementation - would need to be enhanced for specific languages
    if (node.type === 'assignment' && node.left) {
      return node.left.name || node.left.property?.name || null;
    }
    if (node.type === 'variable_declaration' && node.declarations?.[0]) {
      return node.declarations[0].id?.name || null;
    }
    return null;
  }

  /**
   * Extracts variables used in an expression or call
   */
  private extractUsedVariables(node: any): string[] {
    const variables: string[] = [];
    
    const extractVars = (n: any) => {
      if (!n) return;
      
      if (n.type === 'identifier' && n.name) {
        variables.push(n.name);
      }
      
      if (n.arguments) {
        for (const arg of n.arguments) {
          extractVars(arg);
        }
      }
      
      if (n.children) {
        for (const child of n.children) {
          extractVars(child);
        }
      }
    };
    
    extractVars(node);
    return [...new Set(variables)]; // Remove duplicates
  }

  /**
   * Evaluates if sanitization is effective against specific vulnerability types
   */
  private isSanitizationEffective(
    sanitizers: (Sanitizer & { line: number; column: number; endLine: number; endColumn: number })[],
    vulnerabilityType: string
  ): boolean {
    if (sanitizers.length === 0) return false;
    
    // Check if any sanitizer is effective for this vulnerability type
    for (const sanitizer of sanitizers) {
      // High effectiveness threshold
      if (sanitizer.effectiveness >= 0.8) {
        console.log(`[DEBUG] ✅ Effective sanitization found: ${sanitizer.type} (effectiveness: ${sanitizer.effectiveness})`);
        return true;
      }
    }
    
    // Multiple sanitizers might combine to be effective
    const totalEffectiveness = sanitizers.reduce((sum, s) => sum + s.effectiveness, 0);
    const averageEffectiveness = totalEffectiveness / sanitizers.length;
    
    if (averageEffectiveness >= 0.7) {
      console.log(`[DEBUG] ✅ Combined sanitization effective (average: ${averageEffectiveness})`);
      return true;
    }
    
    console.log(`[DEBUG] ⚠️ Sanitization may be insufficient (average: ${averageEffectiveness})`);
    return false;
  }

  /**
   * Provides a detailed summary of the taint analysis results
   */
  public getTaintAnalysisSummary(analysisResult: AnalysisResult): string {
    const { vulnerabilities, sources, sinks, sanitizers } = analysisResult;
    
    const taintVulnerabilities = vulnerabilities.filter(v => v.rule === 'taint-analysis');
    const patternVulnerabilities = vulnerabilities.filter(v => v.rule !== 'taint-analysis');
    
    let summary = '\n🧬 TAINT ANALYSIS SUMMARY\n';
    summary += '========================\n\n';
    
    summary += `📊 Analysis Results:\n`;
    summary += `   • Sources detected: ${sources.length}\n`;
    summary += `   • Sinks detected: ${sinks.length}\n`;
    summary += `   • Sanitizers detected: ${sanitizers.length}\n`;
    summary += `   • Taint vulnerabilities: ${taintVulnerabilities.length}\n`;
    summary += `   • Pattern vulnerabilities: ${patternVulnerabilities.length}\n`;
    summary += `   • Total vulnerabilities: ${vulnerabilities.length}\n\n`;
    
    if (sources.length > 0) {
      summary += `📍 Sources Found:\n`;
      sources.forEach((source, index) => {
        summary += `   ${index + 1}. ${source.type} - "${source.description}" (Line: ${source.line})\n`;
      });
      summary += '\n';
    }
    
    if (sinks.length > 0) {
      summary += `🎯 Sinks Found:\n`;
      sinks.forEach((sink, index) => {
        summary += `   ${index + 1}. ${sink.type} - "${sink.description}" (Line: ${sink.line})\n`;
      });
      summary += '\n';
    }
    
    if (sanitizers.length > 0) {
      summary += `🧼 Sanitizers Found:\n`;
      sanitizers.forEach((sanitizer, index) => {
        summary += `   ${index + 1}. ${sanitizer.type} - "${sanitizer.description}" (Line: ${sanitizer.line}, Effectiveness: ${sanitizer.effectiveness})\n`;
      });
      summary += '\n';
    }
    
    if (taintVulnerabilities.length > 0) {
      summary += `🚨 Taint Vulnerabilities:\n`;
      taintVulnerabilities.forEach((vuln, index) => {
        summary += `   ${index + 1}. [${vuln.severity.toUpperCase()}] ${vuln.type} - Line ${vuln.line}\n`;
        summary += `      ${vuln.message}\n`;
      });
      summary += '\n';
    }
    
    summary += `💡 Recommendations:\n`;
    if (taintVulnerabilities.length > 0) {
      summary += `   • ${taintVulnerabilities.length} taint vulnerabilities need attention\n`;
      summary += `   • Implement proper input validation and output encoding\n`;
      summary += `   • Consider using parameterized queries for database operations\n`;
      summary += `   • Add sanitization functions between sources and sinks\n`;
    } else if (sources.length > 0 && sinks.length > 0) {
      summary += `   • Good! No taint vulnerabilities detected\n`;
      summary += `   • Data flows appear to be properly sanitized\n`;
    } else {
      summary += `   • Continue monitoring for new sources and sinks\n`;
    }
    
    return summary;
  }

  private deduplicateDetections(detections: any[]): any[] {
    const uniqueDetections: any[] = [];
    const seen: Set<string> = new Set();

    for (const detection of detections) {
      // Create a key based on detection type, line number, and detection ID (ignoring column differences)
      const key = `${detection.type}_${detection.id}_${detection.line}`;
      
      if (!seen.has(key)) {
        seen.add(key);
        uniqueDetections.push(detection);
      } else {
        console.log(`[DEBUG] 🔄 Removing duplicate detection: ${detection.type} (${detection.id}) at line ${detection.line}`);
      }
    }

    return uniqueDetections;
  }
}
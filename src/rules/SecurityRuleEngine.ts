import { Vulnerability, Severity } from '../types';
import { PatternMatcher } from '../analysis/patternMatchers/PatternMatcher';
import { SourceDetector, SinkDetector, SanitizerDetector, Source, Sink, Sanitizer } from '../analysis/detectors/index';
import { TaintEngine } from '../analysis/TaintEngine';
import { AiEngine, AiAnalysisRequest, AiAnalysisResult } from '../ai';
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
  private taintEngine: TaintEngine;

  constructor() {
    this.patternMatcher = new PatternMatcher();
    this.sourceDetector = new SourceDetector();
    this.sinkDetector = new SinkDetector();
    this.sanitizerDetector = new SanitizerDetector();
    this.taintEngine = new TaintEngine();
      }

  public async analyzeFile(ast: any, languageId: string, file: string, content: string): Promise<AnalysisResult> {
    try {
      // Detect sources, sinks, and sanitizers by traversing the AST
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
            id: node.id,
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
            id: node.id,
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
            id: node.id,
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
  
      // Pattern-based analysis
      const patternVulnerabilities = this.patternMatcher.matchPatterns(content);
      // Set file path for pattern vulnerabilities
      patternVulnerabilities.forEach(vuln => {
        vuln.file = file;
      });      // Taint analysis - check for unsanitized paths between sources and sinks
      const taintVulnerabilities = this.taintEngine.performTaintAnalysis(uniqueSources, uniqueSinks, uniqueSanitizers,ast, file);
      
      // AI-powered analysis using AiEngine (code extraction + verification)
      let aiAnalysisResult: AiAnalysisResult | null = null;
      
      if (taintVulnerabilities.length > 0) {
        try {
          const aiEngine = new AiEngine();
          const aiRequest: AiAnalysisRequest = {
            file,
            vulnerabilities: taintVulnerabilities,
            context: {
              language: languageId,
              additionalInfo: `Static analysis detected ${taintVulnerabilities.length} potential vulnerabilities`
            }
          };
          
          aiAnalysisResult = await aiEngine.analyzeVulnerabilities(aiRequest);
          console.log(`[DEBUG] 🎯 AI Analysis complete: ${aiAnalysisResult.summary.confirmed} confirmed, ${aiAnalysisResult.summary.falsePositives} false positives`);
        } catch (aiError) {
          console.log(`[DEBUG] ⚠️ AI analysis failed: ${aiError}`);
        }
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
      this.patternMatcher.reloadRules();
      this.sourceDetector.reloadRules();
      this.sinkDetector.reloadRules();
      this.sanitizerDetector.reloadRules();
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
      }
    }

    return uniqueDetections;
  }
}
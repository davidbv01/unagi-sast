import { Vulnerability, Severity, AstNode } from '../types';
import { PatternMatcher } from '../analysis/patternMatchers/PatternMatcher';
import { SourceDetector, SinkDetector, SanitizerDetector, Source, Sink, Sanitizer } from '../analysis/detectors/index';
import { TaintEngine } from '../analysis/TaintEngine';
import { AiEngine, AiAnalysisRequest, AiAnalysisResult } from '../ai';
import { DataFlowGraph } from '../parser/DataFlowGraph';
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
  private aiEngine?: AiEngine;

  constructor(apiKey: string) {
    this.patternMatcher = new PatternMatcher();
    this.sourceDetector = new SourceDetector();
    this.sinkDetector = new SinkDetector();
    this.sanitizerDetector = new SanitizerDetector();
    this.taintEngine = new TaintEngine();
    if (apiKey){
      this.aiEngine = new AiEngine(apiKey);
    }
  }

  public updateAiEngine(apiKey: string | null): void {
    if (apiKey && apiKey.trim() !== '') {
      this.aiEngine = new AiEngine(apiKey);
      console.log('[INFO] AI Engine initialized');
    } else {
      this.aiEngine = undefined;
      console.log('[INFO] AI Engine disabled (no API key)');
    }
  }

  public async analyzeFile(ast: AstNode, dfg: DataFlowGraph, languageId: string, file: string, content: string): Promise<AnalysisResult> {
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
      
      // Initialize finalVulnerabilities with pattern vulnerabilities
      let finalVulnerabilities: Vulnerability[] = [...patternVulnerabilities];

      // Verify that we have api keys for AI analysis
      if (!this.aiEngine) {
        console.warn('[WARNING] No API key provided for AI analysis. Skipping AI-powered verification');
        vscode.window.showWarningMessage('No API key provided for AI analysis. Skipping AI-powered verification');
        finalVulnerabilities.push(...taintVulnerabilities);
      }
      else {
        // AI-powered analysis using AiEngine (code extraction + verification)
      let aiAnalysisResult: AiAnalysisResult | null = null;
      
      if (taintVulnerabilities.length > 0) {
        try {
          const aiRequest: AiAnalysisRequest = {
            file,
            vulnerabilities: taintVulnerabilities,
            context: {
              
              language: languageId,
              additionalInfo: `Static analysis detected ${taintVulnerabilities.length} potential vulnerabilities`
            }
          };

          aiAnalysisResult = await this.aiEngine.analyzeVulnerabilities(aiRequest, ast);
          console.log(`[DEBUG] 🎯 AI Analysis complete: ${aiAnalysisResult.summary.confirmed} confirmed, ${aiAnalysisResult.summary.falsePositives} false positives`);
          
          if (aiAnalysisResult) {
            for (const verified of aiAnalysisResult.verifiedVulnerabilities) {
              if (verified.isConfirmed) {
                finalVulnerabilities.push({
                  ...verified.originalVulnerability,
                  ai: {
                    confidenceScore: verified.aiAnalysis.confidenceScore,
                    shortExplanation: verified.aiAnalysis.shortExplanation,
                    exploitExample: verified.aiAnalysis.exploitExample,
                    remediation: verified.aiAnalysis.remediation
                  }
                });
              }
            }
          }
        } catch (aiError) {
          // Handle AI analysis errors
          finalVulnerabilities = [...patternVulnerabilities, ...taintVulnerabilities];
          vscode.window.showWarningMessage(`AI analysis failed`);
        }
      }
      
      console.log(`[DEBUG] 📌 Found ${taintVulnerabilities.length} taint-based vulnerabilities`);
      }


      // Combine all vulnerabilities
      console.log(`[DEBUG] ✅ Analysis complete. Found ${finalVulnerabilities.length} total vulnerabilities, ${uniqueSources.length} sources, ${uniqueSinks.length} sinks, ${uniqueSanitizers.length} sanitizers`);

      return {
        vulnerabilities: finalVulnerabilities,
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

  private deduplicateDetections(detections: any[]): any[] {
    const uniqueDetections: any[] = [];
    const seen: Set<string> = new Set();

    for (const detection of detections) {
      // Create a key based on detection type, line number, and detection ID (ignoring column differences)
      const key = `${detection.type}_${detection.line}`;
      
      if (!seen.has(key)) {
        seen.add(key);
        uniqueDetections.push(detection);
      }
    }

    return uniqueDetections;
  }
}
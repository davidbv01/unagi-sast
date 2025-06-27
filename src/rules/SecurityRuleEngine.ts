import { Vulnerability, DataFlowVulnerability, Severity, AstNode } from '../types';
import { PatternMatcher } from '../analysis/patternMatchers/PatternMatcher';
import { SourceDetector, SinkDetector, SanitizerDetector, Source, Sink, Sanitizer } from '../analysis/detectors/index';
import { AiEngine, AiAnalysisRequest, AiAnalysisResult } from '../ai';
import { DataFlowGraph } from '../analysis/DataFlowGraph';
import * as vscode from 'vscode';

export interface AnalysisResult {
  patternVulnerabilities: Vulnerability[];
  dataFlowVulnerabilities: DataFlowVulnerability[];
}

export class SecurityRuleEngine {
  private patternMatcher: PatternMatcher;
  private sourceDetector: SourceDetector;
  private sinkDetector: SinkDetector;
  private sanitizerDetector: SanitizerDetector;
  private aiEngine?: AiEngine;

  constructor(apiKey: string) {
    this.patternMatcher = new PatternMatcher();
    this.sourceDetector = new SourceDetector();
    this.sinkDetector = new SinkDetector();
    this.sanitizerDetector = new SanitizerDetector();
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
          // Detect sources
          const detectedSources: (Source & { line: number; column: number; endLine: number; endColumn: number })[] = [];

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

              // Traverse children
              if (node.children) {
                  for (const child of node.children) {
                      traverse(child);
                  }
              }
          };

          // Start traversal
          traverse(ast);

          // Deduplicate sources, sinks, and sanitizers
          const uniqueSources = this.deduplicateDetections(detectedSources);

          // Pattern-based analysis
          const patternVulnerabilities = this.patternMatcher.matchPatterns(content);
          // Set file path for pattern vulnerabilities
          patternVulnerabilities.forEach(vuln => {
              vuln.file = file;
          });      

          // Store detected sources in the DataFlowGraph and perform taint analysis
          for (const source of Object.values(uniqueSources)) {
              // Store the detected source in the corresponding DFG node
              const sourceNode = dfg.nodes.get(source.key);
              if (sourceNode) {
                  sourceNode.detectedSource = source;
              }
              
              dfg.propagateTaint(source.key);
              console.log("[DEBUG] propagateTaint for source:", source.key);

              for (const node of dfg.nodes.values()) {
                  console.log(`Node ${node.id} tainted? ${node.tainted} - Sources: ${[...node.taintSources].join(", ")}`);
              }
          }
          dfg.printGraph();
          const dataFlowVulnerabilities = dfg.detectVulnerabilities();

          // Initialize result with pattern vulnerabilities and empty data flow vulnerabilities
          let finalDataFlowVulnerabilities: DataFlowVulnerability[] = [...dataFlowVulnerabilities];

          // Verify that we have api keys for AI analysis
          if (!this.aiEngine) {
              console.warn('[WARNING] No API key provided for AI analysis. Skipping AI-powered verification');
              vscode.window.showWarningMessage('No API key provided for AI analysis. Skipping AI-powered verification');
              // Keep data flow vulnerabilities as-is without AI verification
          } else {
              // AI-powered analysis using AiEngine (code extraction + verification)
              let aiAnalysisResult: AiAnalysisResult | null = null;
              
              if (dataFlowVulnerabilities.length > 0) {
                  try {
                      // Convert DataFlowVulnerability to Vulnerability for AI analysis
                      const vulnerabilitiesForAI: Vulnerability[] = dataFlowVulnerabilities.map(dfv => ({
                          id: dfv.id,
                          type: dfv.type,
                          severity: dfv.severity,
                          message: dfv.message,
                          file: dfv.file,
                          line: dfv.source.id === 'unknown' ? 0 : 1, // Default line
                          column: 0, // Default column
                          rule: dfv.rule,
                          description: dfv.description,
                          recommendation: dfv.recommendation
                      }));

                      const aiRequest: AiAnalysisRequest = {
                          file,
                          vulnerabilities: vulnerabilitiesForAI,
                          context: {
                              language: languageId,
                              additionalInfo: `Static analysis detected ${dataFlowVulnerabilities.length} potential data flow vulnerabilities`
                          }
                      };

                      aiAnalysisResult = await this.aiEngine.analyzeVulnerabilities(aiRequest, ast);
                      console.log(`[DEBUG] 🎯 AI Analysis complete: ${aiAnalysisResult.summary.confirmed} confirmed, ${aiAnalysisResult.summary.falsePositives} false positives`);
                      
                      if (aiAnalysisResult) {
                          // Update data flow vulnerabilities with AI analysis results
                          finalDataFlowVulnerabilities = dataFlowVulnerabilities.map(dfv => {
                              const verifiedResult = aiAnalysisResult!.verifiedVulnerabilities.find(v => v.originalVulnerability.id === dfv.id);
                              if (verifiedResult && verifiedResult.isConfirmed) {
                                  return {
                                      ...dfv,
                                      isVulnerable: true,
                                      ai: {
                                          confidenceScore: verifiedResult.aiAnalysis.confidenceScore,
                                          shortExplanation: verifiedResult.aiAnalysis.shortExplanation,
                                          exploitExample: verifiedResult.aiAnalysis.exploitExample,
                                          remediation: verifiedResult.aiAnalysis.remediation
                                      }
                                  };
                              } else {
                                  return {
                                      ...dfv,
                                      isVulnerable: false // AI determined it's not vulnerable
                                  };
                              }
                          });
                      }
                  } catch (aiError) {
                      // Handle AI analysis errors - keep original data flow vulnerabilities
                      console.error('[ERROR] AI analysis failed:', aiError);
                      vscode.window.showWarningMessage(`AI analysis failed`);
                  }
              }
              
              console.log(`[DEBUG] 📌 Found ${dataFlowVulnerabilities.length} data flow vulnerabilities`);
          }

          return {
              patternVulnerabilities: patternVulnerabilities,
              dataFlowVulnerabilities: finalDataFlowVulnerabilities
          };
      } catch (error) {
          console.error(`[ERROR] Failed to analyze file ${file}:`, error);
          vscode.window.showErrorMessage(`Failed to analyze file: ${file}`);
          return {
              patternVulnerabilities: [],
              dataFlowVulnerabilities: []
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
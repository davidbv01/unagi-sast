import { Vulnerability, DataFlowVulnerability, AstNode, AiAnalysisRequest, AiAnalysisResult, AnalysisResult } from '../types';
import { PatternMatcher } from '../analysis/patternMatchers/PatternMatcher';
import { SinkDetector, SanitizerDetector } from '../analysis/detectors/index';
import { AiEngine } from '../ai';
import { DataFlowGraph } from '../analysis/DataFlowGraph';  
import * as vscode from 'vscode';

export class SecurityRuleEngine {
  private patternMatcher: PatternMatcher;
  private sinkDetector: SinkDetector;
  private sanitizerDetector: SanitizerDetector;
  private aiEngine?: AiEngine;

  constructor(apiKey: string) {
    this.patternMatcher = new PatternMatcher();
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

  public async analyzeFile(ast: AstNode, languageId: string, file: string, content: string): Promise<AnalysisResult> {
      try {
          // Create a new DataFlowGraph instance for each scan
          const dfg = new DataFlowGraph();
          
          // Pattern-based analysis
          const patternVulnerabilities = this.patternMatcher.matchPatterns(content);
          // Set file path for pattern vulnerabilities
          patternVulnerabilities.forEach(vuln => {
              vuln.file = file;
          });      

          // Perform complete data flow analysis (build graph, detect sources, propagate taint, detect vulnerabilities)
          const dataFlowVulnerabilities = dfg.performCompleteAnalysis(ast);

          // Initialize result with pattern vulnerabilities and data flow vulnerabilities
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
                          line: dfv.sources[0].id === 'unknown' ? 0 : 1, // Default line
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
      this.sinkDetector.reloadRules();
      this.sanitizerDetector.reloadRules();
    } catch (error) {
      console.error('[ERROR] Failed to reload rules:', error);
      vscode.window.showErrorMessage('Failed to reload security rules');
    }
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
}
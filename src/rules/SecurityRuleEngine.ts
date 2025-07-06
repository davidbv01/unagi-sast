import { DataFlowVulnerability, PatternVulnerability, AstNode, AiAnalysisRequest, AnalysisResult } from '../types';
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

  /**
   * Applies AI analysis to vulnerabilities and populates their ai property.
   * @param vulnerabilities Array of vulnerabilities to analyze (pattern and/or data flow)
   * @param ast The AST node for code extraction context
   * @param file The file path being analyzed
   * @param languageId The programming language identifier
   * @param vulnerabilityType Type description for logging (e.g., "pattern", "data flow")
   * @returns Promise<void> - Modifies vulnerabilities in place by adding ai property
   */
  private async applyAiAnalysis(
    vulnerabilities: Array<PatternVulnerability | DataFlowVulnerability>,
    ast: AstNode,
    file: string,
    languageId: string,
    vulnerabilityType: string
  ): Promise<void> {
    if (!this.aiEngine || vulnerabilities.length === 0) {
      return;
    }

    try {
      // Split vulnerabilities into pattern and data flow arrays
      const patternVulnerabilities = vulnerabilities.filter(
        (vuln): vuln is PatternVulnerability => vulnerabilityType === 'pattern'
      );
      const dataFlowVulnerabilities = vulnerabilities.filter(
        (vuln): vuln is DataFlowVulnerability => vulnerabilityType === 'data flow'
      );

      const aiRequest: AiAnalysisRequest = {
        file,
        content: ast.content,
        symbols: ast.symbols,
        patternVulnerabilities,
        dataFlowVulnerabilities,
        context: {
          language: languageId,
          additionalInfo: `Static analysis detected ${vulnerabilities.length} potential ${vulnerabilityType} vulnerabilities`
        }
      };

      const aiAnalysisResult = await this.aiEngine.analyzeVulnerabilities([aiRequest]);
      
      // Apply AI analysis results to all vulnerabilities
      vulnerabilities.forEach(vuln => {
        const verifiedResult = aiAnalysisResult[0]?.verifiedVulnerabilities.find((v: { originalVulnerability: { id: string } }) => v.originalVulnerability.id === vuln.id);
        if (verifiedResult) {
          // Always populate the ai property, regardless of whether vulnerability is confirmed or false positive
          (vuln as any).ai = {
            confidenceScore: verifiedResult.aiAnalysis.confidenceScore,
            shortExplanation: verifiedResult.aiAnalysis.shortExplanation,
            exploitExample: verifiedResult.aiAnalysis.exploitExample,
            remediation: verifiedResult.aiAnalysis.remediation
          };

          // For DataFlowVulnerabilities, also update the isVulnerable field based on AI analysis
          if ('isVulnerable' in vuln) {
            (vuln as DataFlowVulnerability).isVulnerable = verifiedResult.isConfirmed;
          }
        }
      });

    } catch (aiError) {
      console.error(`[ERROR] AI analysis failed for ${vulnerabilityType} vulnerabilities:`, aiError);
      vscode.window.showWarningMessage(`AI analysis failed for ${vulnerabilityType} vulnerabilities`);
    }
  }

  public async analyzeFile(ast: AstNode, languageId: string, filePath: string, content: string): Promise<AnalysisResult> {
      try {
          // Create a new DataFlowGraph instance for each scan
          const dfg = new DataFlowGraph();
          
          // Pattern-based analysis
          const patternVulnerabilities = this.patternMatcher.matchPatterns(content, filePath);
          // Set file path for pattern vulnerabilities
          patternVulnerabilities.forEach(vuln => {
              vuln.filePath = filePath;
          });      

          // Perform complete data flow analysis (build graph, detect sources, propagate taint, detect vulnerabilities)
          const dataFlowVulnerabilities = dfg.performCompleteAnalysis(ast);

          // Apply AI analysis to vulnerabilities if AI engine is available
          if (!this.aiEngine) {
              console.warn('[WARNING] No API key provided for AI analysis. Skipping AI-powered verification');
              vscode.window.showWarningMessage('No API key provided for AI analysis. Skipping AI-powered verification');
          } else {
              // Apply AI analysis to both pattern and data flow vulnerabilities
              await Promise.all([
                  this.applyAiAnalysis(patternVulnerabilities, ast, filePath, languageId, 'pattern'),
                  this.applyAiAnalysis(dataFlowVulnerabilities, ast, filePath, languageId, 'data flow')
              ]);
          }

          console.log(`[DEBUG] 📌 Found ${patternVulnerabilities.length} pattern vulnerabilities and ${dataFlowVulnerabilities.length} data flow vulnerabilities`);

          return {
              patternVulnerabilities: patternVulnerabilities,
              dataFlowVulnerabilities: dataFlowVulnerabilities
          };
      } catch (error) {
          console.error(`[ERROR] Failed to analyze file ${filePath}:`, error);
          vscode.window.showErrorMessage(`Failed to analyze file: ${filePath}`);
          return {
              patternVulnerabilities: [],
              dataFlowVulnerabilities: []
          };
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
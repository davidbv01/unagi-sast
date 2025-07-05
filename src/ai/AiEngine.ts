import { CodeExtractor } from './CodeExtractor';
import { VulnerabilityVerifier } from './VulnerabilityVerifier';
import { AstNode, AiAnalysisRequest, AiAnalysisResult } from '../types';

export class AiEngine {
  private verifier: VulnerabilityVerifier;

  constructor(apiKey: string) {
    this.verifier = new VulnerabilityVerifier(apiKey);
  }

  public async analyzeVulnerabilities(request: AiAnalysisRequest, ast: AstNode): Promise<AiAnalysisResult> {
    const { vulnerabilities, file, context } = request;
    const verified: AiAnalysisResult['verifiedVulnerabilities'] = [];
    let totalConfidence = 0, confirmed = 0, falsePositives = 0;

    const functionSymbols = (ast.symbols || []).filter(s => s.type === 'function');
    const codeExtractions = vulnerabilities.map(vuln => {
      return CodeExtractor.extractDataFlowCode(vuln.file, vuln.pathLines ?? [vuln.line], functionSymbols, ast.content);
    });

    for (let i = 0; i < vulnerabilities.length; i++) {
      const vuln = vulnerabilities[i];
      const code = codeExtractions[i];

      const analysis = await this.verifier.verifyVulnerability({
        codeExtraction: code,
        initialVulnerabilityAssessment: {
          type: vuln.type,
          severity: vuln.severity,
          message: vuln.message,
          description: vuln.description
        },
        context
      });

      const isConfirmed = analysis.isVulnerable && analysis.confidenceScore >= 0.7;
      if (isConfirmed) confirmed++;
      else falsePositives++;
      totalConfidence += analysis.confidenceScore;

      verified.push({ originalVulnerability: vuln, codeExtraction: code, aiAnalysis: analysis, isConfirmed });

    }

    return {
      codeExtractions,
      verifiedVulnerabilities: verified,
      summary: {
        totalAnalyzed: vulnerabilities.length,
        confirmed,
        falsePositives,
        avgConfidence: vulnerabilities.length ? totalConfidence / vulnerabilities.length : 0
      }
    };
  }
}
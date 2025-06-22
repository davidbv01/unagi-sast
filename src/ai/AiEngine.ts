import { CodeExtractor, DataFlowCodeExtraction } from './CodeExtractor';
import { VulnerabilityVerifier, VulnerabilityAnalysis } from './VulnerabilityVerifier';
import { Vulnerability } from '../types';

export interface AiAnalysisRequest {
  file: string;
  vulnerabilities: Vulnerability[];
  context?: {
    language: string;
    framework?: string;
    additionalInfo?: string;
  };
}

export interface AiAnalysisResult {
  codeExtractions: DataFlowCodeExtraction[];
  verifiedVulnerabilities: Array<{
    originalVulnerability: Vulnerability;
    codeExtraction: DataFlowCodeExtraction;
    aiAnalysis: VulnerabilityAnalysis;
    isConfirmed: boolean;
  }>;
  summary: {
    totalAnalyzed: number;
    confirmed: number;
    falsePositives: number;
    avgConfidence: number;
  };
}

export class AiEngine {
  private verifier: VulnerabilityVerifier;

  constructor(apiKey: string) {
    this.verifier = new VulnerabilityVerifier(apiKey);
  }

  public async analyzeVulnerabilities(request: AiAnalysisRequest, ast: any): Promise<AiAnalysisResult> {
    const { vulnerabilities, file, context } = request;
    const verified: AiAnalysisResult['verifiedVulnerabilities'] = [];
    let totalConfidence = 0, confirmed = 0, falsePositives = 0;

    const codeExtractions = vulnerabilities.map(vuln => {
      return CodeExtractor.extractDataFlowCode(vuln.file, vuln.pathLines ?? [vuln.line], ast.functions);
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
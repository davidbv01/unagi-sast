import { CodeExtractor, DataFlowCodeExtraction } from './CodeExtractor';
import { VulnerabilityVerifier, VulnerabilityAnalysis, VerificationRequest } from './VulnerabilityVerifier';
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

  public async analyzeVulnerabilities(request: AiAnalysisRequest): Promise<AiAnalysisResult> {
    const { vulnerabilities, file, context } = request;
    const verified: AiAnalysisResult['verifiedVulnerabilities'] = [];
    let totalConfidence = 0, confirmed = 0, falsePositives = 0;

    const codeExtractions = vulnerabilities.map(vuln => {
      try {
        return CodeExtractor.extractDataFlowCode(file, vuln.pathLines ?? [vuln.line]);
      } catch (err) {
        return this.buildFallbackExtraction(file, vuln.line, err);
      }
    });

    for (let i = 0; i < vulnerabilities.length; i++) {
      const vuln = vulnerabilities[i];
      const code = codeExtractions[i];

      try {
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

      } catch (err) {
        verified.push({
          originalVulnerability: vuln,
          codeExtraction: code,
          aiAnalysis: this.buildFallbackAnalysis(vuln.type, err),
          isConfirmed: false
        });
        falsePositives++;
      }
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

  public async analyzeSingleVulnerability(
    file: string,
    vulnerability: Vulnerability,
    context?: AiAnalysisRequest['context']
  ): Promise<AiAnalysisResult['verifiedVulnerabilities'][0]> {
    const result = await this.analyzeVulnerabilities({ file, vulnerabilities: [vulnerability], context });
    return result.verifiedVulnerabilities[0];
  }

  private buildFallbackExtraction(file: string, line: number, err: unknown): DataFlowCodeExtraction {
    return {
      involvedLines: [line],
      fullContext: `Error extracting code: ${err}`,
      filePath: file,
      sanitizerFunctions: []
    };
  }

  private buildFallbackAnalysis(type: string, err: unknown): VulnerabilityAnalysis {
    return {
      isVulnerable: false,
      confidenceScore: 0,
      shortExplanation: `Verification failed: ${err}`,
      exploitExample: 'N/A',
      remediation: 'Manual review recommended due to verification error'
    };
  }
  
}
import { CodeExtractor } from './CodeExtractor';
import { VulnerabilityVerifier } from './VulnerabilityVerifier';
import { AstNode, AiAnalysisRequest, AiAnalysisResult } from '../types';

/**
 * AI engine for analyzing and verifying vulnerabilities using LLMs.
 */
export class AiEngine {
  private readonly verifier: VulnerabilityVerifier;

  /**
   * Creates a new AiEngine instance.
   * @param apiKey The OpenAI API key.
   */
  constructor(apiKey: string) {
    this.verifier = new VulnerabilityVerifier(apiKey);
  }

  /**
   * Analyzes vulnerabilities for multiple files using AI and verifies them with code context.
   * @param requests Array of AI analysis requests (one per file).
   * @returns Array of AI analysis results with verification details.
   */
  public async analyzeVulnerabilities(requests: AiAnalysisRequest[]): Promise<AiAnalysisResult[]> {
    const results: AiAnalysisResult[] = [];
    for (const request of requests) {
      const { patternVulnerabilities, dataFlowVulnerabilities, file, context, content, symbols } = request;
      const verified: AiAnalysisResult['verifiedVulnerabilities'] = [];
      let totalConfidence = 0, confirmed = 0, falsePositives = 0;
      const functionSymbols = (symbols || []).filter(s => s.type === 'function');

      // Combine all vulnerabilities for batch processing
      const allVulnerabilities = [...patternVulnerabilities, ...dataFlowVulnerabilities];
      
      if (allVulnerabilities.length === 0) {
        results.push({
          codeExtractions: [],
          verifiedVulnerabilities: [],
          summary: {
            totalAnalyzed: 0,
            confirmed: 0,
            falsePositives: 0,
            avgConfidence: 0
          }
        });
        continue;
      }

      // Extract comprehensive context for all vulnerabilities at once
      const codeExtraction = CodeExtractor.extractContext(request);

      // Prepare vulnerabilities for batch verification
      const vulnerabilitiesForVerification = allVulnerabilities.map(vuln => ({
        id: vuln.id,
        type: vuln.type,
        severity: vuln.severity,
        message: vuln.message,
        description: vuln.description,
        line: 'line' in vuln ? vuln.line : ('sources' in vuln && vuln.sources[0]?.loc?.start?.line) || undefined
      }));

      // Verify all vulnerabilities with shared context
      const analyses = await this.verifier.verifyVulnerabilities(
        vulnerabilitiesForVerification,
        codeExtraction,
        context
      );

      // Process results
      for (let i = 0; i < allVulnerabilities.length; i++) {
        const vuln = allVulnerabilities[i];
        const analysis = analyses[i];
        const isConfirmed = analysis.isVulnerable && analysis.confidenceScore >= 0.7;
        
        if (isConfirmed) confirmed++;
        else falsePositives++;
        totalConfidence += analysis.confidenceScore;
        
        verified.push({ 
          originalVulnerability: vuln, 
          codeExtraction, 
          aiAnalysis: analysis, 
          isConfirmed 
        });
      }

      const totalAnalyzed = allVulnerabilities.length;
      results.push({
        codeExtractions: [codeExtraction], // Single comprehensive extraction
        verifiedVulnerabilities: verified,
        summary: {
          totalAnalyzed,
          confirmed,
          falsePositives,
          avgConfidence: totalAnalyzed ? totalConfidence / totalAnalyzed : 0
        }
      });
    }
    return results;
  }
}
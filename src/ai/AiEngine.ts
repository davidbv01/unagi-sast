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
  private vulnerabilityVerifier: VulnerabilityVerifier;

  constructor(openaiApiKey?: string) {
    this.vulnerabilityVerifier = new VulnerabilityVerifier(openaiApiKey);
  }

  /**
   * Performs comprehensive AI analysis: code extraction followed by vulnerability verification
   */
  public async analyzeVulnerabilities(request: AiAnalysisRequest): Promise<AiAnalysisResult> {
    console.log(`[DEBUG] 🤖 Starting AI analysis for ${request.vulnerabilities.length} vulnerabilities in ${request.file}`);
    
    const codeExtractions: DataFlowCodeExtraction[] = [];
    const verifiedVulnerabilities: AiAnalysisResult['verifiedVulnerabilities'] = [];
    
    // Step 1: Code Extraction for each vulnerability
    console.log('[DEBUG] 📋 Step 1: Extracting code for data flows');
    for (const vulnerability of request.vulnerabilities) {
      try {
        const extraction = CodeExtractor.extractDataFlowCode(
          request.file, 
          vulnerability.pathLines ?? [vulnerability.line]
        );
        codeExtractions.push(extraction);
        console.log(`[DEBUG] ✅ Code extracted for vulnerability: ${vulnerability.type} at line ${vulnerability.line}`);
      } catch (extractionError) {
        console.log(`[DEBUG] ⚠️ Code extraction failed for vulnerability ${vulnerability.id}: ${extractionError}`);
        // Create a minimal extraction for verification to continue
        const fallbackExtraction: DataFlowCodeExtraction = {
          involvedLines: [vulnerability.line],
          fullContext: `Error extracting code: ${extractionError}`,
          filePath: request.file,
          sanitizerFunctions: []
        };
        codeExtractions.push(fallbackExtraction);
      }
    }

    // Step 2: Vulnerability Verification using extracted code
    console.log('[DEBUG] 🔍 Step 2: Verifying vulnerabilities with AI');
    let totalConfidence = 0;
    let confirmedCount = 0;
    let falsePositiveCount = 0;

    for (let i = 0; i < request.vulnerabilities.length; i++) {
      const vulnerability = request.vulnerabilities[i];
      const codeExtraction = codeExtractions[i];
      
      try {
        const verificationRequest: VerificationRequest = {
          codeExtraction,
          initialVulnerabilityAssessment: {
            type: vulnerability.type,
            severity: vulnerability.severity,
            message: vulnerability.message,
            description: vulnerability.description
          },
          context: request.context
        };

        const aiAnalysis = await this.vulnerabilityVerifier.verifyVulnerability(verificationRequest);
        
        // Determine if vulnerability is confirmed based on AI analysis
        const isConfirmed = aiAnalysis.isVulnerable && 
                           aiAnalysis.confidenceScore >= 0.7 && 
                           aiAnalysis.falsePositive.likelihood < 0.5;

        if (isConfirmed) {
          confirmedCount++;
        }
        
        if (aiAnalysis.falsePositive.likelihood >= 0.5) {
          falsePositiveCount++;
        }
        
        totalConfidence += aiAnalysis.confidenceScore;

        verifiedVulnerabilities.push({
          originalVulnerability: vulnerability,
          codeExtraction,
          aiAnalysis,
          isConfirmed
        });

        console.log(`[DEBUG] ✅ AI verification complete for ${vulnerability.type}: ${isConfirmed ? 'CONFIRMED' : 'REJECTED'} (confidence: ${aiAnalysis.confidenceScore})`);

      } catch (verificationError) {
        console.log(`[DEBUG] ⚠️ AI verification failed for vulnerability ${vulnerability.id}: ${verificationError}`);
        
        // Create a fallback analysis
        const fallbackAnalysis: VulnerabilityAnalysis = {
          isVulnerable: false,
          confidenceScore: 0,
          vulnerabilityType: vulnerability.type,
          severity: 'low',
          reasoning: `AI verification failed: ${verificationError}`,
          exploitability: {
            isExploitable: false,
            exploitComplexity: 'high',
            description: 'Could not analyze due to verification error'
          },
          sanitization: {
            hasSanitization: false,
            isEffective: false,
            sanitizationMethods: [],
            recommendations: ['Manual review required due to verification error']
          },
          dataFlow: {
            sourceDescription: 'Unknown',
            sinkDescription: 'Unknown',
            pathAnalysis: 'Could not analyze data flow path',
            potentialAttackVectors: []
          },
          falsePositive: {
            likelihood: 1.0,
            reasoning: 'Verification failed, treating as false positive'
          }
        };

        verifiedVulnerabilities.push({
          originalVulnerability: vulnerability,
          codeExtraction,
          aiAnalysis: fallbackAnalysis,
          isConfirmed: false
        });
        
        falsePositiveCount++;
      }
    }

    // Generate summary
    const avgConfidence = request.vulnerabilities.length > 0 ? totalConfidence / request.vulnerabilities.length : 0;
    
    const result: AiAnalysisResult = {
      codeExtractions,
      verifiedVulnerabilities,
      summary: {
        totalAnalyzed: request.vulnerabilities.length,
        confirmed: confirmedCount,
        falsePositives: falsePositiveCount,
        avgConfidence
      }
    };

    console.log(`[DEBUG] 🎯 AI Analysis Summary:`);
    console.log(`[DEBUG]   • Total vulnerabilities analyzed: ${result.summary.totalAnalyzed}`);
    console.log(`[DEBUG]   • Confirmed vulnerabilities: ${result.summary.confirmed}`);
    console.log(`[DEBUG]   • False positives detected: ${result.summary.falsePositives}`);
    console.log(`[DEBUG]   • Average confidence: ${(result.summary.avgConfidence * 100).toFixed(1)}%`);

    return result;
  }

  /**
   * Analyzes a single vulnerability with code extraction and verification
   */
  public async analyzeSingleVulnerability(
    file: string,
    vulnerability: Vulnerability,
    context?: AiAnalysisRequest['context']
  ): Promise<AiAnalysisResult['verifiedVulnerabilities'][0]> {
    const request: AiAnalysisRequest = {
      file,
      vulnerabilities: [vulnerability],
      context
    };
    
    const result = await this.analyzeVulnerabilities(request);
    return result.verifiedVulnerabilities[0];
  }

  /**
   * Gets a human-readable summary of AI analysis results
   */
  public static getAnalysisSummary(result: AiAnalysisResult): string {
    const { summary, verifiedVulnerabilities } = result;
    
    let summaryText = '\n🤖 AI VULNERABILITY ANALYSIS SUMMARY\n';
    summaryText += '====================================\n\n';
    
    summaryText += `📊 Analysis Results:\n`;
    summaryText += `   • Total vulnerabilities analyzed: ${summary.totalAnalyzed}\n`;
    summaryText += `   • Confirmed vulnerabilities: ${summary.confirmed}\n`;
    summaryText += `   • False positives detected: ${summary.falsePositives}\n`;
    summaryText += `   • Average confidence: ${(summary.avgConfidence * 100).toFixed(1)}%\n\n`;
    
    const confirmedVulns = verifiedVulnerabilities.filter(v => v.isConfirmed);
    if (confirmedVulns.length > 0) {
      summaryText += `🚨 Confirmed Vulnerabilities:\n`;
      confirmedVulns.forEach((vuln, index) => {
        summaryText += `   ${index + 1}. [${vuln.aiAnalysis.severity.toUpperCase()}] ${vuln.aiAnalysis.vulnerabilityType} - Line ${vuln.originalVulnerability.line}\n`;
        summaryText += `      Confidence: ${(vuln.aiAnalysis.confidenceScore * 100).toFixed(1)}%\n`;
        summaryText += `      ${vuln.aiAnalysis.reasoning}\n\n`;
      });
    }
    
    const falsePositives = verifiedVulnerabilities.filter(v => v.aiAnalysis.falsePositive.likelihood >= 0.5);
    if (falsePositives.length > 0) {
      summaryText += `✅ False Positives Detected:\n`;
      falsePositives.forEach((vuln, index) => {
        summaryText += `   ${index + 1}. ${vuln.originalVulnerability.type} - Line ${vuln.originalVulnerability.line}\n`;
        summaryText += `      False positive likelihood: ${(vuln.aiAnalysis.falsePositive.likelihood * 100).toFixed(1)}%\n`;
        summaryText += `      ${vuln.aiAnalysis.falsePositive.reasoning}\n\n`;
      });
    }
    
    return summaryText;
  }
}

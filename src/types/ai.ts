import { z } from 'zod';
import { Vulnerability } from './vulnerabilities';

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

  export interface FunctionExtraction {
    functionName: string;
    startLine: number;
    endLine: number;
    sourceCode: string;
    filePath: string;
    language: string;
  }
  
  export interface DataFlowCodeExtraction {
    sourceFunction?: FunctionExtraction;
    sinkFunction?: FunctionExtraction;
    sanitizerFunctions: FunctionExtraction[];
    involvedLines: number[];
    fullContext: string;
    filePath: string;
  }

  export const VulnerabilityAnalysisSchema = z.object({
    isVulnerable: z.boolean(),                    
    confidenceScore: z.number().min(0).max(1),         
    shortExplanation: z.string(),                 
    exploitExample: z.string(),        
    remediation: z.string()  
  });
  
  export type VulnerabilityAnalysis = z.infer<typeof VulnerabilityAnalysisSchema>;

  export interface VerificationRequest {
    codeExtraction: DataFlowCodeExtraction;
    initialVulnerabilityAssessment: {
      type: string;
      severity: string;
      message: string;
      description?: string;
    };
    context?: {
      language: string;
      framework?: string;
      additionalInfo?: string;
    };
  }
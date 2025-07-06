import { z } from 'zod';
import { PatternVulnerability, DataFlowVulnerability } from './vulnerabilities';
import { SymbolTableEntry } from './ast';

export interface AiAnalysisRequest {
    file: string;
    content: string;
    symbols: SymbolTableEntry[];
    patternVulnerabilities: PatternVulnerability[];
    dataFlowVulnerabilities: DataFlowVulnerability[];
    context?: {
      language: string;
      framework?: string;
      additionalInfo?: string;
    };
  }
  
  export interface AiAnalysisResult {
    codeExtractions: string[];
    verifiedVulnerabilities: Array<{
      originalVulnerability: PatternVulnerability | DataFlowVulnerability;
      codeExtraction: string;
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
    codeExtraction: string;
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
import { PatternVulnerability, DataFlowVulnerability, Vulnerability } from "./vulnerabilities";

export interface AnalysisResult {
  patternVulnerabilities: Vulnerability[];
  dataFlowVulnerabilities: DataFlowVulnerability[];
}

export interface ScanResult {
    file: string;
    patternVulnerabilities: PatternVulnerability[];
    dataFlowVulnerabilities: DataFlowVulnerability[];
    scanTime: number;
    linesScanned: number;
    language: string;
  }
  
  export enum OutputFormat {
    INLINE = 'inline',
    PROBLEMS_PANEL = 'problems',
    OUTPUT_CHANNEL = 'output',
    REPORT_FILE = 'file'
  }
  
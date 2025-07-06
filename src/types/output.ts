import { PatternVulnerability, DataFlowVulnerability } from "./vulnerabilities";

export interface AnalysisResult {
  patternVulnerabilities: PatternVulnerability[];
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

export interface WorkspaceScanResult {
  workspaceRoot: string;
  filesAnalyzed: number;
  patternVulnerabilities: PatternVulnerability[];
  dataFlowVulnerabilities: DataFlowVulnerability[];
  scanTime: number;
  linesScanned: number;
}

export enum OutputFormat {
  INLINE = 'inline',
  PROBLEMS_PANEL = 'problems',
  OUTPUT_CHANNEL = 'output',
  REPORT_FILE = 'file'
}

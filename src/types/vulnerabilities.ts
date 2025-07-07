import { Sanitizer, Source, Sink } from "./detectors";

/**
 * Base vulnerability interface containing common properties shared by all vulnerability types.
 */
export interface BaseVulnerability {
  // Core vulnerability identification
  id: string;
  type: string;
  severity: Severity;
  message: string;
  filePath: string;
  rule: string;
  description: string;
  recommendation: string;

  // Vulnerability status after analysis (including AI verification)
  isVulnerable: boolean;

  // AI analysis results (populated after AI verification)
  ai?: {
    confidenceScore: number;
    shortExplanation: string;
    exploitExample: string;
    remediation: string;
  };
}

/**
 * Pattern-based vulnerability detected through regex pattern matching.
 * Extends BaseVulnerability with location-specific information.
 */
export interface PatternVulnerability extends BaseVulnerability {
  // Location information for pattern matches
  line: number;
  column: number;
  
  // AST relations (optional for pattern vulnerabilities)
  pathLines?: number[];
  sourceId?: number;
  sinkId?: number;
  sanitizerIds?: number[];
}

/**
 * Data flow vulnerability detected through taint analysis.
 * Extends BaseVulnerability with data flow-specific information.
 */
export interface DataFlowVulnerability extends BaseVulnerability {
  // Data flow components
  sources: Source[];
  sink: Sink;
  sanitizers: Sanitizer[];

  // Cross-file data flow information
  isCrossFile?: boolean;

  // AST path traceability for the data flow
  pathLines?: number[];
}

export enum Severity {
  CRITICAL = 'CRITICAL',
  HIGH = 'HIGH',
  MEDIUM = 'MEDIUM',
  LOW = 'LOW',
  INFO = 'INFO'
}
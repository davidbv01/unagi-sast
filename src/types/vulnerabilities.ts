import { Sanitizer, Source, Sink } from "./detectors";

/**
 * Base vulnerability interface containing common properties shared by all vulnerability types.
 */
export interface BaseVulnerability {
  // Core vulnerability identification
  id: string;
  type: VulnerabilityType;
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

  // AST path traceability for the data flow
  pathLines?: number[];
}


export enum VulnerabilityType {
  SQL_INJECTION = 'SQL_INJECTION',
  XSS = 'XSS',
  CSRF = 'CSRF',
  HARDCODED_SECRET = 'HARDCODED_SECRET',
  INSECURE_RANDOM = 'INSECURE_RANDOM',
  PATH_TRAVERSAL = 'PATH_TRAVERSAL',
  COMMAND_INJECTION = 'COMMAND_INJECTION',
  WEAK_CRYPTO = 'WEAK_CRYPTO',
  AUTHORIZATION = 'AUTHORIZATION',
  AUTHENTICATION = 'AUTHENTICATION',
  INSECURE_COMMUNICATION = 'INSECURE_COMMUNICATION',
  GENERIC = 'GENERIC',
  INSECURE_DESERIALIZATION = 'INSECURE_DESERIALIZATION',
  INSECURE_PERMISSIONS = 'INSECURE_PERMISSIONS',
  IDOR = 'IDOR',
  INSECURE_DIRECT_OBJECT_REFERENCE = 'INSECURE_DIRECT_OBJECT_REFERENCE'
}

export enum Severity {
  CRITICAL = 'CRITICAL',
  HIGH = 'HIGH',
  MEDIUM = 'MEDIUM',
  LOW = 'LOW',
  INFO = 'INFO'
}
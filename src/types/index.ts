// Types and interfaces for the SAST extension

export interface Vulnerability {
  //Definition of a vulnerability
  id: string;
  type: VulnerabilityType;
  severity: Severity;
  message: string;
  file: string;
  line: number;
  column: number;
  rule: string;
  description: string;
  recommendation: string;
  
  //Relations in the AST
  pathLines?: number[];
  sourceId?: number;
  sinkId?: number;
  sanitizerIds?: number[];
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
  CRITICAL = 'critical',
  HIGH = 'high',
  MEDIUM = 'medium',
  LOW = 'low',
  INFO = 'info'
}

export interface ScanResult {
  file: string;
  vulnerabilities: Vulnerability[];
  sources: Array<{ 
    id: string; 
    type: string; 
    pattern: string; 
    description: string; 
    line: number; 
    column: number; 
    endLine: number; 
    endColumn: number; 
  }>;
  sinks: Array<{ 
    id: string; 
    type: string; 
    pattern: string; 
    description: string; 
    line: number; 
    column: number; 
    endLine: number; 
    endColumn: number; 
  }>;
  sanitizers: Array<{ 
    id: string; 
    type: string; 
    pattern: string; 
    description: string; 
    line: number; 
    column: number; 
    endLine: number; 
    endColumn: number; 
  }>;
  scanTime: number;
  linesScanned: number;
  language: string;
}

export interface ScanConfiguration {
  enabledRules: string[];
  excludePatterns: string[];
  includePatterns: string[];
  severityThreshold: Severity;
  outputFormat: OutputFormat;
}

export enum OutputFormat {
  INLINE = 'inline',
  PROBLEMS_PANEL = 'problems',
  OUTPUT_CHANNEL = 'output',
  REPORT_FILE = 'file'
}

export interface ASTScanRule {
  id: string;
  name: string;
  description: string;
  severity: Severity;
  type: VulnerabilityType;
  languages: string[];
  enabled: boolean;
  checker: (node: any, context: ASTScanContext) => ASTVulnerabilityMatch | null;
}

export interface ASTScanContext {
  fileName: string;
  sourceCode: string;
  languageId: string;
  isUserInput: (node: any) => boolean;
  isTainted: (node: any) => boolean;
  getNodeText: (node: any) => string;
  getParentNodes: (node: any) => any[];
}

export interface ASTVulnerabilityMatch {
  node: any;
  message: string;
  additionalInfo?: Record<string, any>;
}

export interface ASTPosition {
  line: number;
  column: number;
  start: number;
  end: number;
}

export interface Position {
  line: number;
  column: number;
}

// Types and interfaces for the SAST extension
//AST interfaces
export interface AstNode {
  id: Number;
  children: AstNode[];
  type: string;
  named: boolean;
  text: string;
  loc:
  {
    start: { line: Number, column: Number },
    end: { line: Number, column: Number }
  };
  functions: PythonFunction[];
  content: string
};

export interface PythonFunction {
  name: string;
  startLine: number;
  endLine: number;
}


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

  //AI analysis
  ai?: {
    confidenceScore: number;
    shortExplanation: string;
    exploitExample: string;
    remediation: string;
  };
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

export interface Position {
  line: number;
  column: number;
}
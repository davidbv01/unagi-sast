// Types and interfaces for the SAST extension

export interface Vulnerability {
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
}

export enum VulnerabilityType {
  SQL_INJECTION = 'sql-injection',
  XSS = 'xss',
  CSRF = 'csrf',
  HARDCODED_SECRET = 'hardcoded-secret',
  INSECURE_RANDOM = 'insecure-random',
  PATH_TRAVERSAL = 'path-traversal',
  COMMAND_INJECTION = 'command-injection',
  WEAK_CRYPTO = 'weak-crypto',
  AUTHORIZATION = 'authorization',
  AUTHENTICATION = 'authentication'
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
  scanTime: number;
  linesScanned: number;
}

export interface ScanConfiguration {
  enabledRules: string[];
  excludePatterns: string[];
  includePatterns: string[];
  severity: Severity[];
  outputFormat: OutputFormat;
}

export enum OutputFormat {
  INLINE = 'inline',
  PROBLEMS_PANEL = 'problems',
  OUTPUT_CHANNEL = 'output',
  REPORT_FILE = 'file'
}

export interface ScanRule {
  id: string;
  name: string;
  description: string;
  severity: Severity;
  type: VulnerabilityType;
  pattern: RegExp;
  languages: string[];
  enabled: boolean;
}

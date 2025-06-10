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

// New AST-based rule interface
export interface ASTScanRule {
  id: string;
  name: string;
  description: string;
  severity: Severity;
  type: VulnerabilityType;
  languages: string[];
  enabled: boolean;
  // AST node checker function
  checker: (node: any, context: ASTScanContext) => ASTVulnerabilityMatch | null;
}

export interface ASTScanContext {
  fileName: string;
  sourceCode: string;
  languageId: string;
  // Helper methods for common checks
  isUserInput: (node: any) => boolean;
  isTainted: (node: any) => boolean;
  getNodeText: (node: any) => string;
  getParentNodes: (node: any) => any[];
}

export interface ASTVulnerabilityMatch {
  node: any;
  message?: string;
  additionalInfo?: Record<string, any>;
}

export interface ASTPosition {
  line: number;
  column: number;
  start: number;
  end: number;
}

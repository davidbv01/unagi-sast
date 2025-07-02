import { Sanitizer, Source, Sink } from "../analysis/detectors";

//AST interfaces
export interface AstNode {
  id: number;
  children: AstNode[];
  type: string;
  named: boolean;
  text: string;
  loc:
  {
    start: { line: number, column: number },
    end: { line: number, column: number }
  };
  scope: string;
  functions: PythonFunction[];
  filePath?: string;
  content: string
};

export interface PythonFunction {
  name: string;
  startLine: number;
  endLine: number;
  parameters: string[];
}

//Output interfaces
export interface ScanResult {
  file: string;
  patternVulnerabilities: PatternVulnerability[];
  dataFlowVulnerabilities: DataFlowVulnerability[];
  scanTime: number;
  linesScanned: number;
  language: string;
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

export interface DataFlowVulnerability {
  id: string;
  type: VulnerabilityType;
  severity: Severity;
  message: string;
  file: string;
  rule: string;
  description: string;
  recommendation: string;

  // Información del flujo
  source: Source;
  sink: Sink;
  sanitizers: Sanitizer[];

  // Si se considera vulnerable o no (post-sanitización o AI)
  isVulnerable: boolean;

  // AST path / trazabilidad del flujo
  pathLines?: number[];

  // AI analysis opcional
  ai?: {
    confidenceScore: number;
    shortExplanation: string;
    exploitExample: string;
    remediation: string;
  };
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

//Enumerations 
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

export interface PatternVulnerability extends Vulnerability {}

// Inter-file analysis types
export interface ImportInfo {
  importedName: string;
  sourcePath: string;
  targetPath: string;
  importType: 'function' | 'variable' | 'class' | 'module';
  line: number;
  column: number;
}

export interface ExportInfo {
  exportedName: string;
  filePath: string;
  exportType: 'function' | 'variable' | 'class';
  line: number;
  column: number;
  astNodeId: number;
}

export interface FileAnalysisResult {
  filePath: string;
  ast: AstNode;
  imports: ImportInfo[];
  exports: ExportInfo[];
  functions: PythonFunction[];
  sources: Source[];
  sinks: Sink[];
  sanitizers: Sanitizer[];
  localVulnerabilities: DataFlowVulnerability[];
}

export interface CrossFileDataFlow {
  sourceFile: string;
  targetFile: string;
  functionName: string;
  callSite: {
    line: number;
    column: number;
  };
  parameterMappings: {
    argumentNodeId: number;
    parameterName: string;
  }[];
}

export interface WorkspaceScanResult {
  fileResults: ScanResult[];
  crossFileVulnerabilities: DataFlowVulnerability[];
  totalFiles: number;
  totalVulnerabilities: number;
  interFileConnections: CrossFileDataFlow[];
  scanTime: number;
}
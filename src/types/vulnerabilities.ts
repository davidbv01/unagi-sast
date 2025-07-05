import { Sanitizer, Source, Sink } from "./detectors";

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
    sources: Source[];
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

  export interface PatternVulnerability extends Vulnerability {}

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
import { Rule } from './rules';
import { VulnerabilityType, Severity } from './vulnerabilities';

// Base detector item interface
export interface BaseDetectorItem {
  id: string;
  type: string;
  pattern: string;
  description: string;
  loc:
  {
    start: { line: number, column: number },
    end: { line: number, column: number }
  }
  filePath: string;
  info: string;
  key?: string;
}

// Base rule interface
export interface BaseRule extends Rule {
  sources?: BaseDetectorItem[];
  sinks?: BaseDetectorItem[];
  sanitizers?: BaseDetectorItem[];
}

// Source interface
export interface Source extends BaseDetectorItem {
  severity: Severity;

}

// Sink interface
export interface Sink extends BaseDetectorItem {
  vulnerabilityType: VulnerabilityType;
  severity: Severity;
}

// Sanitizer interface
export interface Sanitizer extends BaseDetectorItem {
  effectiveness: number;
}

// Pattern interface
export interface Pattern {
  id: string;
  pattern: string;
  message: string;
  recommendation: string;
  severity?: string;
}

export interface PatternRule extends Rule {
  patterns: Pattern[];
}
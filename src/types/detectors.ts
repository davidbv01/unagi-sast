import { BaseDetectorItem } from '../analysis/detectors/detectorUtils';
import { VulnerabilityType, Severity } from './vulnerabilities';

// Source interface
export interface Source extends BaseDetectorItem {
  severity: string;
  key?: string;
}

// Sink interface
export interface Sink extends BaseDetectorItem {
  info: string;
  vulnerabilityType: VulnerabilityType;
  severity: Severity;
  key?: string;
}

// Sanitizer interface
export interface Sanitizer extends BaseDetectorItem {
  info: string;
  effectiveness: number;
  key?: string;
}

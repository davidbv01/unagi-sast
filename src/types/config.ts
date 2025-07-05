import { OutputFormat } from "./output";
import { Severity } from "./vulnerabilities";

export interface ScanConfiguration {
    enabledRules: string[];
    excludePatterns: string[];
    includePatterns: string[];
    severityThreshold: Severity;
    outputFormat: OutputFormat;
  }
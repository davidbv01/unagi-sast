import { BaseDetectorItem, BaseRule } from "./detectors";

export interface Rule {
    id: string;
    name: string;
    description: string;
    severity: string;
    type: string;
    patterns?: unknown;
    sources?: unknown;
    sinks?: unknown;
    sanitizers?: unknown;
  }


export interface SourceRule extends BaseRule {
    sources: BaseDetectorItem[];
  }

export interface SinkRule extends BaseRule {
    sinks: BaseDetectorItem[];
  }
  
export interface SanitizerRule extends BaseRule {
    sanitizers: BaseDetectorItem[];
  }
  
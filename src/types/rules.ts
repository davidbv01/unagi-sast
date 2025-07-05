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
import { Sanitizer, Sink, Source } from "./detectors";
import { AstNode } from "./ast";

export interface DfgNode {
    id: string;
    name: string;
    astNode: AstNode;
    tainted: boolean;
    taintSources: Set<Source>;
    edges: Set<DfgNode>;
    symbol?: Symbol;
    isSanitizer?: boolean;
    isSink?: boolean;
    infoSanitizer?: string;
    infoSink?: string;
    detectedSource?: Source;
    detectedSink?: Sink;
    detectedSanitizer?: Sanitizer;
    crossFileRef?: any;
    crossFileEdge?: {
      from: string;
      to: string;
      function: string;
    };
  };

  export interface Symbol {
    name: string;
    scope: string;
    uniqueId: string;
  };
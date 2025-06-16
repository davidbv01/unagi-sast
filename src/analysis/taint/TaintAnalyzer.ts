import { Source, SourceDetector } from '../detectors/SourceDetector';
import { Sink, SinkDetector } from '../detectors/SinkDetector';
import { Sanitizer, SanitizerDetector } from '../detectors/SanitizerDetector';
import { Vulnerability, VulnerabilityType, Severity } from '../../types';

export interface TaintNode {
  id: string;
  type: string;
  tainted: boolean;
  source?: Source;
  sanitizers: Sanitizer[];
  children: TaintNode[];
  location: {
    line: number;
    column: number;
  };
  named?: boolean;
  loc?: {
    start: {
      line: number;
      column: number;
    };
    end: {
      line: number;
      column: number;
    };
  };
}

export interface TaintPath {
  source: Source;
  sink: Sink;
  path: TaintNode[];
  isVulnerable: boolean;
  sanitizationPoints: Sanitizer[];
}

export class TaintAnalyzer {
  private sourceDetector: SourceDetector;
  private sinkDetector: SinkDetector;
  private sanitizerDetector: SanitizerDetector;

  constructor(sourceDetector: SourceDetector, sinkDetector: SinkDetector, sanitizerDetector: SanitizerDetector) {
    this.sourceDetector = sourceDetector;
    this.sinkDetector = sinkDetector;
    this.sanitizerDetector = sanitizerDetector;
  }

  public analyzeTaintFlow(ast: any): TaintPath[] {
    console.log('[DEBUG] 🔍 Starting taint flow analysis');
    const paths: TaintPath[] = [];
    const taintNodes = this.buildTaintGraph(ast);
    console.log(`[DEBUG] 📊 Built taint graph with ${taintNodes.length} nodes`);

    // Find all paths from sources to sinks
    for (const source of this.sourceDetector.getAllSources()) {
      console.log(`[DEBUG] 🔎 Looking for source: ${source.id} (${source.description})`);
      const sourceNodes = this.findSourceNodes(taintNodes, source);
      console.log(`[DEBUG] 📌 Found ${sourceNodes.length} source nodes for ${source.id}`);
      
      for (const sourceNode of sourceNodes) {
        console.log(`[DEBUG] 🎯 Analyzing source node at line ${sourceNode.location.line}`);
        
        for (const sink of this.sinkDetector.getAllSinks()) {
          console.log(`[DEBUG] 🔍 Looking for sink: ${sink.id} (${sink.description})`);
          const sinkNodes = this.findSinkNodes(taintNodes, sink);
          console.log(`[DEBUG] 📌 Found ${sinkNodes.length} sink nodes for ${sink.id}`);
          
          for (const sinkNode of sinkNodes) {
            console.log(`[DEBUG] 🎯 Analyzing sink node at line ${sinkNode.location.line}`);
            const path = this.findPath(sourceNode, sinkNode, taintNodes);
            
            if (path) {
              console.log(`[DEBUG] 🛣️ Found path from source to sink (${path.length} nodes)`);
              const sanitizationPoints = this.findSanitizationPoints(path);
              console.log(`[DEBUG] 🛡️ Found ${sanitizationPoints.length} sanitization points`);
              
              const isVulnerable = this.isPathVulnerable(path, sanitizationPoints);
              console.log(`[DEBUG] ⚠️ Path is ${isVulnerable ? 'vulnerable' : 'safe'}`);
              
              paths.push({
                source,
                sink,
                path,
                isVulnerable,
                sanitizationPoints
              });
            }
          }
        }
      }
    }

    console.log(`[DEBUG] ✅ Taint flow analysis complete. Found ${paths.length} paths`);
    return paths;
  }

  private buildTaintGraph(ast: any): TaintNode[] {
    console.log('[DEBUG] 🏗️ Building taint graph');
    const nodes: TaintNode[] = [];
    
    const traverse = (node: any, parent: TaintNode | null = null) => {
      if (!node) return;

      // Get and validate positions
      const startLine = node.loc?.start.line || 1;
      const startCol = node.loc?.start.column || 1;
      const endLine = node.loc?.end.line || startLine;
      const endCol = node.loc?.end.column || startCol;

      // Ensure end position is valid
      const finalEndLine = endLine < startLine ? startLine : endLine;
      const finalEndCol = (endLine === startLine && endCol < startCol) ? startCol : endCol;

      // Create taint node with validated positions
      const taintNode: TaintNode = {
        id: `${node.type}-${startLine}-${startCol}`,
        type: node.type,
        tainted: false,
        sanitizers: [],
        children: [],
        location: {
          line: startLine,
          column: startCol
        },
        named: node.named,
        loc: {
          start: { line: startLine, column: startCol },
          end: { line: finalEndLine, column: finalEndCol }
        }
      };

      // Check if node is a source
      const source = this.sourceDetector.detectSource(node);
      if (source) {
        console.log(`[DEBUG] 📥 Found source at line ${taintNode.location.line}: ${source.id}`);
        taintNode.source = source;
        taintNode.tainted = true;
      }

      // Check if node is a sanitizer
      /*const sanitizer = this.sanitizerDetector.detectSanitizer(node, content);
      if (sanitizer) {
        console.log(`[DEBUG] 🛡️ Found sanitizer at line ${taintNode.location.line}: ${sanitizer.id}`);
        taintNode.sanitizers.push(sanitizer);
      }*/

      nodes.push(taintNode);

      // Handle all children of the node
      const children = node.children || [];
      if (Array.isArray(children)) {
        children.forEach((child: any) => {
          if (child && typeof child === 'object') {
            traverse(child, taintNode);
            if (nodes.length > 0) {
              taintNode.children.push(nodes[nodes.length - 1]);
            }
          }
        });
      }
    };

    traverse(ast);
    return nodes;
  }

  private findSourceNodes(nodes: TaintNode[], source: Source): TaintNode[] {
    return nodes.filter(node => node.source?.id === source.id);
  }

  private findSinkNodes(nodes: TaintNode[], sink: Sink): TaintNode[] {
    return nodes.filter(node => {
      // Check for sink patterns in the node's type and structure
      if (node.type === 'call' || node.type === 'expression_statement') {
        const nodeText = this.getNodeText(node);
        return new RegExp(sink.pattern).test(nodeText);
      }
      return false;
    });
  }

  private getNodeText(node: TaintNode): string {
    // Extract text content from the node based on its structure
    if (node.type === 'call') {
      const identifier = node.children.find(child => child.type === 'identifier');
      return identifier ? identifier.type : '';
    }
    return node.type;
  }

  private findPath(source: TaintNode, sink: TaintNode, nodes: TaintNode[]): TaintNode[] | null {
    console.log(`[DEBUG] 🔍 Finding path from source (line ${source.location.line}) to sink (line ${sink.location.line})`);
    const visited = new Set<string>();
    const path: TaintNode[] = [];

    const dfs = (current: TaintNode): boolean => {
      if (current.id === sink.id) {
        path.push(current);
        return true;
      }

      if (visited.has(current.id)) return false;
      visited.add(current.id);

      for (const child of current.children) {
        if (dfs(child)) {
          path.unshift(current);
          return true;
        }
      }

      return false;
    };

    const result = dfs(source);
    if (result) {
      console.log(`[DEBUG] 🛣️ Found path with ${path.length} nodes`);
      path.forEach((node, index) => {
        console.log(`[DEBUG] 📍 Path node ${index + 1}: ${node.type} at line ${node.location.line}`);
      });
    } else {
      console.log('[DEBUG] ❌ No path found');
    }

    return result ? path : null;
  }

  private findSanitizationPoints(path: TaintNode[]): Sanitizer[] {
    const sanitizers: Sanitizer[] = [];
    for (const node of path) {
      sanitizers.push(...node.sanitizers);
    }
    return sanitizers;
  }

  private isPathVulnerable(path: TaintNode[], sanitizers: Sanitizer[]): boolean {
    const effectiveness = this.sanitizerDetector.calculateSanitizationEffectiveness(sanitizers);
    console.log(`[DEBUG] 🛡️ Sanitization effectiveness: ${effectiveness * 100}%`);
    return effectiveness < 0.9; // Consider path vulnerable if sanitization effectiveness is less than 90%
  }

  public getVulnerabilitiesFromPaths(paths: TaintPath[]): Vulnerability[] {
    return paths
      .filter(path => path.isVulnerable)
      .map(path => ({
        id: `${path.source.id}-${path.sink.id}-${path.path[0].location.line}`,
        type: VulnerabilityType.GENERIC,
        severity: Severity.HIGH,
        message: `Potential taint flow from ${path.source.description} to ${path.sink.description}`,
        file: '', // This should be set by the caller
        line: path.path[0].location.line,
        column: path.path[0].location.column,
        rule: path.sink.id,
        description: `Data flows from ${path.source.description} to ${path.sink.description} without proper sanitization`,
        recommendation: this.getRecommendation(VulnerabilityType.GENERIC)
      }));
  }

  private getRecommendation(type: VulnerabilityType): string {
    switch (type) {
      case VulnerabilityType.GENERIC:
        return 'Consider implementing proper input validation and sanitization at the source or using a safe alternative to the sink function.';
      default:
        return 'Review the code for potential security issues.';
    }
  }
} 
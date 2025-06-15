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

  constructor() {
    this.sourceDetector = new SourceDetector();
    this.sinkDetector = new SinkDetector();
    this.sanitizerDetector = new SanitizerDetector();
  }

  public analyzeTaintFlow(ast: any, content: string): TaintPath[] {
    console.log('[DEBUG] 🔍 Starting taint flow analysis');
    const paths: TaintPath[] = [];
    const taintNodes = this.buildTaintGraph(ast, content);
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

  private buildTaintGraph(ast: any, content: string): TaintNode[] {
    console.log('[DEBUG] 🏗️ Building taint graph');
    const nodes: TaintNode[] = [];
    
    const traverse = (node: any, parent: TaintNode | null = null) => {
      if (!node) return;

      const taintNode: TaintNode = {
        id: `${node.type}-${node.loc?.start.line}-${node.loc?.start.column}`,
        type: node.type,
        tainted: false,
        sanitizers: [],
        children: [],
        location: {
          line: node.loc?.start.line || 1,
          column: node.loc?.start.column || 1
        }
      };

      // Check if node is a source
      const source = this.sourceDetector.detectSource(node, content);
      if (source) {
        console.log(`[DEBUG] 📥 Found source at line ${taintNode.location.line}: ${source.id}`);
        taintNode.source = source;
        taintNode.tainted = true;
      }

      // Check if node is a sanitizer
      const sanitizer = this.sanitizerDetector.detectSanitizer(node, content);
      if (sanitizer) {
        console.log(`[DEBUG] 🛡️ Found sanitizer at line ${taintNode.location.line}: ${sanitizer.id}`);
        taintNode.sanitizers.push(sanitizer);
      }

      nodes.push(taintNode);

      // Recursively process children
      for (const key in node) {
        if (node[key] && typeof node[key] === 'object') {
          if (Array.isArray(node[key])) {
            node[key].forEach((child: any) => traverse(child, taintNode));
          } else {
            traverse(node[key], taintNode);
          }
        }
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
      const nodeText = this.getNodeText(node);
      return new RegExp(sink.pattern).test(nodeText);
    });
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

  private getNodeText(node: TaintNode): string {
    // This is a placeholder - in a real implementation, you would need to
    // store and retrieve the actual text content of the node
    return '';
  }

  public getVulnerabilitiesFromPaths(paths: TaintPath[]): Vulnerability[] {
    console.log(`[DEBUG] 📊 Converting ${paths.length} paths to vulnerabilities`);
    return paths
      .filter(path => path.isVulnerable)
      .map(path => {
        console.log(`[DEBUG] ⚠️ Creating vulnerability for path from ${path.source.id} to ${path.sink.id}`);
        return {
          id: `${path.source.id}-${path.sink.id}-${path.path[0].location.line}`,
          type: path.sink.vulnerabilityType,
          severity: path.sink.severity,
          message: `Potential ${path.sink.vulnerabilityType} vulnerability: ${path.source.description} flows to ${path.sink.description}`,
          file: '', // This should be set by the caller
          line: path.path[0].location.line,
          column: path.path[0].location.column,
          rule: path.sink.id,
          description: `Data flows from ${path.source.description} to ${path.sink.description} without proper sanitization`,
          recommendation: this.getRecommendation(path.sink.vulnerabilityType)
        };
      });
  }

  private getRecommendation(type: VulnerabilityType): string {
    const recommendations: Record<VulnerabilityType, string> = {
      [VulnerabilityType.SQL_INJECTION]: 'Use parameterized queries or an ORM',
      [VulnerabilityType.COMMAND_INJECTION]: 'Avoid using shell=True and validate/sanitize input',
      [VulnerabilityType.PATH_TRAVERSAL]: 'Validate and sanitize file paths',
      [VulnerabilityType.INSECURE_DESERIALIZATION]: 'Use safe deserialization methods or validate input',
      [VulnerabilityType.HARDCODED_SECRET]: 'Use environment variables or secure secret management',
      [VulnerabilityType.INSECURE_PERMISSIONS]: 'Use more restrictive file permissions',
      [VulnerabilityType.INSECURE_DIRECT_OBJECT_REFERENCE]: 'Implement proper access controls',
      [VulnerabilityType.XSS]: 'Sanitize user input and use proper output encoding',
      [VulnerabilityType.WEAK_CRYPTO]: 'Use strong cryptographic algorithms and proper key management',
      [VulnerabilityType.INSECURE_COMMUNICATION]: 'Use secure communication protocols (HTTPS, TLS)',
      [VulnerabilityType.CSRF]: 'Implement CSRF tokens and validate requests',
      [VulnerabilityType.INSECURE_RANDOM]: 'Use cryptographically secure random number generators',
      [VulnerabilityType.AUTHORIZATION]: 'Implement proper authorization checks',
      [VulnerabilityType.AUTHENTICATION]: 'Use secure authentication methods',
      [VulnerabilityType.IDOR]: 'Implement proper access controls and object reference validation',
      [VulnerabilityType.GENERIC]: 'Review and fix the identified security issue'
    };
    return recommendations[type] || recommendations[VulnerabilityType.GENERIC];
  }
} 
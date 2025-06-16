import { Vulnerability } from '../types';
import { ASTParser } from '../parser/ASTParser';
import { TaintAnalyzer } from '../analysis/taint/TaintAnalyzer';
import { PatternMatcher } from '../analysis/patternMatchers/PatternMatcher';
import { SourceDetector } from '../analysis/detectors/SourceDetector';
import { SinkDetector } from '../analysis/detectors/SinkDetector';
import { SanitizerDetector } from '../analysis/detectors/SanitizerDetector';
import { Source } from '../analysis/detectors/SourceDetector';
import { Sink } from '../analysis/detectors/SinkDetector';
import { Sanitizer } from '../analysis/detectors/SanitizerDetector';
import * as vscode from 'vscode';

export interface AnalysisResult {
  vulnerabilities: Vulnerability[];
  sources: (Source & { line: number; column: number; endLine: number; endColumn: number })[];
  sinks: (Sink & { line: number; column: number; endLine: number; endColumn: number })[];
  sanitizers: (Sanitizer & { line: number; column: number; endLine: number; endColumn: number })[];
}

export class SecurityRuleEngine {
  private astParser: ASTParser;
  private taintAnalyzer: TaintAnalyzer;
  private patternMatcher: PatternMatcher;
  private sourceDetector: SourceDetector;
  private sinkDetector: SinkDetector;
  private sanitizerDetector: SanitizerDetector;

  constructor() {
    this.astParser = new ASTParser();
    this.taintAnalyzer = new TaintAnalyzer();
    this.patternMatcher = new PatternMatcher();
    this.sourceDetector = new SourceDetector();
    this.sinkDetector = new SinkDetector();
    this.sanitizerDetector = new SanitizerDetector();
  }

  public analyzeFile(ast: any, languageId: string, file: string, content: string): AnalysisResult {
    try {
      console.log(`[DEBUG] 🔍 Starting security analysis for file: ${file}`);
      console.log(`[DEBUG] 📄 Language: ${languageId}`);
      
      // Detect sources, sinks, and sanitizers by traversing the AST
      console.log('[DEBUG] 🔍 Detecting sources, sinks, and sanitizers');
      const detectedSources: (Source & { line: number; column: number; endLine: number; endColumn: number })[] = [];
      const detectedSinks: (Sink & { line: number; column: number; endLine: number; endColumn: number })[] = [];
      const detectedSanitizers: (Sanitizer & { line: number; column: number; endLine: number; endColumn: number })[] = [];
      
      const traverse = (node: any) => {
        if (!node) return;
        
        // Check for sources
        const source = this.sourceDetector.detectSource(node, content);
        if (source) {
          detectedSources.push({
            ...source,
            line: node.loc?.start?.line || 1,
            column: node.loc?.start?.column || 0,
            endLine: node.loc?.end?.line || node.loc?.start?.line || 1,
            endColumn: node.loc?.end?.column || (node.loc?.start?.column || 0) + 10
          });
        }
        
        // Check for sinks
        const sink = this.sinkDetector.detectSink(node, content);
        if (sink) {
          detectedSinks.push({
            ...sink,
            line: node.loc?.start?.line || 1,
            column: node.loc?.start?.column || 0,
            endLine: node.loc?.end?.line || node.loc?.start?.line || 1,
            endColumn: node.loc?.end?.column || (node.loc?.start?.column || 0) + 10
          });
        }
        
        // Check for sanitizers
        const sanitizer = this.sanitizerDetector.detectSanitizer(node, content);
        if (sanitizer) {
          detectedSanitizers.push({
            ...sanitizer,
            line: node.loc?.start?.line || 1,
            column: node.loc?.start?.column || 0,
            endLine: node.loc?.end?.line || node.loc?.start?.line || 1,
            endColumn: node.loc?.end?.column || (node.loc?.start?.column || 0) + 10
          });
        }
        
        // Recursively traverse children
        if (node.children) {
          for (const child of node.children) {
            traverse(child);
          }
        }
      };
      
      traverse(ast);
      
      console.log(`[DEBUG] 📌 Found ${detectedSources.length} sources:`);
      detectedSources.forEach((source, index) => {
        console.log(`[DEBUG]   ${index + 1}. ${source.type} - ${source.description} (Line: ${source.line}, Column: ${source.column})`);
      });
      
      console.log(`[DEBUG] 📌 Found ${detectedSinks.length} sinks:`);
      detectedSinks.forEach((sink, index) => {
        console.log(`[DEBUG]   ${index + 1}. ${sink.type} - ${sink.description} (Line: ${sink.line}, Column: ${sink.column})`);
      });
      
      console.log(`[DEBUG] 📌 Found ${detectedSanitizers.length} sanitizers:`);
      detectedSanitizers.forEach((sanitizer, index) => {
        console.log(`[DEBUG]   ${index + 1}. ${sanitizer.type} - ${sanitizer.description} (Line: ${sanitizer.line}, Column: ${sanitizer.column})`);
      });
      
      // Pattern-based analysis
      console.log('[DEBUG] 📊 Running pattern-based analysis');
      const patternVulnerabilities = this.patternMatcher.matchPatterns(content);
      console.log(`[DEBUG] 📌 Found ${patternVulnerabilities.length} pattern-based vulnerabilities`);

      // Set file path for pattern vulnerabilities
      patternVulnerabilities.forEach(vuln => {
        vuln.file = file;
      });

      console.log(`[DEBUG] ✅ Analysis complete. Found ${patternVulnerabilities.length} vulnerabilities, ${detectedSources.length} sources, ${detectedSinks.length} sinks, ${detectedSanitizers.length} sanitizers`);

      return {
        vulnerabilities: patternVulnerabilities,
        sources: detectedSources,
        sinks: detectedSinks,
        sanitizers: detectedSanitizers
      };
    } catch (error) {
      console.error(`[ERROR] Failed to analyze file ${file}:`, error);
      vscode.window.showErrorMessage(`Failed to analyze file: ${file}`);
      return {
        vulnerabilities: [],
        sources: [],
        sinks: [],
        sanitizers: []
      };
    }
  }

  public reloadRules(): void {
    try {
      console.log('[DEBUG] 🔄 Reloading all security rules');
      this.patternMatcher.reloadRules();
      this.sourceDetector.reloadRules();
      this.sinkDetector.reloadRules();
      this.sanitizerDetector.reloadRules();
      console.log('[DEBUG] ✅ Rules reloaded successfully');
    } catch (error) {
      console.error('[ERROR] Failed to reload rules:', error);
      vscode.window.showErrorMessage('Failed to reload security rules');
    }
  }

  public getSourceDetector(): SourceDetector {
    return this.sourceDetector;
  }

  public getSinkDetector(): SinkDetector {
    return this.sinkDetector;
  }

  public getSanitizerDetector(): SanitizerDetector {
    return this.sanitizerDetector;
  }

  public getPatternMatcher(): PatternMatcher {
    return this.patternMatcher;
  }

  public getTaintAnalyzer(): TaintAnalyzer {
    return this.taintAnalyzer;
  }
} 
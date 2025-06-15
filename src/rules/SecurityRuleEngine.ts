import { Vulnerability } from '../types';
import { ASTParser } from '../parser/ASTParser';
import { TaintAnalyzer } from '../analysis/taint/TaintAnalyzer';
import { PatternMatcher } from '../analysis/patternMatchers/PatternMatcher';
import { SourceDetector } from '../analysis/detectors/SourceDetector';
import { SinkDetector } from '../analysis/detectors/SinkDetector';
import { SanitizerDetector } from '../analysis/detectors/SanitizerDetector';
import * as vscode from 'vscode';

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

  public analyzeFile(content: string, languageId: string, file: string): Vulnerability[] {
    try {
      console.log(`[DEBUG] 🔍 Starting security analysis for file: ${file}`);
      console.log(`[DEBUG] 📄 Language: ${languageId}`);
      
      // Pattern-based analysis
      console.log('[DEBUG] 📊 Running pattern-based analysis');
      const patternVulnerabilities = this.patternMatcher.matchPatterns(content);
      console.log(`[DEBUG] 📌 Found ${patternVulnerabilities.length} pattern-based vulnerabilities`);

      // Set file path for pattern vulnerabilities
      patternVulnerabilities.forEach(vuln => {
        vuln.file = file;
      });

      // Taint analysis
      console.log('[DEBUG] 🔄 Running taint analysis');
      const taintPaths = this.taintAnalyzer.analyzeTaintFlow(content, file);
      const taintVulnerabilities = this.taintAnalyzer.getVulnerabilitiesFromPaths(taintPaths);
      console.log(`[DEBUG] 📌 Found ${taintVulnerabilities.length} taint-based vulnerabilities`);

      // Set file path for taint vulnerabilities
      taintVulnerabilities.forEach(vuln => {
        vuln.file = file;
      });

      // Combine results
      const allVulnerabilities = [...patternVulnerabilities, ...taintVulnerabilities];
      console.log(`[DEBUG] ✅ Analysis complete. Total vulnerabilities found: ${allVulnerabilities.length}`);

      return allVulnerabilities;
    } catch (error) {
      console.error(`[ERROR] Failed to analyze file ${file}:`, error);
      vscode.window.showErrorMessage(`Failed to analyze file: ${file}`);
      return [];
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
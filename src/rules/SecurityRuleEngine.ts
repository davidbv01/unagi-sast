import { Vulnerability } from '../types';
import { ASTParser } from '../parser/ASTParser';
import { TaintAnalyzer } from '../analysis/taint/TaintAnalyzer';
import { PatternMatcher } from '../analysis/patternMatchers/PatternMatcher';
import { SourceDetector } from '../analysis/detectors/SourceDetector';
import { SinkDetector } from '../analysis/detectors/SinkDetector';
import { SanitizerDetector } from '../analysis/detectors/SanitizerDetector';

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

  public async analyzeFile(content: string, file: string, languageId: string): Promise<Vulnerability[]> {
    const vulnerabilities: Vulnerability[] = [];

    try {
      // 1. Pattern-based analysis
      const patternVulnerabilities = this.patternMatcher.findPatterns(content, file);
      vulnerabilities.push(...patternVulnerabilities);

      // 2. AST-based analysis (for supported languages)
      if (languageId === 'python') {
        const ast = await this.astParser.parse(content, languageId, file);
        if (ast) {
          // 2.1 Taint analysis
          const taintPaths = this.taintAnalyzer.analyzeTaintFlow(ast, content);
          const taintVulnerabilities = this.taintAnalyzer.getVulnerabilitiesFromPaths(taintPaths);
          
          // Add file information to vulnerabilities
          taintVulnerabilities.forEach(v => v.file = file);
          vulnerabilities.push(...taintVulnerabilities);
        }
      }

      // 3. Remove duplicates (same vulnerability type at same location)
      return this.removeDuplicates(vulnerabilities);
    } catch (error) {
      console.error(`Error analyzing file ${file}:`, error);
      return vulnerabilities;
    }
  }

  private removeDuplicates(vulnerabilities: Vulnerability[]): Vulnerability[] {
    const seen = new Set<string>();
    return vulnerabilities.filter(v => {
      const key = `${v.type}-${v.file}-${v.line}-${v.column}`;
      if (seen.has(key)) {
        return false;
      }
      seen.add(key);
      return true;
    });
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
import { DataFlowVulnerability, PatternVulnerability, AstNode, AiAnalysisRequest, AnalysisResult, SymbolTableEntry } from '../types';
import { PatternMatcher } from '../analysis/patternMatchers/PatternMatcher';
import { SinkDetector, SanitizerDetector } from '../analysis/detectors/index';
import { AiEngine } from '../ai';
import { DataFlowGraph } from '../analysis/DataFlowGraph';  
import * as vscode from 'vscode';
import * as path from 'path';
import * as fs from 'fs';

/**
 * Encapsulates all security analysis logic for workspace-wide scanning.
 */
export class WorkspaceSecurityRuleEngine {
  private patternMatcher: PatternMatcher;
  private sinkDetector: SinkDetector;
  private sanitizerDetector: SanitizerDetector;
  private aiEngine?: AiEngine;
  private skipAiAnalysis: boolean;

  /**
   * Creates a new WorkspaceSecurityRuleEngine instance.
   * 
   * @param apiKey - OpenAI API key for AI-powered analysis (optional)
   * @param skipAiAnalysis - Flag to skip AI analysis (useful for MCP calls)
   */
  constructor(apiKey: string, skipAiAnalysis: boolean = false) {
    this.patternMatcher = new PatternMatcher();
    this.sinkDetector = new SinkDetector();
    this.sanitizerDetector = new SanitizerDetector();
    this.skipAiAnalysis = skipAiAnalysis;
    if (apiKey && !skipAiAnalysis) {
      this.aiEngine = new AiEngine(apiKey);
    }
  }

  /**
   * Updates the AI engine with a new API key.
   * @param apiKey The OpenAI API key, or null to disable AI analysis
   */
  public updateAiEngine(apiKey: string | null): void {
    if (apiKey && apiKey.trim() !== '') {
      this.aiEngine = new AiEngine(apiKey);
      console.log('[INFO] AI Engine initialized for workspace analysis');
    } else {
      this.aiEngine = undefined;
      console.log('[INFO] AI Engine disabled for workspace analysis (no API key)');
    }
  }

  /**
   * Applies AI analysis to vulnerabilities and populates their ai property.
   * @param vulnerabilities Array of vulnerabilities to analyze (pattern and/or data flow)
   * @param asts Map of AST nodes for code extraction context
   * @param workspaceRoot The workspace root path
   * @param vulnerabilityType Type description for logging (e.g., "pattern", "data flow")
   * @returns Promise<void> - Modifies vulnerabilities in place by adding ai property
   */
  private async applyAiAnalysis(
    vulnerabilities: Array<PatternVulnerability | DataFlowVulnerability>,
    asts: Map<string, AstNode>,
    workspaceRoot: string,
    vulnerabilityType: string
  ): Promise<void> {
    if (!this.aiEngine || vulnerabilities.length === 0) {
      return;
    }

    try {
      // Build cross-file context maps for AI analysis
      const filesContent = new Map<string, string>();
      const filesSymbols = new Map<string, SymbolTableEntry[]>();
      
      for (const [relativePath, ast] of asts) {
        const absolutePath = path.isAbsolute(relativePath) ? relativePath : path.join(workspaceRoot, relativePath);
        filesContent.set(absolutePath, ast.content);
        filesSymbols.set(absolutePath, ast.symbols);
      }

      // Group vulnerabilities by file for AI analysis
      const vulnerabilityByFile = new Map<string, Array<PatternVulnerability | DataFlowVulnerability>>();
      
      for (const vuln of vulnerabilities) {
        const filePath = vuln.filePath;
        if (!vulnerabilityByFile.has(filePath)) {
          vulnerabilityByFile.set(filePath, []);
        }
        vulnerabilityByFile.get(filePath)!.push(vuln);
      }

      // Process each file's vulnerabilities
      const aiRequests: AiAnalysisRequest[] = [];
      for (const [filePath, fileVulns] of vulnerabilityByFile) {
        const relativePath = vscode.workspace.asRelativePath(filePath);
        const ast = asts.get(relativePath);
        
        if (!ast) {
          console.warn(`[WARNING] No AST found for file ${filePath}, skipping AI analysis`);
          continue;
        }

        // Split vulnerabilities based on vulnerability type
        const patternVulnerabilities = vulnerabilityType === 'pattern' ? fileVulns as PatternVulnerability[] : [];
        const dataFlowVulnerabilities = vulnerabilityType === 'data flow' ? fileVulns as DataFlowVulnerability[] : [];

        // Check if any vulnerabilities in this file are cross-file
        const hasCrossFileVulns = dataFlowVulnerabilities.some(vuln => vuln.isCrossFile);

        const aiRequest: AiAnalysisRequest = {
          file: filePath,
          content: ast.content,
          symbols: ast.symbols,
          patternVulnerabilities,
          dataFlowVulnerabilities,
          context: {
            language: "python", // TODO: get language from file extension
            additionalInfo: `Workspace analysis detected ${fileVulns.length} potential ${vulnerabilityType} vulnerabilities`,
            // Include cross-file context maps if there are cross-file vulnerabilities
            ...(hasCrossFileVulns && {
              filesContent,
              filesSymbols
            })
          }
        };

        aiRequests.push(aiRequest);
      }

      if (aiRequests.length === 0) {
        return;
      }

      const aiAnalysisResults = await this.aiEngine.analyzeVulnerabilities(aiRequests);
      
      // Apply AI analysis results to all vulnerabilities
      vulnerabilities.forEach(vuln => {
        // Find the corresponding AI result for this vulnerability
        const aiResult = aiAnalysisResults.find(result => 
          result.verifiedVulnerabilities.some((v: { originalVulnerability: { id: string } }) => 
            v.originalVulnerability.id === vuln.id
          )
        );

        if (aiResult) {
          const verifiedResult = aiResult.verifiedVulnerabilities.find((v: { originalVulnerability: { id: string } }) => 
            v.originalVulnerability.id === vuln.id
          );
          
          if (verifiedResult) {
            // Always populate the ai property, regardless of whether vulnerability is confirmed or false positive
            (vuln as any).ai = {
              confidenceScore: verifiedResult.aiAnalysis.confidenceScore,
              shortExplanation: verifiedResult.aiAnalysis.shortExplanation,
              exploitExample: verifiedResult.aiAnalysis.exploitExample,
              remediation: verifiedResult.aiAnalysis.remediation
            };

            // Update the isVulnerable field based on AI analysis for all vulnerability types
            vuln.isVulnerable = verifiedResult.isConfirmed;
          }
        }
      });

    } catch (aiError) {
      console.error(`[ERROR] AI analysis failed for ${vulnerabilityType} vulnerabilities:`, aiError);
      vscode.window.showWarningMessage(`AI analysis failed for ${vulnerabilityType} vulnerabilities`);
    }
  }

  /**
   * Performs complete workspace-wide security analysis including cross-file data flow.
   * @param asts Map of parsed ASTs for all files
   * @param symbolTable Global symbol table
   * @param graphs Map of data flow graphs for all files  
   * @param workspaceRoot The workspace root directory
   * @returns Complete workspace analysis results
   */
  public async analyzeWorkspace(
    asts: Map<string, AstNode>,
    symbolTable: Map<string, SymbolTableEntry>,
    graphs: Map<string, DataFlowGraph>,
    workspaceRoot: string
  ): Promise<AnalysisResult> {
    try {
      console.log('🔍 Starting workspace-wide security analysis...');

      // Step 1: Analyze each file individually for in-file vulnerabilities
      const allPatternVulnerabilities: PatternVulnerability[] = [];
      const allDataFlowVulnerabilities: DataFlowVulnerability[] = [];

      for (const [filePath, dfg] of graphs) {
        try {
          const ast = asts.get(filePath);
          if (!ast) { continue; }

          const absolutePath = path.isAbsolute(filePath) ? filePath : path.join(workspaceRoot, filePath);
          const content = fs.readFileSync(absolutePath, 'utf8');
          
          // Pattern-based analysis
          const patternVulnerabilities = this.patternMatcher.matchPatterns(content,filePath);
          patternVulnerabilities.forEach(vuln => {
            vuln.filePath = absolutePath;
          });
          allPatternVulnerabilities.push(...patternVulnerabilities);

          // Data flow analysis for this file
          const fileDataFlowVulnerabilities = dfg.performCompleteAnalysis(ast);
          // Ensure all data flow vulnerabilities have the correct absolute file path
          fileDataFlowVulnerabilities.forEach(vuln => {
            vuln.filePath = absolutePath;
          });
          allDataFlowVulnerabilities.push(...fileDataFlowVulnerabilities);
          
        } catch (error) {
          console.error(`[ERROR] Failed to analyze file ${filePath}:`, error);
        }
      }

      // Step 2: Perform cross-file data flow analysis
      const crossFileVulnerabilities = this.analyzeCrossFileDataFlow(
        asts, 
        symbolTable, 
        graphs, 
        workspaceRoot
      );
      allDataFlowVulnerabilities.push(...crossFileVulnerabilities);

      // Step 3: Deduplicate vulnerabilities
      const deduplicatedDataFlowVulnerabilities = this.deduplicateVulnerabilities(allDataFlowVulnerabilities);

      // Step 4: Apply AI analysis if available and not skipped
      if (this.skipAiAnalysis) {
        console.log('[INFO] Skipping AI analysis (MCP mode)');
      } else if (!this.aiEngine) {
        console.warn('[WARNING] No API key provided for AI analysis. Skipping AI-powered verification');
        vscode.window.showWarningMessage('No API key provided for AI analysis. Skipping AI-powered verification');
      } else {
        // Apply AI analysis to both pattern and data flow vulnerabilities
        await Promise.all([
          this.applyAiAnalysis(allPatternVulnerabilities, asts, workspaceRoot, 'pattern'),
          this.applyAiAnalysis(deduplicatedDataFlowVulnerabilities, asts, workspaceRoot, 'data flow')
        ]);
      }

      console.log(`[DEBUG] 📌 Found ${allPatternVulnerabilities.length} pattern vulnerabilities and ${deduplicatedDataFlowVulnerabilities.length} data flow vulnerabilities across workspace`);

      return {
        patternVulnerabilities: allPatternVulnerabilities,
        dataFlowVulnerabilities: deduplicatedDataFlowVulnerabilities
      };

    } catch (error) {
      console.error(`[ERROR] Failed to analyze workspace:`, error);
      vscode.window.showErrorMessage('Failed to analyze workspace');
      return {
        patternVulnerabilities: [],
        dataFlowVulnerabilities: []
      };
    }
  }

  /**
   * Performs cross-file data flow analysis to detect vulnerabilities that span multiple files.
   * @param asts Map of parsed ASTs
   * @param symbolTable Global symbol table
   * @param graphs Map of data flow graphs
   * @param workspaceRoot Workspace root directory
   * @returns Array of cross-file data flow vulnerabilities
   */
  private analyzeCrossFileDataFlow(
    asts: Map<string, AstNode>,
    symbolTable: Map<string, SymbolTableEntry>,
    graphs: Map<string, DataFlowGraph>,
    workspaceRoot: string
  ): DataFlowVulnerability[] {
    const crossFileVulnerabilities: DataFlowVulnerability[] = [];
    let crossFileConnections = 0;

    console.log('🔗 Analyzing cross-file data flow...');

    // Propagate taint across files and analyze resulting vulnerabilities
    for (const [sourceFilePath, sourceDfg] of graphs) {
      for (const [nodeId, node] of sourceDfg.nodes) {
        if (node.tainted && node.crossFileEdge) {
          const targetFilePath = node.crossFileEdge.to;
          const functionName = node.crossFileEdge.function;
          const targetRelativePath = vscode.workspace.asRelativePath(targetFilePath);
          const targetDfg = graphs.get(targetRelativePath);
          const targetAst = asts.get(targetRelativePath);

          if (targetDfg && targetAst) {
            // Find the function symbol in the target file
            const functionSymbol =  Array.from(symbolTable.values()).find(sym =>
              sym.name === functionName && sym.type === 'function' && (sym.filePath === targetRelativePath || 
                sym.filePath === targetFilePath)
            );

            let parameterNodes: any[] = [];
            if (functionSymbol && functionSymbol.parameters) {
              // Use symbol table parameters if available
              parameterNodes = functionSymbol.parameters.map(paramName => {
                const paramNodeId = `${functionName}_${paramName}`;
                return targetDfg.nodes.get(paramNodeId);
              }).filter(Boolean);
            } else {
              // Fallback to finding parameter nodes by pattern
              parameterNodes = Array.from(targetDfg.nodes.values()).filter(n =>
                n.id.startsWith(`${functionName}_`) &&
                !n.id.includes('_return') &&
                n.symbol?.scope === functionName
              );
            }

            // Propagate taint to parameter nodes
            for (const paramNode of parameterNodes) {
              if (!paramNode.tainted) {
                paramNode.tainted = true;
                if (node.taintSources && node.taintSources.size > 0) {
                  paramNode.taintSources = new Set(node.taintSources);
                  for (const src of node.taintSources) {
                    targetDfg.propagateTaint(src);
                  }
                }
                crossFileConnections++;
              }
            }

            // Detect vulnerabilities in the target file after taint propagation
            const targetAbsolutePath = path.isAbsolute(targetFilePath) ? targetFilePath : path.join(workspaceRoot, targetRelativePath);
            const crossFileVulns = targetDfg.detectVulnerabilities(targetAbsolutePath);
            const newVulns = crossFileVulns.map(vuln => ({
              ...vuln,
              id: `cross-file-${vuln.id}`,
              message: `Cross-file vulnerability: ${vuln.message} (originated from ${sourceFilePath})`,
              isCrossFile: true
            }));
            crossFileVulnerabilities.push(...newVulns);
          }
        }
      }
    }

    console.log(`🔗 Found ${crossFileConnections} cross-file connections and ${crossFileVulnerabilities.length} cross-file vulnerabilities`);
    return crossFileVulnerabilities;
  }

  /**
   * Deduplicates DataFlowVulnerability objects by file, sink location, type, and sources.
   * @param vulns Array of vulnerabilities to deduplicate
   * @returns Deduplicated array of vulnerabilities
   */
  private deduplicateVulnerabilities(vulns: DataFlowVulnerability[]): DataFlowVulnerability[] {
    const seen = new Map<string, DataFlowVulnerability>();
    
    for (const vuln of vulns) {
      const sinkLoc = vuln.sink?.loc?.start;
      const sourcesKey = vuln.sources
        .map(s => `${s.filePath}:${s.loc?.start?.line}:${s.loc?.start?.column}`)
        .sort()
        .join('|');
      const key = `${vuln.filePath}:${sinkLoc?.line}:${sinkLoc?.column}:${vuln.type}:${sourcesKey}`;
      
      if (!seen.has(key)) {
        seen.set(key, vuln);
      } else {
        const existing = seen.get(key)!;
        // Keep the vulnerability with more sources (more comprehensive)
        if (vuln.sources.length > existing.sources.length) {
          seen.set(key, vuln);
        }
      }
    }
    
    const deduplicated = Array.from(seen.values());
    console.log(`🔧 Deduplicated ${vulns.length} vulnerabilities down to ${deduplicated.length}`);
    return deduplicated;
  }

  // --- Getters for detectors and matchers (same as SecurityRuleEngine) ---

  public getSinkDetector(): SinkDetector {
    return this.sinkDetector;
  }

  public getSanitizerDetector(): SanitizerDetector {
    return this.sanitizerDetector;
  }

  public getPatternMatcher(): PatternMatcher {
    return this.patternMatcher;
  }
} 
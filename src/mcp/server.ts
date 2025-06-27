import { McpServer, ResourceTemplate } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { z } from "zod";
import * as fs from 'fs';
import * as path from 'path';
import { ScanOrchestrator } from '../core/ScanOrchestrator';
import { OutputManager } from '../output/OutputManager';
import { ConfigurationManager } from '../config/ConfigurationManager';
import { ASTParser } from '../parser/ASTParser';
import { SecurityRuleEngine } from '../rules/SecurityRuleEngine';
import { DataFlowGraph } from '../analysis/DataFlowGraph';
import { VulnerabilityType, Severity } from '../types';

// Create an MCP server for Unagi SAST
const server = new McpServer({
  name: "unagi-sast-server",
  version: "1.0.0"
});

// Initialize components
const outputManager = new OutputManager(path.join(process.cwd(), '.unagi'));
const scanOrchestrator = new ScanOrchestrator(outputManager, process.env.OPENAI_API_KEY || '');

// Tool: Scan File for Security Vulnerabilities
server.registerTool("scan_file",
  {
    title: "Scan File for Security Vulnerabilities",
    description: "Performs static application security testing (SAST) on a file to detect vulnerabilities",
    inputSchema: {
      filePath: z.string().describe("Path to the file to scan"),
      content: z.string().optional().describe("File content (if not provided, will read from filePath)"),
      languageId: z.string().optional().describe("Programming language identifier (js, ts, py, etc.)")
    }
  },
  async ({ filePath, content, languageId }) => {
    try {
      const fileContent = content || fs.readFileSync(filePath, 'utf8');
      const language = languageId || getLanguageFromExtension(filePath);
      
      // Create a mock VS Code document-like object
      const mockDocument = {
        fileName: filePath,
        languageId: language,
        getText: () => fileContent,
        uri: { fsPath: filePath }
      };

      const result = await scanOrchestrator.scanFile(mockDocument as any);
      
      const allVulnerabilities = [
        ...result.patternVulnerabilities,
        ...result.dataFlowVulnerabilities
      ];
      
      const sources = result.dataFlowVulnerabilities.map(dfv => dfv.source);
      const sinks = result.dataFlowVulnerabilities.map(dfv => dfv.sink);
      const sanitizers = result.dataFlowVulnerabilities.flatMap(dfv => dfv.sanitizers);
      
      return {
        content: [{
          type: "text",
          text: JSON.stringify({
            summary: {
              file: result.file,
              vulnerabilitiesFound: allVulnerabilities.length,
              sourcesFound: sources.length,
              sinksFound: sinks.length,
              sanitizersFound: sanitizers.length,
              scanTime: result.scanTime,
              linesScanned: result.linesScanned,
              language: result.language
            },
            vulnerabilities: allVulnerabilities.map(v => {
              if ('line' in v && 'column' in v) {
                return {
                  id: v.id,
                  type: v.type,
                  severity: v.severity,
                  message: v.message,
                  line: v.line,
                  column: v.column,
                  rule: v.rule,
                  description: v.description,
                  recommendation: v.recommendation,
                  ai: v.ai
                };
              } else {
                return {
                  id: v.id,
                  type: v.type,
                  severity: v.severity,
                  message: v.message,
                  line: v.sink?.loc?.start?.line ?? null,
                  column: v.sink?.loc?.start?.column ?? null,
                  rule: v.rule,
                  description: v.description,
                  recommendation: v.recommendation,
                  ai: v.ai
                };
              }
            }),
            sources: sources.map(s => ({
              id: s.id,
              type: s.type,
              description: s.description,
              location: s.loc
            })),
            sinks: sinks.map(s => ({
              id: s.id,
              type: s.type,
              description: s.description,
              location: s.loc
            })),
            sanitizers: sanitizers.map(s => ({
              id: s.id,
              type: s.type,
              description: s.description,
              effectiveness: s.effectiveness,
              location: s.loc
            }))
          }, null, 2)
        }]
      };
    } catch (error) {
      return {
        content: [{
          type: "text",
          text: `Error scanning file: ${error instanceof Error ? error.message : 'Unknown error'}`
        }]
      };
    }
  }
);

// Tool: Analyze Data Flow
server.registerTool("analyze_data_flow",
  {
    title: "Analyze Data Flow",
    description: "Performs taint analysis to track data flow from sources to sinks",
    inputSchema: {
      filePath: z.string().describe("Path to the file to analyze"),
      content: z.string().optional().describe("File content (if not provided, will read from filePath)"),
      languageId: z.string().optional().describe("Programming language identifier")
    }
  },
  async ({ filePath, content, languageId }) => {
    try {
      const fileContent = content || fs.readFileSync(filePath, 'utf8');
      const language = languageId || getLanguageFromExtension(filePath);
      
      const astParser = new ASTParser();
      const ast = astParser.parse(fileContent, language, filePath);
      
      if (!ast) {
        throw new Error('Could not parse file into AST');
      }

      const dfg = DataFlowGraph.getInstance();
      dfg.reset();
      dfg.buildFromAst(ast);
      
      const dataFlowVulnerabilities = dfg.performCompleteAnalysis(ast);
      
      return {
        content: [{
          type: "text",
          text: JSON.stringify({
            summary: {
              totalNodes: dfg.nodes.size,
              vulnerabilitiesFound: dataFlowVulnerabilities.length,
              file: filePath
            },
            vulnerabilities: dataFlowVulnerabilities.map(v => ({
              id: v.id,
              type: v.type,
              severity: v.severity,
              message: v.message,
              source: {
                id: v.source.id,
                description: v.source.description,
                location: v.source.loc
              },
              sink: {
                id: v.sink.id,
                description: v.sink.description,
                location: v.sink.loc
              },
              sanitizers: v.sanitizers.map(s => ({
                id: s.id,
                description: s.description,
                effectiveness: s.effectiveness
              })),
              pathLines: v.pathLines,
              ai: v.ai
            }))
          }, null, 2)
        }]
      };
    } catch (error) {
      return {
        content: [{
          type: "text",
          text: `Error analyzing data flow: ${error instanceof Error ? error.message : 'Unknown error'}`
        }]
      };
    }
  }
);

// Tool: Configure Security Rules
server.registerTool("configure_rules",
  {
    title: "Configure Security Rules",
    description: "View or update security scanning rules configuration",
    inputSchema: {
      enabledRules: z.array(z.string()).optional().describe("Array of rule IDs to enable"),
      excludePatterns: z.array(z.string()).optional().describe("File patterns to exclude from scanning"),
      includePatterns: z.array(z.string()).optional().describe("File patterns to include in scanning"),
      minimumSeverity: z.enum(['info', 'low', 'medium', 'high', 'critical']).optional().describe("Minimum severity level to report")
    }
  },
  async ({ enabledRules, excludePatterns, includePatterns, minimumSeverity }) => {
    try {
      const configManager = ConfigurationManager.getInstance();
      const currentConfig = configManager.getScanConfiguration();
      
      // Update configuration if new values provided
      if (enabledRules !== undefined) {
        configManager.updateConfiguration('enabledRules', enabledRules);
      }
      if (excludePatterns !== undefined) {
        configManager.updateConfiguration('excludePatterns', excludePatterns);
      }
      if (includePatterns !== undefined) {
        configManager.updateConfiguration('includePatterns', includePatterns);
      }
      if (minimumSeverity !== undefined) {
        configManager.updateConfiguration('minimumSeverity', [minimumSeverity]);
      }
      
      // Refresh and return current configuration
      configManager.refresh();
      const updatedConfig = configManager.getScanConfiguration();
      
      return {
        content: [{
          type: "text",
          text: JSON.stringify({
            configuration: {
              enabledRules: updatedConfig.enabledRules,
              excludePatterns: updatedConfig.excludePatterns,
              includePatterns: updatedConfig.includePatterns,
              severityThreshold: updatedConfig.severityThreshold,
              outputFormat: updatedConfig.outputFormat
            },
            message: "Configuration updated successfully"
          }, null, 2)
        }]
      };
    } catch (error) {
      return {
        content: [{
          type: "text",
          text: `Error configuring rules: ${error instanceof Error ? error.message : 'Unknown error'}`
        }]
      };
    }
  }
);

// Tool: Generate Security Report
server.registerTool("generate_report",
  {
    title: "Generate Security Report",
    description: "Creates a comprehensive security analysis report for one or more files",
    inputSchema: {
      filePaths: z.array(z.string()).describe("Array of file paths to include in the report"),
      outputPath: z.string().optional().describe("Path where to save the report (optional)"),
      format: z.enum(['json', 'html', 'markdown']).optional().default('json').describe("Report format")
    }
  },
  async ({ filePaths, outputPath, format = 'json' }) => {
    try {
      const results = [];
      
      for (const filePath of filePaths) {
        try {
          const fileContent = fs.readFileSync(filePath, 'utf8');
          const language = getLanguageFromExtension(filePath);
          
          const mockDocument = {
            fileName: filePath,
            languageId: language,
            getText: () => fileContent,
            uri: { fsPath: filePath }
          };

          const result = await scanOrchestrator.scanFile(mockDocument as any);
          results.push(result);
        } catch (fileError) {
          results.push({
            file: filePath,
            error: `Failed to scan file: ${fileError instanceof Error ? fileError.message : 'Unknown error'}`,
            vulnerabilities: [],
            sources: [],
            sinks: [],
            sanitizers: []
          });
        }
      }
      
      const report = {
        generatedAt: new Date().toISOString(),
        summary: {
          filesScanned: results.length,
          totalVulnerabilities: results.reduce((sum, r) => sum + (('patternVulnerabilities' in r && 'dataFlowVulnerabilities' in r)
            ? ((r.patternVulnerabilities?.length || 0) + (r.dataFlowVulnerabilities?.length || 0))
            : 0), 0),
          highSeverityCount: results.reduce((sum, r) => sum + (('patternVulnerabilities' in r && 'dataFlowVulnerabilities' in r)
            ? ([...(r.patternVulnerabilities || []), ...(r.dataFlowVulnerabilities || [])].filter((v: any) => v.severity === 'high').length)
            : 0), 0),
          criticalSeverityCount: results.reduce((sum, r) => sum + (('patternVulnerabilities' in r && 'dataFlowVulnerabilities' in r)
            ? ([...(r.patternVulnerabilities || []), ...(r.dataFlowVulnerabilities || [])].filter((v: any) => v.severity === 'critical').length)
            : 0), 0)
        },
        results
      };
      
      let reportContent = '';
      
      if (format === 'json') {
        reportContent = JSON.stringify(report, null, 2);
      } else if (format === 'markdown') {
        reportContent = generateMarkdownReport(report);
      } else if (format === 'html') {
        reportContent = generateHtmlReport(report);
      }
      
      if (outputPath) {
        fs.writeFileSync(outputPath, reportContent);
        return {
          content: [{
            type: "text",
            text: `Security report generated and saved to: ${outputPath}`
          }]
        };
      } else {
        return {
          content: [{
            type: "text",
            text: reportContent
          }]
        };
      }
    } catch (error) {
      return {
        content: [{
          type: "text",
          text: `Error generating report: ${error instanceof Error ? error.message : 'Unknown error'}`
        }]
      };
    }
  }
);

// Tool: Verify Vulnerability with AI
server.registerTool("verify_vulnerability_ai",
  {
    title: "Verify Vulnerability with AI",
    description: "Uses AI to verify and analyze detected vulnerabilities for false positives",
    inputSchema: {
      filePath: z.string().describe("Path to the file containing the vulnerability"),
      vulnerabilityId: z.string().describe("ID of the vulnerability to verify"),
      apiKey: z.string().optional().describe("OpenAI API key (if not set in environment)")
    }
  },
  async ({ filePath, vulnerabilityId, apiKey }) => {
    try {
      const envApiKey = apiKey || process.env.OPENAI_API_KEY;
      if (!envApiKey) {
        return {
          content: [{
            type: "text",
            text: "Error: OpenAI API key not provided. Set OPENAI_API_KEY environment variable or pass apiKey parameter."
          }]
        };
      }
      
      // Create a new security rule engine with API key
      const ruleEngine = new SecurityRuleEngine(envApiKey);
      const fileContent = fs.readFileSync(filePath, 'utf8');
      const language = getLanguageFromExtension(filePath);
      
      const astParser = new ASTParser();
      const ast = astParser.parse(fileContent, language, filePath);
      
      if (!ast) {
        throw new Error('Could not parse file into AST');
      }

      const dfg = DataFlowGraph.getInstance();
      dfg.reset();
      dfg.buildFromAst(ast);
      
      const analysisResult = await ruleEngine.analyzeFile(ast, dfg, language, filePath, fileContent);
      
      // Find the specific vulnerability
      const vulnerability = [...analysisResult.patternVulnerabilities, ...analysisResult.dataFlowVulnerabilities]
        .find(v => v.id === vulnerabilityId);
        
      if (!vulnerability) {
        return {
          content: [{
            type: "text",
            text: `Vulnerability with ID '${vulnerabilityId}' not found in file '${filePath}'`
          }]
        };
      }
      
      return {
        content: [{
          type: "text",
          text: JSON.stringify({
            vulnerability,
            aiAnalysis: vulnerability.ai || null,
            verificationStatus: vulnerability.ai ? 'verified' : 'not_verified'
          }, null, 2)
        }]
      };
    } catch (error) {
      return {
        content: [{
          type: "text",
          text: `Error verifying vulnerability: ${error instanceof Error ? error.message : 'Unknown error'}`
        }]
      };
    }
  }
);

// Resource: Security Rules Documentation
server.registerResource(
  "security_rules",
  new ResourceTemplate("security_rules://{ruleType}", { list: undefined }),
  {
    title: "Security Rules Documentation",
    description: "Documentation for available security rules and patterns"
  },
  async (uri: any, request: any) => {
    const ruleType = request.params?.ruleType || 'list';
    const ruleTypes = {
      'sources': 'Data sources (user input points)',
      'sinks': 'Data sinks (potentially dangerous operations)',
      'sanitizers': 'Data sanitizers (input validation/cleaning)',
      'patterns': 'Pattern-based vulnerability detection rules'
    };
    
    if (ruleType === 'list') {
      return {
        contents: [{
          uri: uri.href,
          text: JSON.stringify({
            availableRuleTypes: ruleTypes,
            vulnerabilityTypes: Object.values(VulnerabilityType),
            severityLevels: Object.values(Severity)
          }, null, 2)
        }]
      };
    }
    
    return {
      contents: [{
        uri: uri.href,
        text: `Security Rule Type: ${ruleType}\nDescription: ${ruleTypes[ruleType as keyof typeof ruleTypes] || 'Unknown rule type'}`
      }]
    };
  }
);

// Utility functions
function getLanguageFromExtension(filePath: string): string {
  const ext = path.extname(filePath).toLowerCase();
  const langMap: { [key: string]: string } = {
    '.js': 'javascript',
    '.jsx': 'javascriptreact',
    '.ts': 'typescript',
    '.tsx': 'typescriptreact',
    '.py': 'python',
    '.java': 'java',
    '.php': 'php',
    '.c': 'c',
    '.cpp': 'cpp',
    '.cs': 'csharp',
    '.go': 'go',
    '.rb': 'ruby',
    '.rs': 'rust'
  };
  return langMap[ext] || 'plaintext';
}

function generateMarkdownReport(report: any): string {
  let md = `# Security Analysis Report\n\n`;
  md += `**Generated:** ${report.generatedAt}\n\n`;
  md += `## Summary\n`;
  md += `- Files Scanned: ${report.summary.filesScanned}\n`;
  md += `- Total Vulnerabilities: ${report.summary.totalVulnerabilities}\n`;
  md += `- High Severity: ${report.summary.highSeverityCount}\n`;
  md += `- Critical Severity: ${report.summary.criticalSeverityCount}\n\n`;
  
  report.results.forEach((result: any, index: number) => {
    md += `## File ${index + 1}: ${result.file}\n\n`;
    if (result.error) {
      md += `**Error:** ${result.error}\n\n`;
    } else {
      md += `**Vulnerabilities Found:** ${result.vulnerabilities.length}\n\n`;
      result.vulnerabilities.forEach((vuln: any, vIndex: number) => {
        md += `### Vulnerability ${vIndex + 1}\n`;
        md += `- **Type:** ${vuln.type}\n`;
        md += `- **Severity:** ${vuln.severity}\n`;
        md += `- **Line:** ${vuln.line}\n`;
        md += `- **Message:** ${vuln.message}\n`;
        md += `- **Recommendation:** ${vuln.recommendation}\n\n`;
      });
    }
  });
  
  return md;
}

function generateHtmlReport(report: any): string {
  let html = `
<!DOCTYPE html>
<html>
<head>
    <title>Security Analysis Report</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 40px; }
        .summary { background: #f5f5f5; padding: 20px; border-radius: 5px; }
        .vulnerability { border: 1px solid #ddd; margin: 10px 0; padding: 15px; border-radius: 5px; }
        .high { border-left: 5px solid #ff6b6b; }
        .critical { border-left: 5px solid #dc143c; }
        .medium { border-left: 5px solid #ffa500; }
        .low { border-left: 5px solid #32cd32; }
    </style>
</head>
<body>
    <h1>Security Analysis Report</h1>
    <p><strong>Generated:</strong> ${report.generatedAt}</p>
    
    <div class="summary">
        <h2>Summary</h2>
        <ul>
            <li>Files Scanned: ${report.summary.filesScanned}</li>
            <li>Total Vulnerabilities: ${report.summary.totalVulnerabilities}</li>
            <li>High Severity: ${report.summary.highSeverityCount}</li>
            <li>Critical Severity: ${report.summary.criticalSeverityCount}</li>
        </ul>
    </div>
`;

  report.results.forEach((result: any, index: number) => {
    html += `<h2>File ${index + 1}: ${result.file}</h2>`;
    if (result.error) {
      html += `<p><strong>Error:</strong> ${result.error}</p>`;
    } else {
      html += `<p><strong>Vulnerabilities Found:</strong> ${result.vulnerabilities.length}</p>`;
      result.vulnerabilities.forEach((vuln: any) => {
        html += `
        <div class="vulnerability ${vuln.severity}">
            <h3>${vuln.type}</h3>
            <p><strong>Severity:</strong> ${vuln.severity}</p>
            <p><strong>Line:</strong> ${vuln.line}</p>
            <p><strong>Message:</strong> ${vuln.message}</p>
            <p><strong>Recommendation:</strong> ${vuln.recommendation}</p>
        </div>`;
      });
    }
  });

  html += `</body></html>`;
  return html;
}

// Start receiving messages on stdin and sending messages on stdout
async function main() {
  const transport = new StdioServerTransport();
  await server.connect(transport);
}

main().catch(console.error);
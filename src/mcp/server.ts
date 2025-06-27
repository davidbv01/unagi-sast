#!/usr/bin/env node

import { Server } from '@modelcontextprotocol/sdk/server/index.js';
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
import { 
  CallToolRequestSchema,
  ListToolsRequestSchema,
  Tool
} from '@modelcontextprotocol/sdk/types.js';
import { z } from 'zod';

// Define the tools that this MCP server provides
const SCAN_ACTUAL_FILE_TOOL: Tool = {
  name: 'scan_actual_file',
  description: 'Scans the currently active file for vulnerabilities (Python only)',
  inputSchema: {
    type: 'object',
    properties: {
      filePath: {
        type: 'string',
        description: 'Path to the file to scan for vulnerabilities'
      },
      language: {
        type: 'string',
        description: 'Programming language of the file',
        enum: ['python']
      }
    },
    required: ['filePath', 'language']
  }
};

const SCAN_WORKSPACE_TOOL: Tool = {
  name: 'scan_workspace',
  description: 'Scans all Python files in the current workspace for vulnerabilities',
  inputSchema: {
    type: 'object',
    properties: {
      workspacePath: {
        type: 'string',
        description: 'Optional path to the workspace directory (uses current VS Code workspace if not provided)'
      }
    },
    required: []
  }
};

class UnagiSastMcpServer {
  private server: Server;
  private scanOrchestrator: any; // Will be initialized in constructor

  constructor() {
    this.server = new Server(
      {
        name: 'unagi-sast-server',
        version: '1.0.0',
      },
      {
        capabilities: {
          tools: {},
        },
      }
    );

    // Dynamically import ScanOrchestrator to avoid circular deps
    // (or require if using CJS)
    // eslint-disable-next-line @typescript-eslint/no-var-requires
    const { ScanOrchestrator } = require('../core/ScanOrchestrator');
    this.scanOrchestrator = new ScanOrchestrator();

    this.setupToolHandlers();
    this.setupErrorHandling();
  }

  private setupErrorHandling(): void {
    this.server.onerror = (error) => {
      console.error('[MCP Server Error]', error);
    };

    process.on('SIGINT', async () => {
      await this.server.close();
      process.exit(0);
    });
  }

  private setupToolHandlers(): void {
    // List available tools
    this.server.setRequestHandler(ListToolsRequestSchema, async () => {
      return {
        tools: [SCAN_ACTUAL_FILE_TOOL, SCAN_WORKSPACE_TOOL],
      };
    });

    // Handle tool calls
    this.server.setRequestHandler(CallToolRequestSchema, async (request) => {
      const { name, arguments: args } = request.params;

      try {
        switch (name) {
          case 'scan_actual_file':
            return await this.handleScanActualFile(args);
          case 'scan_workspace':
            return await this.handleScanWorkspace(args);
          default:
            throw new Error(`Unknown tool: ${name}`);
        }
      } catch (error) {
        const errorMessage = error instanceof Error ? error.message : 'Unknown error occurred';
        return {
          content: [
            {
              type: 'text',
              text: `Error executing tool ${name}: ${errorMessage}`,
            },
          ],
          isError: true,
        };
      }
    });
  }

  private async handleScanActualFile(args: any) {
    const { filePath, language } = args;
    if (language !== 'python') {
      return {
        content: [
          {
            type: 'text',
            text: 'Only Python files are supported',
          },
        ],
        isError: true,
      };
    }
    try {
      // Simulate progress (in real MCP, progress reporting is different)
      // Use the ScanOrchestrator to scan the file
      const result = await this.scanOrchestrator.scanFile({ fileName: filePath });
      const totalVulns = result.patternVulnerabilities.length + result.dataFlowVulnerabilities.length;
      return {
        content: [
          {
            type: 'text',
            text: `Scan completed for ${filePath}. Found ${totalVulns} vulnerabilities.`,
          },
          {
            type: 'json',
            json: result,
          },
        ],
      };
    } catch (error: any) {
      return {
        content: [
          {
            type: 'text',
            text: `Error scanning file: ${error.message}`,
          },
        ],
        isError: true,
      };
    }
  }

  private async handleScanWorkspace(args: any) {
    const { workspacePath } = args;
    try {
      // Use the ScanOrchestrator to scan the workspace
      const results = await this.scanOrchestrator.scanWorkspace(workspacePath);
      const totalVulns = results.reduce((sum: number, result: any) => 
        sum + result.patternVulnerabilities.length + result.dataFlowVulnerabilities.length, 0
      );
      const totalFiles = results.length;
      
      return {
        content: [
          {
            type: 'text',
            text: `Workspace scan completed. Scanned ${totalFiles} Python files and found ${totalVulns} vulnerabilities.`,
          },
          {
            type: 'json',
            json: {
              summary: {
                totalFiles,
                totalVulnerabilities: totalVulns,
                patternVulnerabilities: results.reduce((sum: number, result: any) => sum + result.patternVulnerabilities.length, 0),
                dataFlowVulnerabilities: results.reduce((sum: number, result: any) => sum + result.dataFlowVulnerabilities.length, 0),
                totalScanTime: results.reduce((sum: number, result: any) => sum + result.scanTime, 0)
              },
              results
            },
          },
        ],
      };
    } catch (error: any) {
      return {
        content: [
          {
            type: 'text',
            text: `Error scanning workspace: ${error.message}`,
          },
        ],
        isError: true,
      };
    }
  }

  async run(): Promise<void> {
    const transport = new StdioServerTransport();
    await this.server.connect(transport);
    console.error('🛡️ Unagi SAST MCP Server started successfully');
  }
}

// Start the server
if (require.main === module) {
  const server = new UnagiSastMcpServer();
  server.run().catch(console.error);
} 
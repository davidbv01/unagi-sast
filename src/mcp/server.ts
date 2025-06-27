#!/usr/bin/env node

import { Server } from '@modelcontextprotocol/sdk/server/index.js';
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
import { 
  CallToolRequestSchema,
  ListToolsRequestSchema,
  Tool
} from '@modelcontextprotocol/sdk/types.js';
import { z } from 'zod';

// Define the tool that this MCP server provides
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
        tools: [SCAN_ACTUAL_FILE_TOOL],
      };
    });

    // Handle tool calls
    this.server.setRequestHandler(CallToolRequestSchema, async (request) => {
      const { name, arguments: args } = request.params;

      try {
        switch (name) {
          case 'scan_actual_file':
            return await this.handleScanActualFile(args);
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
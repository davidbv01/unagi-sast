#!/usr/bin/env node

import { Server } from '@modelcontextprotocol/sdk/server/index.js';
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
import { CallToolRequestSchema, ListToolsRequestSchema, Tool } from '@modelcontextprotocol/sdk/types.js';

// Define two dummy tools
const SCAN_ACTUAL_FILE_TOOL: Tool = {
  name: 'scan_actual_file',
  description: 'Dummy scanner for the currently active file',
  inputSchema: {
    type: 'object',
    properties: {
      filePath: { type: 'string', description: 'Path to the file' },
      language: { type: 'string', description: 'Programming language' }
    },
    required: ['filePath', 'language']
  }
};

const SCAN_WORKSPACE_TOOL: Tool = {
  name: 'scan_workspace',
  description: 'Dummy scanner for all files in the workspace',
  inputSchema: {
    type: 'object',
    properties: {
      workspacePath: { type: 'string', description: 'Optional workspace path' }
    },
    required: []
  }
};

class UnagiSimpleMcpServer {
  private server: Server;

  constructor() {
    this.server = new Server(
      { name: 'unagi-sast-server', version: '0.1.0' },
      { capabilities: { tools: {} } }
    );

    this.setupHandlers();
  }

  private setupHandlers() {
    // Handle listing tools
    this.server.setRequestHandler(ListToolsRequestSchema, async () => {
      console.log('[MCP] ListToolsRequest received');
      return { tools: [SCAN_ACTUAL_FILE_TOOL, SCAN_WORKSPACE_TOOL] };
    });

    // Handle tool calls
    this.server.setRequestHandler(CallToolRequestSchema, async (request) => {
      const { name, arguments: args } = request.params;
      console.log(`[MCP] CallToolRequest received:`, name, args);

      return {
        content: [
          { type: 'text', text: `Tool "${name}" called with args: ${JSON.stringify(args)}` }
        ],
        isError: false
      };
    });
  }

  async run() {
    console.log('🛡️ Starting Unagi MCP server in dummy mode...');
    const transport = new StdioServerTransport();
    await this.server.connect(transport);
    console.log('✅ MCP server connected via STDIO');
  }
}

// Entrypoint
if (require.main === module) {
  const server = new UnagiSimpleMcpServer();
  server.run().catch((err) => {
    console.error('❌ MCP server crashed', err);
  });
}

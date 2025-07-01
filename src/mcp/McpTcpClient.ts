import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import net from "net";
import { z } from "zod";

const HOST = process.env.TCP_HOST || "127.0.0.1";
const PORT = process.env.TCP_PORT ? parseInt(process.env.TCP_PORT, 10) : 7070;

function sendTcpMessage(message: string): Promise<string> {
  return new Promise((resolve, reject) => {
    const client = new net.Socket();
    let response = "";

    client.connect(PORT, HOST, () => {
      client.write(message);
    });

    client.on("data", (data) => {
      response += data.toString();
      client.destroy();
      resolve(response);
    });

    client.on("error", (err) => {
      reject(err);
    });
  });
}

// Create an MCP server
const server = new McpServer({
  name: "unagi-sast-server",
  version: "1.0.0"
});

// Register scan_actual_file tool
server.registerTool("scan_actual_file",
  {
    title: "Scan Actual File",
    description: "Scan the specified file for security vulnerabilities",
    inputSchema: {
      path: z.string().describe("Absolute path to the file to scan")
    }
  },
  async ({ path }) => {
    try {
      const result = await sendTcpMessage(`scanActualFile:${path}`);
      return {
        content: [{ type: "text", text: `Scan completed: ${result}` }]
      };
    } catch (error) {
      return {
        content: [{ type: "text", text: `Error scanning file: ${error}` }]
      };
    }
  }
);

// Register scan_workspace tool
server.registerTool("scan_workspace",
  {
    title: "Scan Workspace",
    description: "Scan the entire workspace or a specified directory for security vulnerabilities",
    inputSchema: {
      path: z.string().describe("Optional path to a directory to scan instead of the whole workspace").optional()
    }
  },
  async ({ path }) => {
    try {
      const message = path ? `scanWorkspace:${path}` : "scanWorkspace";
      const result = await sendTcpMessage(message);
      return {
        content: [{ type: "text", text: `Workspace scan completed: ${result}` }]
      };
    } catch (error) {
      return {
        content: [{ type: "text", text: `Error scanning workspace: ${error}` }]
      };
    }
  }
);

// Start receiving messages on stdin and sending messages on stdout
async function startServer() {
  const transport = new StdioServerTransport();
  await server.connect(transport);
}

startServer().catch(console.error); 
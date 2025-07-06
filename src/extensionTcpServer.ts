import net from "net";
import { OutputManager } from "./output/OutputManager";
import { ScanOrchestrator } from "./core/ScanOrchestrator";
import { WorkspaceScanOrchestrator } from "./core/WorkspaceScanOrchestrator";
import { FileUtils } from "./utils";
import { DataFlowVulnerability, Severity } from "./types";
import * as fs from "fs";
import * as vscode from "vscode";

/**
 * TCP server for remote control and automation of Unagi SAST scans.
 * Supports commands for scanning individual files and the entire workspace.
 */

const PORT: number = process.env.TCP_PORT ? parseInt(process.env.TCP_PORT, 10) : 7070;
const DEFAULT_API_KEY: string = process.env.OPENAI_API_KEY || "";
const DEFAULT_FOLDER_PATH: string = process.env.UNAGI_OUTPUT_PATH || "./unagi-output";

const outputManager = new OutputManager(DEFAULT_FOLDER_PATH);
const scanOrchestrator = new ScanOrchestrator(outputManager, DEFAULT_API_KEY);
const workspaceScanOrchestrator = new WorkspaceScanOrchestrator(outputManager, DEFAULT_API_KEY);
/**
 * Handles incoming TCP messages and dispatches scan commands.
 * @param socket The TCP socket connection.
 * @param message The received message string.
 */
async function handleTcpMessage(socket: net.Socket, message: string): Promise<void> {
  if (message.startsWith("scanActualFile:")) {
    await handleScanActualFile(socket, message.replace("scanActualFile:", "").trim());
  } else if (message === "scanWorkspace") {
    await handleScanWorkspace(socket);
  } else {
    console.log("Unknown message:", message);
  }
}

/**
 * Handles the scanActualFile command.
 * @param socket The TCP socket connection.
 * @param filePath The file path to scan.
 */
async function handleScanActualFile(socket: net.Socket, filePath: string): Promise<void> {
  console.log("Received scanActualFile request");
  if (!fs.existsSync(filePath)) {
    socket.write(JSON.stringify({ error: `File not found: ${filePath}` }) + "\n");
    return;
  }
  if (!FileUtils.isSupportedFile(filePath)) {
    socket.write(JSON.stringify({ error: `Unsupported file type: ${filePath}` }) + "\n");
    return;
  }
  try {
    // Open the file as a VSCode TextDocument
    const document = await vscode.workspace.openTextDocument(filePath);
    // Scan using the orchestrator, which will update VSCode UI
    const result = await scanOrchestrator.run(document);
    socket.write(JSON.stringify(result) + "\n");
  } catch (scanErr) {
    socket.write(JSON.stringify({ error: `Scan failed: ${scanErr}` }) + "\n");
  }
}

/**
 * Handles the scanWorkspace command.
 * @param socket The TCP socket connection.
 */
async function handleScanWorkspace(socket: net.Socket): Promise<void> {
  console.log("Received scanWorkspace request");
  try {
    // Get the workspace root
    const workspaceRoot = vscode.workspace.workspaceFolders?.[0]?.uri.fsPath;
    if (!workspaceRoot) {
      socket.write(JSON.stringify({ error: "No workspace folder found" }) + "\n");
      return;
    }
    // Run the workspace analysis
    await workspaceScanOrchestrator.run(workspaceRoot);
    // Get the vulnerabilities
    const vulnerabilities = workspaceScanOrchestrator.getWorkspaceVulnerabilities();
    // Prepare the result
    const result = {
      workspaceRoot,
      filesAnalyzed: workspaceScanOrchestrator.getSymbolTable().size,
      vulnerabilities: vulnerabilities,
      summary: {
        totalVulnerabilities: vulnerabilities.length,
        crossFileVulnerabilities: vulnerabilities.filter((v: DataFlowVulnerability) => (v as any).crossFileContext).length,
        severityBreakdown: {
          critical: vulnerabilities.filter((v: DataFlowVulnerability) => v.severity === Severity.CRITICAL).length,
          high: vulnerabilities.filter((v: DataFlowVulnerability) => v.severity === Severity.HIGH).length,
          medium: vulnerabilities.filter((v: DataFlowVulnerability) => v.severity === Severity.MEDIUM).length,
          low: vulnerabilities.filter((v: DataFlowVulnerability) => v.severity === Severity.LOW).length
        }
      }
    };
    socket.write(JSON.stringify(result) + "\n");
  } catch (workspaceErr) {
    socket.write(JSON.stringify({ error: `Workspace scan failed: ${workspaceErr}` }) + "\n");
  }
}

// --- TCP Server Setup ---

/**
 * Starts the TCP server for Unagi SAST extension automation.
 */
const server = net.createServer((socket) => {
  socket.on("data", async (data) => {
    try {
      const message = data.toString().trim();
      await handleTcpMessage(socket, message);
    } catch (err) {
      console.error("Error handling TCP message:", err);
    }
  });

  socket.on("error", (err) => {
    console.error("Socket error:", err);
  });
});

server.listen(PORT, () => {
  console.log(`TCP server listening on port ${PORT}`);
}); 
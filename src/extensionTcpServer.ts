import net from "net";
import { OutputManager } from "./output/OutputManager";
import { ScanOrchestrator } from "./core/ScanOrchestrator";
import { FileUtils } from "./utils";
import { DataFlowVulnerability, Severity } from "./types";
import * as fs from "fs";
import * as vscode from "vscode";

const PORT = process.env.TCP_PORT ? parseInt(process.env.TCP_PORT, 10) : 7070;
const DEFAULT_API_KEY = process.env.OPENAI_API_KEY || "";
const DEFAULT_FOLDER_PATH = process.env.UNAGI_OUTPUT_PATH || "./unagi-output";

const outputManager = new OutputManager(DEFAULT_FOLDER_PATH);
const scanOrchestrator = new ScanOrchestrator(outputManager, DEFAULT_API_KEY);

const server = net.createServer((socket) => {
  socket.on("data", async (data) => {
    try {
      const message = data.toString().trim();
      if (message.startsWith("scanActualFile:")) {
        console.log("Received scanActualFile request");
        const filePath = message.replace("scanActualFile:", "").trim();
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
      } else if (message === "scanWorkspace") {
        console.log("Received scanWorkspace request");
        try {
          const { WorkspaceScanOrchestrator } = await import("./core/WorkspaceScanOrchestrator.js");
          const workspaceOrchestrator = new WorkspaceScanOrchestrator();
          
          // Get the workspace root
          const workspaceRoot = vscode.workspace.workspaceFolders?.[0]?.uri.fsPath;
          if (!workspaceRoot) {
            socket.write(JSON.stringify({ error: "No workspace folder found" }) + "\n");
            return;
          }
          
          // Run the workspace analysis
          await workspaceOrchestrator.run(workspaceRoot);
          
          // Get the vulnerabilities
          const vulnerabilities = workspaceOrchestrator.getWorkspaceVulnerabilities();
          
          // Prepare the result
          const result = {
            workspaceRoot,
            filesAnalyzed: workspaceOrchestrator.getSymbolTable().size,
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
      } else {
        console.log("Unknown message:", message);
      }
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
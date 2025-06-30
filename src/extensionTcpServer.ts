import net from "net";
import { OutputManager } from "./output/OutputManager";
import { ScanOrchestrator } from "./core/ScanOrchestrator";
import { FileUtils } from "./utils";
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
          const result = await scanOrchestrator.scanFile(document);
          socket.write(JSON.stringify(result) + "\n");
        } catch (scanErr) {
          socket.write(JSON.stringify({ error: `Scan failed: ${scanErr}` }) + "\n");
        }
      } else if (message === "scanWorkspace") {
        console.log("Received scanWorkspace request");
        // TODO: Implement scanWorkspace logic
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
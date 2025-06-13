import * as vscode from 'vscode';
import { ScanOrchestrator } from '../scanners/ScanOrchestrator';
import { OutputManager } from '../output/OutputManager';

export class CommandTrigger {
  private scanOrchestrator: ScanOrchestrator;
  private outputManager: OutputManager;

  constructor() {
    this.scanOrchestrator = new ScanOrchestrator();
    this.outputManager = new OutputManager();
  }

  public registerCommands(context: vscode.ExtensionContext): void {
    // Register command to scan current file
    context.subscriptions.push(
      vscode.commands.registerCommand('unagi.scanActualFile', async () => {
        const editor = vscode.window.activeTextEditor;
        if (!editor) {
          vscode.window.showWarningMessage('No active editor found');
          return;
        }

        const document = editor.document;
        if (document.languageId !== 'python') {
          vscode.window.showWarningMessage('Only Python files are supported');
          return;
        }

        try {
          vscode.window.withProgress({
            location: vscode.ProgressLocation.Window,
            title: "Unagi",
            cancellable: false
          }, async (progress) => {
            progress.report({ message: `Scanning ${document.fileName}...` });
            const result = await this.scanOrchestrator.scanFile(document);
            await this.outputManager.displayResults(result);
            progress.report({ message: `Found ${result.vulnerabilities.length} vulnerabilities` });
          });
        } catch (error: any) {
          vscode.window.showErrorMessage(`Error scanning file: ${error.message}`);
        }
      })
    );

    // Register command to scan workspace
    context.subscriptions.push(
      vscode.commands.registerCommand('unagi.scanWorkspace', async () => {
        const workspaceFolders = vscode.workspace.workspaceFolders;
        if (!workspaceFolders) {
          vscode.window.showWarningMessage('No workspace folder found');
          return;
        }

        try {
          vscode.window.withProgress({
            location: vscode.ProgressLocation.Window,
            title: "Unagi",
            cancellable: false
          }, async (progress) => {
            progress.report({ message: 'Scanning workspace...' });
            
            // Find all Python files in workspace
            const pythonFiles = await vscode.workspace.findFiles('**/*.py');
            let totalVulnerabilities = 0;

            for (const file of pythonFiles) {
              const document = await vscode.workspace.openTextDocument(file);
              progress.report({ message: `Scanning ${file.fsPath}...` });
              
              const result = await this.scanOrchestrator.scanFile(document);
              await this.outputManager.displayResults(result);
              totalVulnerabilities += result.vulnerabilities.length;
            }

            progress.report({ message: `Found ${totalVulnerabilities} vulnerabilities across ${pythonFiles.length} files` });
          });
        } catch (error: any) {
          vscode.window.showErrorMessage(`Error scanning workspace: ${error.message}`);
        }
      })
    );
  }
} 
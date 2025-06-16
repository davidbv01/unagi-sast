import * as vscode from 'vscode';
import { ScanOrchestrator } from './ScanOrchestrator';
import { OutputManager } from '../output/OutputManager';

export class CommandTrigger {
  private scanOrchestrator: ScanOrchestrator;
  private outputManager: OutputManager;

  constructor() {
    this.outputManager = new OutputManager();
    this.scanOrchestrator = new ScanOrchestrator(this.outputManager);
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
            progress.report({ message: `Found ${result.vulnerabilities.length} vulnerabilities` });
          });
        } catch (error: any) {
          vscode.window.showErrorMessage(`Error scanning file: ${error.message}`);
        }
      })
    );
  }
} 
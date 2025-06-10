import * as vscode from 'vscode';
import { ScanOrchestrator } from '../scanners/ScanOrchestrator.js';

export class CommandTrigger {
  private scanOrchestrator: ScanOrchestrator;

  constructor() {
    this.scanOrchestrator = new ScanOrchestrator();
  }

  public registerCommands(context: vscode.ExtensionContext): void {
    // Scan current file
    const scanFileCommand = vscode.commands.registerCommand('unagi.scanActualFile', () => {
      this.scanCurrentFile();
    });

    // Scan entire workspace
    const scanWorkspaceCommand = vscode.commands.registerCommand('unagi.scanWorkspace', () => {
      this.scanWorkspace();
    });

    // Scan selected files
    const scanSelectedCommand = vscode.commands.registerCommand('unagi.scanSelected', (uri: vscode.Uri) => {
      this.scanSelected(uri);
    });

    // Clear scan results
    const clearResultsCommand = vscode.commands.registerCommand('unagi.clearResults', () => {
      this.clearResults();
    });

    context.subscriptions.push(
      scanFileCommand,
      scanWorkspaceCommand,
      scanSelectedCommand,
      clearResultsCommand
    );
  }

  private async scanCurrentFile(): Promise<void> {
    const editor = vscode.window.activeTextEditor;
    if (!editor) {
      vscode.window.showWarningMessage('Unagi: No active file to scan.');
      return;
    }

    const fileName = editor.document.fileName;
    vscode.window.showInformationMessage(`Unagi: Scanning file ${fileName}`);
    
    try {
      await this.scanOrchestrator.scanFile(editor.document);
    } catch (error) {
      vscode.window.showErrorMessage(`Unagi: Error scanning file - ${error}`);
    }
  }

  private async scanWorkspace(): Promise<void> {
    const workspaceFolders = vscode.workspace.workspaceFolders;
    if (!workspaceFolders) {
      vscode.window.showWarningMessage('Unagi: No workspace folder found.');
      return;
    }

    vscode.window.showInformationMessage('Unagi: Scanning workspace...');
    
    try {
      await this.scanOrchestrator.scanWorkspace();
    } catch (error) {
      vscode.window.showErrorMessage(`Unagi: Error scanning workspace - ${error}`);
    }
  }

  private async scanSelected(uri: vscode.Uri): Promise<void> {
    if (!uri) {
      vscode.window.showWarningMessage('Unagi: No file selected.');
      return;
    }

    try {
      const document = await vscode.workspace.openTextDocument(uri);
      await this.scanOrchestrator.scanFile(document);
    } catch (error) {
      vscode.window.showErrorMessage(`Unagi: Error scanning selected file - ${error}`);
    }
  }

  private clearResults(): void {
    this.scanOrchestrator.clearResults();
    vscode.window.showInformationMessage('Unagi: Scan results cleared.');
  }
}

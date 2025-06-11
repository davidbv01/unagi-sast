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
    console.log('🔍 Initiating current file scan...');
    const editor = vscode.window.activeTextEditor;
    if (!editor) {
      console.log('⚠️ No active text editor found');
      vscode.window.showWarningMessage('Unagi: No active text editor.');
      return;
    }

    console.log(`📄 Scanning file: ${editor.document.fileName}`);
    try {
      console.log('⚙️ Starting file scan...');
      await this.scanOrchestrator.scanFile(editor.document);
      console.log('✅ File scan completed successfully');
    } catch (error) {
      console.error('❌ Error during file scan:', error);
      vscode.window.showErrorMessage(`Unagi: Error scanning file - ${error}`);
    }
  }

  private async scanWorkspace(): Promise<void> {
    console.log('🔍 Initiating workspace scan...');
    const workspaceFolders = vscode.workspace.workspaceFolders;
    if (!workspaceFolders) {
      console.log('⚠️ No workspace folder found');
      vscode.window.showWarningMessage('Unagi: No workspace folder found.');
      return;
    }

    console.log(`📁 Found workspace folder: ${workspaceFolders[0].name}`);
    vscode.window.showInformationMessage('Unagi: Scanning workspace...');
    
    try {
      console.log('⚙️ Starting workspace scan...');
      await this.scanOrchestrator.scanWorkspace();
      console.log('✅ Workspace scan completed successfully');
    } catch (error) {
      console.error('❌ Error during workspace scan:', error);
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

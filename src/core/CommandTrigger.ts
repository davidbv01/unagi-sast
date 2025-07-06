import * as vscode from 'vscode';
import { ScanOrchestrator } from './ScanOrchestrator';
import { OutputManager } from '../output/OutputManager';
import { WorkspaceScanOrchestrator } from './WorkspaceScanOrchestrator';

/**
 * Handles registration and execution of Unagi SAST extension commands.
 */
export class CommandTrigger {
  private readonly scanOrchestrator: ScanOrchestrator;
  private readonly outputManager: OutputManager;
  private readonly workspaceScanOrchestrator: WorkspaceScanOrchestrator;
  /**
   * Creates a new CommandTrigger instance.
   * @param apiKey The OpenAI API key for AI-powered features.
   * @param folderPath The folder path for output and reports.
   */
  constructor(apiKey: string, folderPath: string) {
    this.outputManager = new OutputManager(folderPath);
    this.scanOrchestrator = new ScanOrchestrator(this.outputManager, apiKey);
    this.workspaceScanOrchestrator = new WorkspaceScanOrchestrator(this.outputManager, apiKey);
  }

  /**
   * Registers all extension commands with VSCode.
   * @param context The extension context.
   */
  public registerCommands(context: vscode.ExtensionContext): void {
    // Command constants
    const SCAN_FILE_CMD = 'unagi.scanActualFile';
    const CONFIGURE_API_KEY_CMD = 'unagiSast.configureOpenAIApiKey';
    const SCAN_WORKSPACE_CMD = 'unagi.scanWorkspace';
    const CREATE_REPORT_CMD = 'unagi.createReport';

    // Register command to scan current file
    context.subscriptions.push(
      vscode.commands.registerCommand(SCAN_FILE_CMD, async () => {
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
          await vscode.window.withProgress({
            location: vscode.ProgressLocation.Window,
            title: 'Unagi',
            cancellable: false
          }, async (progress) => {
            progress.report({ message: `Scanning ${document.fileName}...` });
            const result = await this.scanOrchestrator.run(document);
            const totalVulns = result.patternVulnerabilities.length + result.dataFlowVulnerabilities.length;
            progress.report({ message: `Found ${totalVulns} vulnerabilities` });
          });
        } catch (error: any) {
          vscode.window.showErrorMessage(`Error scanning file: ${error.message}`);
        }
      })
    );

    // Register command to scan workspace
    context.subscriptions.push(
      vscode.commands.registerCommand(SCAN_WORKSPACE_CMD, async () => {
        if (!vscode.workspace.workspaceFolders || vscode.workspace.workspaceFolders.length === 0) {
          vscode.window.showWarningMessage('No workspace folder open');
          return;
        }
        try {
          await this.workspaceScanOrchestrator.run(vscode.workspace.workspaceFolders[0].uri.fsPath);
          // (Optional) Aggregate and display results, save reports, etc.
        } catch (error: any) {
          vscode.window.showErrorMessage(`Error scanning workspace: ${error.message}`);
        }
      })
    );

    // Register command to configure OpenAI API key
    context.subscriptions.push(
      vscode.commands.registerCommand(CONFIGURE_API_KEY_CMD, async () => {
        const existingKey = context.globalState.get<string>('OPENAI_API_KEY');
        if (existingKey) {
          const action = await vscode.window.showQuickPick([
            'Replace API Key',
            'Delete API Key',
            'Cancel'
          ], {
            placeHolder: 'An OpenAI API Key is already set. What would you like to do?'
          });
          if (action === 'Delete API Key') {
            await context.globalState.update('OPENAI_API_KEY', undefined);
            vscode.window.showInformationMessage('OpenAI API Key deleted.');
            this.scanOrchestrator.ruleEngine.updateAiEngine(null);
            return;
          } else if (action !== 'Replace API Key') {
            vscode.window.showInformationMessage('No changes made to OpenAI API Key.');
            return;
          }
        }
        const apiKey = await vscode.window.showInputBox({
          prompt: 'Enter your OpenAI API Key',
          ignoreFocusOut: true,
          password: true,
          placeHolder: 'sk-...'
        });
        if (apiKey) {
          await context.globalState.update('OPENAI_API_KEY', apiKey);
          vscode.window.showInformationMessage('OpenAI API Key saved successfully!');
          this.scanOrchestrator.ruleEngine.updateAiEngine(apiKey);
        } else {
          vscode.window.showWarningMessage('OpenAI API Key not set.');
        }
      })
    );

    // Register command to create a security report
    context.subscriptions.push(
      vscode.commands.registerCommand(CREATE_REPORT_CMD, async () => {
        await this.outputManager.createReport();
      })
    );
  }

  /**
   * Disposes resources held by this instance.
   */
  public dispose(): void {
    this.outputManager.dispose();
  }
}


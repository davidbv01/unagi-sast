import * as vscode from 'vscode';
import { ScanOrchestrator } from './ScanOrchestrator';
import { OutputManager } from '../output/OutputManager';
import { WorkspaceScanOrchestrator } from './WorkspaceScanOrchestrator';

export class CommandTrigger {
  private scanOrchestrator: ScanOrchestrator;
  private outputManager: OutputManager;

  constructor(apiKey: string, folderPath: string) {
    this.outputManager = new OutputManager(folderPath);
    this.scanOrchestrator = new ScanOrchestrator(this.outputManager, apiKey);
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
            const result = await this.scanOrchestrator.run(document);
            const totalVulns = result.patternVulnerabilities.length + result.dataFlowVulnerabilities.length;
            progress.report({ message: `Found ${totalVulns} vulnerabilities` });
          });
        } catch (error: any) {
          vscode.window.showErrorMessage(`Error scanning file: ${error.message}`);
        }
      })
    );

    // Register command to configure OpenAI API key
    context.subscriptions.push(
      vscode.commands.registerCommand('unagiSast.configureOpenAIApiKey', async () => {
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

    // Register command to scan workspace
    context.subscriptions.push(
      vscode.commands.registerCommand('unagi.scanWorkspace', async () => {
        if (!vscode.workspace.workspaceFolders || vscode.workspace.workspaceFolders.length === 0) {
          vscode.window.showWarningMessage('No workspace folder open');
          return;
        }

        try {
          const orchestrator = new WorkspaceScanOrchestrator();
          await orchestrator.run(vscode.workspace.workspaceFolders[0].uri.fsPath);
          /*const results = await this.scanOrchestrator.scanWorkspace();
          
          // Aggregate and display results
          const totalVulns = results.reduce((sum, result) => 
            sum + result.patternVulnerabilities.length + result.dataFlowVulnerabilities.length, 0
          );
          
          const totalFiles = results.length;
          const totalTime = results.reduce((sum, result) => sum + result.scanTime, 0);
          
          console.log(`📊 Workspace scan summary:
            - Files scanned: ${totalFiles}
            - Total vulnerabilities: ${totalVulns}
            - Total scan time: ${(totalTime / 1000).toFixed(2)}s`);
          
          // Save workspace results to a consolidated report
          if (results.length > 0) {
            await this.outputManager.saveWorkspaceResults(results);
            
          }*/
        } catch (error: any) {
          vscode.window.showErrorMessage(`Error scanning workspace: ${error.message}`);
        }
      })
    );

    // Register command to create a security report
    context.subscriptions.push(
      vscode.commands.registerCommand('unagi.createReport', async () => {
        await this.outputManager.createReport();
      })
    );
  }
}


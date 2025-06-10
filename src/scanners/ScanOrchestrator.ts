import * as vscode from 'vscode';
import { Vulnerability, ScanResult } from '../types';
import { SecurityRuleEngine } from './SecurityRuleEngine';
import { OutputManager } from '../output/OutputManager';
import { configManager } from '../config/ConfigurationManager';

export class ScanOrchestrator {
  private ruleEngine: SecurityRuleEngine;
  private outputManager: OutputManager;

  constructor() {
    this.ruleEngine = new SecurityRuleEngine();
    this.outputManager = new OutputManager();
  }

  public async scanFile(document: vscode.TextDocument): Promise<ScanResult> {
    const startTime = Date.now();
    const content = document.getText();
    const lines = content.split('\n');
    
    vscode.window.withProgress({
      location: vscode.ProgressLocation.Window,
      title: "Unagi",
      cancellable: false
    }, async (progress) => {
      progress.report({ message: `Scanning ${document.fileName}...` });
      
      const vulnerabilities = await this.ruleEngine.scanContent(content, document.languageId, document.fileName);
      
      const result: ScanResult = {
        file: document.fileName,
        vulnerabilities,
        scanTime: Date.now() - startTime,
        linesScanned: lines.length
      };

      await this.outputManager.displayResults(result);
      
      progress.report({ message: `Found ${vulnerabilities.length} vulnerabilities` });
      
      return result;
    });

    return {
      file: document.fileName,
      vulnerabilities: [],
      scanTime: 0,
      linesScanned: 0
    };
  }

  public async scanWorkspace(): Promise<ScanResult[]> {
    const config = configManager.getScanConfiguration();
    const workspaceFolders = vscode.workspace.workspaceFolders;
    
    if (!workspaceFolders) {
      throw new Error('No workspace folder found');
    }

    const results: ScanResult[] = [];
    
    return vscode.window.withProgress({
      location: vscode.ProgressLocation.Notification,
      title: "Unagi: Scanning workspace",
      cancellable: true
    }, async (progress, token) => {
      
      for (const pattern of config.includePatterns) {
        const files = await vscode.workspace.findFiles(pattern);
        
        for (let i = 0; i < files.length; i++) {
          if (token.isCancellationRequested) {
            break;
          }
          
          progress.report({
            message: `Scanning file ${i + 1} of ${files.length}`,
            increment: (100 / files.length)
          });
          
          try {
            const document = await vscode.workspace.openTextDocument(files[i]);
            const result = await this.scanFile(document);
            results.push(result);
          } catch (error) {
            console.error(`Error scanning ${files[i].fsPath}:`, error);
          }
        }
      }
      
      await this.outputManager.displayWorkspaceResults(results);
      return results;
    });
  }

  public clearResults(): void {
    this.outputManager.clearResults();
  }
}

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
    console.log(`🔍 Starting scan of file: ${document.fileName}`);
    console.log(`📄 Language: ${document.languageId}`);
    
    const content = document.getText();
    const lines = content.split('\n');
    console.log(`📊 File contains ${lines.length} lines`);
    
    vscode.window.withProgress({
      location: vscode.ProgressLocation.Window,
      title: "Unagi",
      cancellable: false
    }, async (progress) => {
      progress.report({ message: `Scanning ${document.fileName}...` });
      console.log('⚙️ Running security rule engine...');
      
      const vulnerabilities = await this.ruleEngine.scanContent(content, document.languageId, document.fileName);
      console.log(`🔎 Found ${vulnerabilities.length} potential vulnerabilities`);
      
      const result: ScanResult = {
        file: document.fileName,
        vulnerabilities,
        scanTime: Date.now() - startTime,
        linesScanned: lines.length,
        language: document.languageId
      };

      console.log(`⏱️ Scan completed in ${result.scanTime}ms`);
      console.log('📤 Displaying results...');
      await this.outputManager.displayResults(result);
      
      progress.report({ message: `Found ${vulnerabilities.length} vulnerabilities` });
      console.log('✅ Scan process completed');
      
      return result;
    });

    return {
      file: document.fileName,
      vulnerabilities: [],
      scanTime: 0,
      linesScanned: 0,
      language: document.languageId
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

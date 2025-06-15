import * as vscode from 'vscode';
import { Vulnerability, ScanResult } from '../types';
import { SecurityRuleEngine } from '../rules/SecurityRuleEngine';
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
    console.log(`[DEBUG] 🔍 Starting scan of file: ${document.fileName}`);
    console.log(`[DEBUG] 📄 Language: ${document.languageId}`);
    
    const content = document.getText();
    const lines = content.split('\n');
    console.log(`[DEBUG] 📊 File contains ${lines.length} lines`);
    
    vscode.window.withProgress({
      location: vscode.ProgressLocation.Window,
      title: "Unagi",
      cancellable: false
    }, async (progress) => {
      progress.report({ message: `Scanning ${document.fileName}...` });
      console.log('[DEBUG] ⚙️ Running security rule engine...');
      
      const vulnerabilities = await this.ruleEngine.analyzeFile(content, document.languageId, document.fileName);
      console.log(`[DEBUG] 🔎 Found ${vulnerabilities.length} potential vulnerabilities`);
      
      if (vulnerabilities.length === 0) {
        console.log('[DEBUG] ℹ️ No vulnerabilities found. Checking if rules were properly loaded...');
        console.log('[DEBUG] ℹ️ File content preview:', content.substring(0, 200) + '...');
      }
      
      const result: ScanResult = {
        file: document.fileName,
        vulnerabilities,
        scanTime: Date.now() - startTime,
        linesScanned: lines.length,
        language: document.languageId
      };

      console.log(`[DEBUG] ⏱️ Scan completed in ${result.scanTime}ms`);
      console.log('[DEBUG] 📤 Displaying results...');
      await this.outputManager.displayResults(result);
      
      progress.report({ message: `Found ${vulnerabilities.length} vulnerabilities` });
      console.log('[DEBUG] ✅ Scan process completed');
      
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
import * as vscode from 'vscode';
import { Vulnerability, ScanResult } from '../types';
import { SecurityRuleEngine } from '../rules/SecurityRuleEngine';
import { OutputManager } from '../output/OutputManager';
import { configManager } from '../config/ConfigurationManager';
import { ASTParser } from '../parser/ASTParser';

export class ScanOrchestrator {
  private ruleEngine: SecurityRuleEngine;
  private outputManager: OutputManager;
  private astParser: ASTParser;

  constructor() {
    this.ruleEngine = new SecurityRuleEngine();
    this.outputManager = new OutputManager();
    this.astParser = new ASTParser();
  }

  public async scanFile(document: vscode.TextDocument): Promise<ScanResult> {
    const startTime = Date.now();
    console.log(`[DEBUG] 🔍 Starting scan of file: ${document.fileName}`);
    console.log(`[DEBUG] 📄 Language: ${document.languageId}`);
    
    const content = document.getText();
    const lines = content.split('\n');
    console.log(`[DEBUG] 📊 File contains ${lines.length} lines`);
    
    try {
      return await vscode.window.withProgress({
        location: vscode.ProgressLocation.Window,
        title: "Unagi",
        cancellable: false
      }, async (progress) => {
        progress.report({ message: `Scanning ${document.fileName}...` });
        console.log('[DEBUG] ⚙️ Running security rule engine...');
        
        // Parse content into AST
        console.log('[DEBUG] 🔄 Parsing content into AST');
        let ast;
        try {
          ast = this.astParser.parse(content, document.languageId, document.fileName);
        } catch (error) {
          console.error('[ERROR] Failed to parse file into AST:', error);
          ast = null;
        }
        let vulnerabilities: Vulnerability[] = [];
        
        if (ast) {
          try {
            vulnerabilities = await this.ruleEngine.analyzeFile(ast, document.languageId, document.fileName, content);
            console.log(`[DEBUG] 🔎 Found ${vulnerabilities.length} potential vulnerabilities`);
            
            if (vulnerabilities.length === 0) {
              console.log('[DEBUG] ℹ️ No vulnerabilities found. Checking if rules were properly loaded...');
              console.log('[DEBUG] ℹ️ File content preview:', content.substring(0, 200) + '...');
            }
          } catch (error) {
            console.error('[ERROR] Failed to analyze AST:', error);
            vscode.window.showErrorMessage(`Failed to analyze file: ${document.fileName}`);
          }
        } else {
          console.log('[DEBUG] ⚠️ Could not parse file into AST, skipping taint analysis');
          // Still run pattern-based analysis even if AST parsing fails
          try {
            vulnerabilities = await this.ruleEngine.analyzeFile(content, document.languageId, document.fileName, content);
            console.log(`[DEBUG] 🔎 Found ${vulnerabilities.length} pattern-based vulnerabilities`);
          } catch (error) {
            console.error('[ERROR] Failed to run pattern analysis:', error);
            vscode.window.showErrorMessage(`Failed to run pattern analysis on file: ${document.fileName}`);
          }
        }
        
        const result = this.createScanResult(document, vulnerabilities, startTime, lines.length);
        console.log(`[DEBUG] ⏱️ Scan completed in ${result.scanTime}ms`);
        console.log('[DEBUG] 📤 Displaying results...');
        
        try {
          await this.outputManager.displayResults(result);
        } catch (error) {
          console.error('[ERROR] Failed to display results:', error);
          vscode.window.showErrorMessage('Failed to display scan results');
        }
        
        progress.report({ message: `Found ${vulnerabilities.length} vulnerabilities` });
        console.log('[DEBUG] ✅ Scan process completed');
        
        return result;
      });
    } catch (error) {
      console.error('[ERROR] Scan process failed:', error);
      vscode.window.showErrorMessage(`Scan failed for file: ${document.fileName}`);
      return this.createScanResult(document, [], startTime, lines.length);
    }
  }

  private createScanResult(document: vscode.TextDocument, vulnerabilities: Vulnerability[], startTime: number, linesScanned: number): ScanResult {
    return {
      file: document.fileName,
      vulnerabilities,
      scanTime: Date.now() - startTime,
      linesScanned,
      language: document.languageId
    };
  }

  public clearResults(): void {
    this.outputManager.clearResults();
  }
} 
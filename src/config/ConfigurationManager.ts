import * as vscode from 'vscode';
import { ScanConfiguration, OutputFormat, Severity } from '../types';

export class ConfigurationManager {
  private static instance: ConfigurationManager;
  private config: vscode.WorkspaceConfiguration;

  private constructor() {
    this.config = vscode.workspace.getConfiguration('unagi');
  }

  public static getInstance(): ConfigurationManager {
    if (!ConfigurationManager.instance) {
      ConfigurationManager.instance = new ConfigurationManager();
    }
    return ConfigurationManager.instance;
  }

  public getScanConfiguration(): ScanConfiguration {
    return {
      enabledRules: this.config.get('enabledRules', []),
      excludePatterns: this.config.get('excludePatterns', ['**/node_modules/**', '**/dist/**', '**/build/**']),
      includePatterns: this.config.get('includePatterns', ['**/*.js', '**/*.ts', '**/*.jsx', '**/*.tsx', '**/*.py', '**/*.java', '**/*.php']),
      severity: this.config.get('minimumSeverity', [Severity.LOW, Severity.MEDIUM, Severity.HIGH, Severity.CRITICAL]),
      outputFormat: this.config.get('outputFormat', OutputFormat.PROBLEMS_PANEL)
    };
  }

  public updateConfiguration(key: string, value: any): void {
    this.config.update(key, value, vscode.ConfigurationTarget.Workspace);
  }

  public getConfiguration(): vscode.WorkspaceConfiguration {
    return this.config;
  }

  public refresh(): void {
    this.config = vscode.workspace.getConfiguration('unagi');
  }
}

export const configManager = ConfigurationManager.getInstance();

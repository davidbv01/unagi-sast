import * as vscode from 'vscode';
import { ScanConfiguration, OutputFormat, Severity } from '../types';

/**
 * Singleton manager for Unagi SAST extension configuration.
 */
export class ConfigurationManager {
  private static instance: ConfigurationManager;
  private config: vscode.WorkspaceConfiguration;

  /**
   * Private constructor to enforce singleton pattern.
   */
  private constructor() {
    this.config = vscode.workspace.getConfiguration('unagi');
  }

  /**
   * Get the singleton instance of ConfigurationManager.
   * @returns The ConfigurationManager instance.
   */
  public static getInstance(): ConfigurationManager {
    if (!ConfigurationManager.instance) {
      ConfigurationManager.instance = new ConfigurationManager();
    }
    return ConfigurationManager.instance;
  }

  /**
   * Get the current scan configuration from workspace settings.
   * @returns The scan configuration object.
   */
  public getScanConfiguration(): ScanConfiguration {
    return {
      enabledRules: this.config.get('enabledRules', []),
      excludePatterns: this.config.get('excludePatterns', ['**/node_modules/**', '**/dist/**', '**/build/**']),
      includePatterns: this.config.get('includePatterns', ['**/*.js', '**/*.ts', '**/*.jsx', '**/*.tsx', '**/*.py', '**/*.java', '**/*.php']),
      severityThreshold: this.config.get('minimumSeverity', [Severity.LOW, Severity.MEDIUM, Severity.HIGH, Severity.CRITICAL])[0],
      outputFormat: this.config.get('outputFormat', OutputFormat.PROBLEMS_PANEL)
    };
  }

  /**
   * Update a configuration key in the workspace settings.
   * @param key The configuration key to update.
   * @param value The new value to set.
   */
  public updateConfiguration(key: string, value: any): void {
    this.config.update(key, value, vscode.ConfigurationTarget.Workspace);
  }

  /**
   * Get the raw VSCode workspace configuration object.
   * @returns The workspace configuration.
   */
  public getConfiguration(): vscode.WorkspaceConfiguration {
    return this.config;
  }

  /**
   * Refresh the configuration from workspace settings.
   */
  public refresh(): void {
    this.config = vscode.workspace.getConfiguration('unagi');
  }
}

/**
 * Singleton instance of the configuration manager.
 */
export const configManager = ConfigurationManager.getInstance();

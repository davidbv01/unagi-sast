import * as fs from 'fs';
import * as path from 'path';
import * as yaml from 'js-yaml';
import * as vscode from 'vscode';
import { Rule } from '../../types';

/**
 * Loads and manages security rules from YAML files for Unagi SAST.
 * Implements a singleton pattern per rules directory.
 */
export class RuleLoader {
  private static readonly instances: Map<string, RuleLoader> = new Map();
  protected readonly rules: Map<string, Rule> = new Map();
  protected readonly rulesDirectory: string;

  /**
   * Private constructor to enforce singleton usage.
   * @param rulesDirectory The directory containing rule YAML files.
   */
  private constructor(rulesDirectory: string) {
    const extensionRoot = vscode.extensions.getExtension('your-publisher-name.unagi')?.extensionPath || path.resolve(__dirname, '..', '..', '..');
    this.rulesDirectory = path.join(extensionRoot, 'out', 'analysis', 'rules', rulesDirectory);
    console.log(`[DEBUG] 📂 Using rules directory: ${this.rulesDirectory}`);
    this.loadRules();
  }

  /**
   * Singleton accessor for each rulesDirectory.
   * @param rulesDirectory The directory containing rule YAML files.
   * @returns The RuleLoader instance for the directory.
   */
  public static getInstance(rulesDirectory: string): RuleLoader {
    if (!this.instances.has(rulesDirectory)) {
      this.instances.set(rulesDirectory, new RuleLoader(rulesDirectory));
    }
    return this.instances.get(rulesDirectory)!;
  }

  /**
   * Loads all rules from the rules directory.
   */
  protected loadRules(): void {
    try {
      console.log(`[DEBUG] 📂 Loading rules from directory: ${this.rulesDirectory}`);
      if (!fs.existsSync(this.rulesDirectory)) {
        console.error(`[ERROR] Rules directory does not exist: ${this.rulesDirectory}`);
        return;
      }
      const files = fs.readdirSync(this.rulesDirectory);
      for (const file of files) {
        if (file.endsWith('.yaml') || file.endsWith('.yml')) {
          try {
            const filePath = path.join(this.rulesDirectory, file);
            const fileContent = fs.readFileSync(filePath, 'utf8');
            const rule = yaml.load(fileContent) as Rule;
            if (this.validateRule(rule)) {
              this.rules.set(rule.id, rule);
            } else {
              console.error(`[ERROR] Invalid rule format in file: ${file}`);
            }
          } catch (fileError) {
            console.error(`[ERROR] Failed to load rule file ${file}:`, fileError);
          }
        }
      }
      console.log(`[DEBUG] 📊 Loaded ${this.rules.size} rules successfully`);
    } catch (error) {
      console.error('[ERROR] Failed to load rules:', error);
      vscode.window.showErrorMessage('Failed to load security rules. Check the console for details.');
    }
  }

  /**
   * Validates a rule object to ensure it meets the required structure.
   * @param rule The rule object to validate.
   * @returns True if valid, false otherwise.
   */
  protected validateRule(rule: any): rule is Rule {
    const requiredFields = ['id', 'name', 'description', 'severity', 'type'];
    const missingFields = requiredFields.filter(field => !(field in rule));
    if (missingFields.length > 0) {
      console.error(`[ERROR] Rule validation failed. Missing fields: ${missingFields.join(', ')}`);
      return false;
    }
    const hasRuleContent = rule.patterns || rule.sources || rule.sinks || rule.sanitizers;
    if (!hasRuleContent) {
      console.error('[ERROR] Rule validation failed. Rule must have at least one of: patterns, sources, sinks, or sanitizers');
      return false;
    }
    return true;
  }

  /**
   * Retrieves a rule by its ID.
   * @param id The rule ID.
   * @returns The Rule object, or undefined if not found.
   */
  public getRule(id: string): Rule | undefined {
    const rule = this.rules.get(id);
    if (!rule) {
      console.warn(`[WARN] Rule not found: ${id}`);
    }
    return rule;
  }

  /**
   * Retrieves all loaded rules.
   * @returns Array of all Rule objects.
   */
  public getAllRules(): Rule[] {
    return Array.from(this.rules.values());
  }

  /**
   * Adds a new rule to the loader.
   * @param rule The Rule object to add.
   */
  public addRule(rule: Rule): void {
    try {
      if (this.validateRule(rule)) {
        this.rules.set(rule.id, rule);
        console.log(`[DEBUG] ✅ Added new rule: ${rule.id}`);
      }
    } catch (error) {
      console.error(`[ERROR] Failed to add rule ${rule.id}:`, error);
    }
  }

  /**
   * Removes a rule by its ID.
   * @param id The rule ID to remove.
   */
  public removeRule(id: string): void {
    try {
      if (this.rules.delete(id)) {
        console.log(`[DEBUG] ✅ Removed rule: ${id}`);
      } else {
        console.warn(`[WARN] Rule not found for removal: ${id}`);
      }
    } catch (error) {
      console.error(`[ERROR] Failed to remove rule ${id}:`, error);
    }
  }

  /**
   * Reloads all rules from the rules directory.
   */
  public reloadRules(): void {
    try {
      console.log('[DEBUG] 🔄 Reloading rules');
      this.rules.clear();
      this.loadRules();
    } catch (error) {
      console.error('[ERROR] Failed to reload rules:', error);
    }
  }
} 
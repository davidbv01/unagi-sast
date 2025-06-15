import * as fs from 'fs';
import * as path from 'path';
import * as yaml from 'js-yaml';
import * as vscode from 'vscode';

export interface Rule {
  id: string;
  name: string;
  description: string;
  severity: string;
  type: string;
  patterns?: unknown;
  sources?: unknown;
  sinks?: unknown;
  sanitizers?: unknown;
}

export class RuleLoader {
  protected rules: Map<string, Rule> = new Map();
  protected rulesDirectory: string;

  constructor(rulesDirectory: string) {
    // Get the extension's root directory
    const extensionRoot = vscode.extensions.getExtension('your-publisher-name.unagi')?.extensionPath || path.resolve(__dirname, '..', '..', '..');
    
    // Use only the out directory path
    this.rulesDirectory = path.join(extensionRoot, 'out', 'analysis', 'rules', rulesDirectory);
    
    console.log(`[DEBUG] 📂 Using rules directory: ${this.rulesDirectory}`);
    this.loadRules();
  }

  protected loadRules(): void {
    try {
      console.log(`[DEBUG] 📂 Loading rules from directory: ${this.rulesDirectory}`);
      
      if (!fs.existsSync(this.rulesDirectory)) {
        console.error(`[ERROR] Rules directory does not exist: ${this.rulesDirectory}`);
        return;
      }

      const files = fs.readdirSync(this.rulesDirectory);
      console.log(`[DEBUG] 📄 Found ${files.length} files in rules directory`);

      for (const file of files) {
        if (file.endsWith('.yaml') || file.endsWith('.yml')) {
          try {
            const filePath = path.join(this.rulesDirectory, file);
            console.log(`[DEBUG] 📖 Loading rule file: ${file}`);
            
            const fileContent = fs.readFileSync(filePath, 'utf8');
            const rule = yaml.load(fileContent) as Rule;
            
            if (this.validateRule(rule)) {
              this.rules.set(rule.id, rule);
              console.log(`[DEBUG] ✅ Successfully loaded rule: ${rule.id}`);
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

  protected validateRule(rule: any): rule is Rule {
    const requiredFields = ['id', 'name', 'description', 'severity', 'type'];
    const missingFields = requiredFields.filter(field => !(field in rule));
    
    if (missingFields.length > 0) {
      console.error(`[ERROR] Rule validation failed. Missing fields: ${missingFields.join(', ')}`);
      return false;
    }

    // Check for at least one of the rule type fields
    const hasRuleContent = rule.patterns || rule.sources || rule.sinks || rule.sanitizers;
    if (!hasRuleContent) {
      console.error('[ERROR] Rule validation failed. Rule must have at least one of: patterns, sources, sinks, or sanitizers');
      return false;
    }

    return true;
  }

  public getRule(id: string): Rule | undefined {
    const rule = this.rules.get(id);
    if (!rule) {
      console.warn(`[WARN] Rule not found: ${id}`);
    }
    return rule;
  }

  public getAllRules(): Rule[] {
    return Array.from(this.rules.values());
  }

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
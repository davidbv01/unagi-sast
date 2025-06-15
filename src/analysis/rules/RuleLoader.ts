import * as fs from 'fs';
import * as path from 'path';
import * as yaml from 'js-yaml';

export interface Rule {
  id: string;
  name: string;
  description: string;
  severity: string;
  type: string;
}

export class RuleLoader {
  protected rules: Map<string, Rule> = new Map();

  constructor(protected rulesDir: string) {}

  protected loadRules(): void {
    const files = fs.readdirSync(this.rulesDir);
    
    for (const file of files) {
      if (file.endsWith('.yaml') || file.endsWith('.yml')) {
        const filePath = path.join(this.rulesDir, file);
        const content = fs.readFileSync(filePath, 'utf8');
        
        try {
          const rule = yaml.load(content) as Rule;
          this.rules.set(rule.id, rule);
        } catch (error) {
          console.error(`Error loading rule from ${file}:`, error);
        }
      }
    }
  }

  public getRule(id: string): Rule | undefined {
    return this.rules.get(id);
  }

  public getAllRules(): Rule[] {
    return Array.from(this.rules.values());
  }

  public addRule(rule: Rule): void {
    this.rules.set(rule.id, rule);
  }

  public removeRule(ruleId: string): void {
    this.rules.delete(ruleId);
  }
} 
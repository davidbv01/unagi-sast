import { Vulnerability, VulnerabilityType, Severity, ScanRule } from '../types';
import { ASTSecurityEngine } from './ASTSecurityEngine';

export class SecurityRuleEngine {
  private rules: ScanRule[];
  private astEngine: ASTSecurityEngine;
  constructor() {
    this.rules = this.loadSecurityRules();
    this.astEngine = new ASTSecurityEngine();
  }

  public async scanContent(content: string, languageId: string, fileName: string): Promise<Vulnerability[]> {
    const vulnerabilities: Vulnerability[] = [];

    // Use AST-based scanning for JavaScript/TypeScript
    if (['javascript', 'typescript', 'jsx', 'tsx'].includes(languageId)) {
      const astVulnerabilities = await this.astEngine.scanContent(content, languageId, fileName);
      vulnerabilities.push(...astVulnerabilities);
    }

    // Continue with regex-based scanning for all languages (fallback and additional coverage)
    const regexVulnerabilities = await this.scanWithRegex(content, languageId, fileName);
    vulnerabilities.push(...regexVulnerabilities);

    // Remove duplicates (same type and line)
    return this.deduplicateVulnerabilities(vulnerabilities);
  }

  private async scanWithRegex(content: string, languageId: string, fileName: string): Promise<Vulnerability[]> {
    const vulnerabilities: Vulnerability[] = [];
    const lines = content.split('\n');

    // Filter rules by language
    const applicableRules = this.rules.filter(rule => 
      rule.enabled && rule.languages.includes(languageId)
    );

    for (let lineIndex = 0; lineIndex < lines.length; lineIndex++) {
      const line = lines[lineIndex];
      
      for (const rule of applicableRules) {
        const matches = line.match(rule.pattern);
        if (matches) {
          const vulnerability: Vulnerability = {
            id: `${rule.id}-${lineIndex}`,
            type: rule.type,
            severity: rule.severity,
            message: rule.name,
            file: fileName,
            line: lineIndex + 1,
            column: matches.index || 0,
            rule: rule.id,
            description: rule.description,
            recommendation: this.getRecommendation(rule.type)
          };
          vulnerabilities.push(vulnerability);
        }
      }
    }

    return vulnerabilities;
  }

  private deduplicateVulnerabilities(vulnerabilities: Vulnerability[]): Vulnerability[] {
    const seen = new Set<string>();
    return vulnerabilities.filter(vuln => {
      const key = `${vuln.type}-${vuln.line}-${vuln.column}`;
      if (seen.has(key)) {
        return false;
      }
      seen.add(key);
      return true;
    });
  }

  private loadSecurityRules(): ScanRule[] {
    return [
      // SQL Injection rules
      {
        id: 'sql-injection-1',
        name: 'Potential SQL Injection',
        description: 'Direct string concatenation in SQL query',
        severity: Severity.HIGH,
        type: VulnerabilityType.SQL_INJECTION,
        pattern: /(SELECT|INSERT|UPDATE|DELETE).*([\+\s]+['"]).*/i,
        languages: ['javascript', 'typescript', 'python', 'java', 'php'],
        enabled: true
      },
      
      // XSS rules
      {
        id: 'xss-1',
        name: 'Potential XSS Vulnerability',
        description: 'Unsafe HTML content insertion',
        severity: Severity.MEDIUM,
        type: VulnerabilityType.XSS,
        pattern: /innerHTML\s*=\s*.*[\+\s].*/,
        languages: ['javascript', 'typescript'],
        enabled: true
      },
      
      // Hardcoded secrets
      {
        id: 'hardcoded-secret-1',
        name: 'Hardcoded API Key',
        description: 'Potential hardcoded API key found',
        severity: Severity.CRITICAL,
        type: VulnerabilityType.HARDCODED_SECRET,
        pattern: /(api[_-]?key|apikey|secret[_-]?key)\s*[=:]\s*['"][a-zA-Z0-9]{16,}['"]/i,
        languages: ['javascript', 'typescript', 'python', 'java', 'php'],
        enabled: true
      },
      
      // Weak cryptography
      {
        id: 'weak-crypto-1',
        name: 'Weak Cryptographic Algorithm',
        description: 'Use of MD5 or SHA1 hash algorithm',
        severity: Severity.MEDIUM,
        type: VulnerabilityType.WEAK_CRYPTO,
        pattern: /(MD5|SHA1|md5|sha1)/,
        languages: ['javascript', 'typescript', 'python', 'java', 'php'],
        enabled: true
      },
      
      // Command injection
      {
        id: 'command-injection-1',
        name: 'Potential Command Injection',
        description: 'Unsafe command execution with user input',
        severity: Severity.HIGH,
        type: VulnerabilityType.COMMAND_INJECTION,
        pattern: /(exec|system|shell_exec|passthru|eval)\s*\(.*([\+\s]+.*|.*\$|.*input)/i,
        languages: ['javascript', 'typescript', 'python', 'php'],
        enabled: true
      },
      
      // Path traversal
      {
        id: 'path-traversal-1',
        name: 'Potential Path Traversal',
        description: 'Unsafe file path construction',
        severity: Severity.MEDIUM,
        type: VulnerabilityType.PATH_TRAVERSAL,
        pattern: /(\.\.[\/\\]|\.\.\\\\)/,
        languages: ['javascript', 'typescript', 'python', 'java', 'php'],
        enabled: true
      }
    ];
  }

  private getRecommendation(type: VulnerabilityType): string {
    const recommendations: Record<VulnerabilityType, string> = {
      [VulnerabilityType.SQL_INJECTION]: 'Use parameterized queries or prepared statements instead of string concatenation.',
      [VulnerabilityType.XSS]: 'Sanitize user input and use safe DOM manipulation methods.',
      [VulnerabilityType.HARDCODED_SECRET]: 'Store secrets in environment variables or secure configuration files.',
      [VulnerabilityType.WEAK_CRYPTO]: 'Use strong cryptographic algorithms like SHA-256 or bcrypt.',
      [VulnerabilityType.COMMAND_INJECTION]: 'Validate and sanitize input before executing commands.',
      [VulnerabilityType.PATH_TRAVERSAL]: 'Validate file paths and use path normalization.',
      [VulnerabilityType.CSRF]: 'Implement CSRF tokens and validate requests.',
      [VulnerabilityType.INSECURE_RANDOM]: 'Use cryptographically secure random number generators.',
      [VulnerabilityType.AUTHORIZATION]: 'Implement proper access controls and permission checks.',
      [VulnerabilityType.AUTHENTICATION]: 'Use secure authentication mechanisms and session management.'
    };
    
    return recommendations[type] || 'Review the code for potential security issues.';
  }
}

import * as assert from 'assert';
import { SecurityRuleEngine } from '../src/scanners/SecurityRuleEngine';
import { VulnerabilityType, Severity } from '../src/types';

suite('Security Rule Engine Test Suite', () => {
    let ruleEngine: SecurityRuleEngine;

    suiteSetup(() => {
        ruleEngine = new SecurityRuleEngine();
    });

    test('Should detect SQL injection vulnerability', async () => {
        const code = `
            const userInput = req.body.id;
            const query = "SELECT * FROM users WHERE id = " + userInput;
            db.query(query);
        `;

        const vulnerabilities = await ruleEngine.scanContent(code, 'javascript', 'test.js');
        
        assert.strictEqual(vulnerabilities.length > 0, true);
        assert.strictEqual(vulnerabilities[0].type, VulnerabilityType.SQL_INJECTION);
        assert.strictEqual(vulnerabilities[0].severity, Severity.HIGH);
    });

    test('Should detect XSS vulnerability', async () => {
        const code = `
            const userInput = req.body.comment;
            document.getElementById('comment').innerHTML = userInput;
        `;

        const vulnerabilities = await ruleEngine.scanContent(code, 'javascript', 'test.js');
        
        assert.strictEqual(vulnerabilities.length > 0, true);
        assert.strictEqual(vulnerabilities[0].type, VulnerabilityType.XSS);
        assert.strictEqual(vulnerabilities[0].severity, Severity.HIGH);
    });

    test('Should detect hardcoded secrets', async () => {
        const code = `
            const apiKey = "sk_test_51Hx123456789abcdefghijklmnopqrstuvwxyz";
            const password = "super_secret_password123";
        `;

        const vulnerabilities = await ruleEngine.scanContent(code, 'javascript', 'test.js');
        
        assert.strictEqual(vulnerabilities.length > 0, true);
        assert.strictEqual(vulnerabilities[0].type, VulnerabilityType.HARDCODED_SECRET);
        assert.strictEqual(vulnerabilities[0].severity, Severity.CRITICAL);
    });
}); 
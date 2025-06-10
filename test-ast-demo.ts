// Quick test to demonstrate AST vs Regex scanning capabilities
import { SecurityRuleEngine } from './src/scanners/SecurityRuleEngine';

async function testASTScanning() {
    const engine = new SecurityRuleEngine();
    
    // Test code with various vulnerabilities
    const testCode = `
// SQL Injection - both regex and AST should detect
const query = "SELECT * FROM users WHERE id = " + userId;

// XSS - AST provides better context
document.getElementById('content').innerHTML = userInput;

// Hardcoded secret - AST can better understand assignments
const apiKey = "sk-1234567890abcdef1234567890abcdef";
const config = {
    secret_key: "super_secret_password_123456"
};

// Command injection - AST understands function calls
const exec = require('child_process').exec;
exec('ls -la ' + userCommand);

// eval usage - clearly dangerous
eval(userInput);

// Weak crypto
const crypto = require('crypto');
const hash = crypto.createHash('md5');
`;

    console.log('🔍 Starting AST + Regex Security Scan...\n');
    
    try {
        const vulnerabilities = await engine.scanContent(testCode, 'javascript', 'test.js');
        
        console.log(`Found ${vulnerabilities.length} vulnerabilities:\n`);
        
        const groupedByType = vulnerabilities.reduce((acc, vuln) => {
            if (!acc[vuln.type]) acc[vuln.type] = [];
            acc[vuln.type].push(vuln);
            return acc;
        }, {} as Record<string, any[]>);
        
        Object.entries(groupedByType).forEach(([type, vulns]) => {
            console.log(`📋 ${type.toUpperCase()} (${vulns.length} found):`);
            vulns.forEach(vuln => {
                const source = vuln.rule.startsWith('ast-') ? '🌳 AST' : '🔤 Regex';
                console.log(`  ${source} Line ${vuln.line}: ${vuln.message}`);
                console.log(`    💡 ${vuln.recommendation}\n`);
            });
        });
        
        // Show the advantage of AST scanning
        const astDetected = vulnerabilities.filter(v => v.rule.startsWith('ast-')).length;
        const regexDetected = vulnerabilities.filter(v => !v.rule.startsWith('ast-')).length;
        
        console.log('📊 Detection Summary:');
        console.log(`   🌳 AST-based rules: ${astDetected} vulnerabilities`);
        console.log(`   🔤 Regex-based rules: ${regexDetected} vulnerabilities`);
        console.log(`   🎯 Total unique vulnerabilities: ${vulnerabilities.length}`);
        
    } catch (error) {
        console.error('❌ Error during scanning:', error);
    }
}

// Run the test
testASTScanning().catch(console.error);

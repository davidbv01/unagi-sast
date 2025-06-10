// Sample vulnerable JavaScript code for testing Unagi SAST extension

// SQL Injection vulnerability
function getUserData(userId) {
    const query = "SELECT * FROM users WHERE id = " + userId; // VULNERABLE: SQL injection
    return db.query(query);
}

// XSS vulnerability
function displayMessage(message) {
    document.getElementById('content').innerHTML = message; // VULNERABLE: XSS
}

// Hardcoded secret
const API_KEY = "sk_1234567890abcdef1234567890abcdef"; // VULNERABLE: Hardcoded secret

// Weak cryptography
const crypto = require('crypto');
function hashPassword(password) {
    return crypto.createHash('md5').update(password).digest('hex'); // VULNERABLE: Weak crypto
}

// Command injection
function executeCommand(userInput) {
    const command = "ls " + userInput; // VULNERABLE: Command injection
    exec(command);
}

// Path traversal
function readFile(fileName) {
    const filePath = "./uploads/" + fileName; // VULNERABLE: Path traversal if fileName contains "../"
    return fs.readFileSync(filePath);
}

// Safe examples (should not trigger alerts)
function safeGetUserData(userId) {
    const query = "SELECT * FROM users WHERE id = ?";
    return db.query(query, [userId]); // SAFE: Parameterized query
}

function safeDisplayMessage(message) {
    document.getElementById('content').textContent = message; // SAFE: textContent instead of innerHTML
}

const API_KEY_SAFE = process.env.API_KEY; // SAFE: Environment variable

function safeHashPassword(password) {
    return crypto.createHash('sha256').update(password).digest('hex'); // SAFE: Strong crypto
}

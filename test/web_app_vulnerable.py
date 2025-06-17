#!/usr/bin/env python3
"""
Web Application Vulnerability Test File for Unagi SAST
Demonstrates web-specific security issues including XSS, CSRF, and injection attacks
"""
import json
import hashlib
import base64
from urllib.parse import unquote

class WebAppVulnerabilities:
    """Class demonstrating various web application security vulnerabilities"""
    
    def __init__(self):
        self.users = {}
        self.sessions = {}
    
    def handle_login(self, request_data):
        """Login handler with multiple vulnerability patterns"""
        
        # SOURCE: HTTP request data - untrusted user input from web forms
        username = request_data.get('username', '')  # SOURCE: web form input
        password = request_data.get('password', '')  # SOURCE: web form input
        remember_me = request_data.get('remember', False)  # SOURCE: checkbox input
        
        # WEAK SANITIZATION: Basic HTML encoding (insufficient for all contexts)
        username = username.replace('<', '&lt;').replace('>', '&gt;')
        # NOTE: This only prevents basic XSS, doesn't handle other injection vectors
        
        # SINK: SQL-like query construction - injection vulnerability
        query = f"SELECT * FROM users WHERE username='{username}' AND password='{password}'"
        print(f"Executing query: {query}")  # SINK: potential SQL injection
        
        # SINK: Log injection - writing untrusted data to logs
        self.log_attempt(f"Login attempt for user: {username}")  # SINK: log injection
        
        # Simulated authentication check
        if self.authenticate_user(username, password):
            # SINK: Session token generation with weak randomness
            session_token = hashlib.md5(f"{username}{password}".encode()).hexdigest()  # SINK: weak crypto
            
            # SINK: Cookie setting without security flags
            cookie_value = f"session={session_token}; user={username}"  # SINK: insecure cookie
            if remember_me:
                cookie_value += "; Max-Age=2592000"  # 30 days
            
            return {"status": "success", "cookie": cookie_value}
        else:
            return {"status": "failed", "message": f"Invalid credentials for {username}"}
    
    def display_user_profile(self, user_data):
        """Profile display with XSS vulnerabilities"""
        
        # SOURCE: User profile data from database/form
        display_name = user_data.get('display_name', '')  # SOURCE: user profile data
        bio = user_data.get('bio', '')  # SOURCE: user input
        website = user_data.get('website', '')  # SOURCE: URL input
        
        # SINK: Direct HTML output without encoding - XSS vulnerability
        profile_html = f"""
        <div class="profile">
            <h2>Welcome, {display_name}!</h2>
            <p>Bio: {bio}</p>
            <a href="{website}">Visit Website</a>
        </div>
        """  # SINK: XSS vulnerability - unescaped user data in HTML
        
        # SINK: JavaScript code generation - XSS vulnerability
        script_tag = f"<script>var userName = '{display_name}';</script>"  # SINK: XSS in script context
        
        return profile_html + script_tag
    
    def search_handler(self, search_params):
        """Search functionality with multiple injection points"""
        
        # SOURCE: Search parameters from URL/form
        search_term = search_params.get('q', '')  # SOURCE: search input
        category = search_params.get('category', 'all')  # SOURCE: dropdown selection
        sort_order = search_params.get('sort', 'date')  # SOURCE: sort parameter
        
        # INSUFFICIENT SANITIZATION: Only URL decoding
        search_term = unquote(search_term)  # Partial sanitization
        # NOTE: URL decoding alone doesn't prevent injection attacks
        
        # SINK: Dynamic SQL ORDER BY clause - SQL injection
        query = f"SELECT * FROM articles WHERE title LIKE '%{search_term}%' ORDER BY {sort_order}"
        print(f"Search query: {query}")  # SINK: SQL injection vulnerability
        
        # SINK: File system access based on user input - path traversal
        category_file = f"/data/categories/{category}.json"  # SINK: path traversal
        try:
            with open(category_file, 'r') as f:  # SINK: file system access
                category_data = json.load(f)
        except FileNotFoundError:
            category_data = {"items": []}
        
        # SINK: Command execution for search indexing - command injection
        import os
        os.system(f"updateindex.sh '{search_term}' '{category}'")  # SINK: command injection
        
        return {"query": search_term, "category": category_data}
    
    def file_upload_handler(self, file_data):
        """File upload with security vulnerabilities"""
        
        # SOURCE: File upload data from HTTP request
        filename = file_data.get('filename', '')  # SOURCE: uploaded filename
        content = file_data.get('content', b'')  # SOURCE: file content
        file_type = file_data.get('type', '')  # SOURCE: MIME type (user-controlled)
        
        # WEAK SANITIZATION: Basic file extension check
        allowed_extensions = ['.jpg', '.png', '.gif', '.pdf']
        if not any(filename.lower().endswith(ext) for ext in allowed_extensions):
            return {"error": "File type not allowed"}
        # NOTE: This check can be bypassed with double extensions or null bytes
        
        # SINK: File path construction - path traversal vulnerability
        upload_path = f"/uploads/{filename}"  # SINK: path traversal
        
        # SINK: File system write with user content
        try:
            with open(upload_path, 'wb') as f:  # SINK: file write
                f.write(content)  # SINK: writing untrusted content
        except Exception as e:
            return {"error": str(e)}
        
        # SINK: Image processing command - potential command injection
        if file_type.startswith('image/'):
            import subprocess
            # Dangerous: using shell=True with user input
            subprocess.run(f"convert {upload_path} -resize 200x200 {upload_path}_thumb.jpg", 
                         shell=True)  # SINK: command injection
        
        return {"success": True, "path": upload_path}
    
    def api_endpoint(self, json_data):
        """API endpoint with deserialization vulnerabilities"""
        
        # SOURCE: JSON data from API request
        user_input = json_data.get('data', '')  # SOURCE: API input
        action = json_data.get('action', '')  # SOURCE: action parameter
        payload = json_data.get('payload', {})  # SOURCE: nested payload
        
        # SINK: Direct deserialization - deserialization vulnerability
        if action == 'execute':
            # Dangerous: evaluating user-provided code
            result = eval(user_input)  # SINK: code injection vulnerability
            return {"result": result}
        
        # SINK: Dynamic module import - code execution
        if action == 'import':
            module_name = payload.get('module', '')  # SOURCE: module name
            # Dangerous: importing user-specified modules
            imported_module = __import__(module_name)  # SINK: dynamic import vulnerability
            return {"module": str(imported_module)}
        
        # SINK: Template injection vulnerability
        if action == 'render':
            template = payload.get('template', '')  # SOURCE: template string
            data = payload.get('data', {})  # SOURCE: template data
            # Dangerous: direct string formatting with user data
            rendered = template.format(**data)  # SINK: template injection
            return {"rendered": rendered}
        
        return {"error": "Unknown action"}
    
    def log_attempt(self, message):
        """Logging function that may be vulnerable to log injection"""
        # SINK: Writing to log file without sanitization
        with open("/var/log/webapp.log", "a") as log_file:  # SINK: log injection
            log_file.write(f"{message}\n")
    
    def authenticate_user(self, username, password):
        """Simulated authentication - always returns True for testing"""
        return True

def demonstrate_secure_practices():
    """Shows secure alternatives to the vulnerable patterns above"""
    
    # SOURCE: Same untrusted input
    user_input = input("Enter search term: ")  # SOURCE: user input
    
    # PROPER SANITIZATION: Whitelist validation
    import re
    if not re.match(r'^[a-zA-Z0-9\s]+$', user_input):  # SANITIZER: regex validation
        print("Invalid input: only alphanumeric characters and spaces allowed")
        return
    
    # SAFE SINK: Parameterized query
    # query = "SELECT * FROM articles WHERE title LIKE ? ORDER BY date"  # SAFE
    # cursor.execute(query, (f"%{user_input}%",))  # SAFE: parameterized query
    
    # SAFE SINK: HTML escaping for output
    import html
    safe_output = html.escape(user_input)  # SANITIZER: HTML encoding
    print(f"Safe HTML output: <p>{safe_output}</p>")
    
    # SAFE SINK: Base64 encoding for data transmission
    encoded_data = base64.b64encode(user_input.encode()).decode()  # SANITIZER: encoding
    print(f"Safe encoded data: {encoded_data}")

if __name__ == "__main__":
    print("=== Web Application Vulnerability Demonstration ===")
    
    app = WebAppVulnerabilities()
    
    # Simulate vulnerable login attempt
    login_data = {
        'username': '<script>alert("xss")</script>',
        'password': "' OR '1'='1",
        'remember': True
    }
    print("Login result:", app.handle_login(login_data))
    
    # Simulate profile display
    profile_data = {
        'display_name': '<img src=x onerror=alert("xss")>',
        'bio': 'My bio with <script>alert("bio")</script>',
        'website': 'javascript:alert("click")'
    }
    print("Profile HTML:", app.display_user_profile(profile_data))
    
    print("\n=== Secure Practices Demo ===")
    demonstrate_secure_practices() 
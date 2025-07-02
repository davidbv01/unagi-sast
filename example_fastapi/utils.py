import os
import subprocess
import sqlite3

def process_user_data(user_input):
    """
    This function processes user input and has a SQL injection vulnerability
    """
    # Sink: SQL injection vulnerability
    conn = sqlite3.connect('database.db')
    cursor = conn.cursor()
    
    # Dangerous: Direct string concatenation in SQL query
    query = f"SELECT * FROM users WHERE name = '{user_input}'"
    cursor.execute(query)
    
    results = cursor.fetchall()
    conn.close()
    return results

def execute_command(command):
    """
    This function executes system commands - VERY DANGEROUS!
    """
    # Sink: Command injection vulnerability
    try:
        # Extremely dangerous: executing user input directly
        result = os.system(command)
        return f"Command executed with result: {result}"
    except Exception as e:
        return f"Error: {str(e)}"

def safe_process_data(user_input):
    """
    This is a safer version that sanitizes input
    """
    # Sanitizer: Input validation and sanitization
    if not user_input or len(user_input) > 100:
        return "Invalid input"
    
    # Remove potentially dangerous characters
    sanitized_input = ''.join(char for char in user_input if char.isalnum() or char.isspace())
    
    # Use parameterized query instead of string concatenation
    conn = sqlite3.connect('database.db')
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM users WHERE name = ?", (sanitized_input,))
    results = cursor.fetchall()
    conn.close()
    return results

def file_operation(filename):
    """
    Path traversal vulnerability
    """
    # Sink: Path traversal vulnerability
    try:
        with open(f"/var/uploads/{filename}", 'r') as f:
            return f.read()
    except Exception as e:
        return f"Error reading file: {str(e)}"
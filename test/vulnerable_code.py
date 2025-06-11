import os
import subprocess
import sqlite3
import pickle
import yaml
from flask import Flask, request

app = Flask(__name__)

# 1. SQL Injection vulnerability
def get_user_data(user_id):
    conn = sqlite3.connect('database.db')
    cursor = conn.cursor()
    # Vulnerable to SQL injection
    query = f"SELECT * FROM users WHERE id = {user_id}"
    cursor.execute(query)
    return cursor.fetchall()

# 2. Command Injection vulnerability
def execute_command(command):
    # Vulnerable to command injection
    return subprocess.check_output(command, shell=True)

# 3. Path Traversal vulnerability
def read_user_file(username):
    # Vulnerable to path traversal
    file_path = f"./users/{username}/profile.txt"
    with open(file_path, 'r') as f:
        return f.read()

# 4. Insecure Deserialization vulnerability
def load_user_data(data):
    # Vulnerable to insecure deserialization
    return pickle.loads(data)

# 5. YAML Deserialization vulnerability
def load_config(config_data):
    # Vulnerable to YAML deserialization
    return yaml.load(config_data)

# 6. Hardcoded credentials
DB_PASSWORD = "super_secret_password_123"
API_KEY = "sk_live_51H7q9K2H7q9K2H7q9K2H7q9K2H7q9K2"

# 7. Insecure file permissions
def create_user_file(username, content):
    # Vulnerable to insecure file permissions
    file_path = f"./users/{username}/data.txt"
    with open(file_path, 'w') as f:
        f.write(content)
    os.chmod(file_path, 0o777)  # Too permissive

# 8. Insecure direct object reference
@app.route('/user/<user_id>')
def get_user(user_id):
    # Vulnerable to IDOR
    return f"User data for ID: {user_id}"

# Example usage
if __name__ == "__main__":
    # SQL Injection
    user_input = request.args.get('id')
    get_user_data(user_input)

    # Command Injection
    cmd = request.form.get('command')
    execute_command(cmd)

    # Path Traversal
    username = request.args.get('username')
    read_user_file(username)

    # Insecure Deserialization
    user_data = request.get_data()
    load_user_data(user_data)

    # YAML Deserialization
    config = request.form.get('config')
    load_config(config)

    # Insecure file permissions
    content = request.form.get('content')
    create_user_file(username, content) 
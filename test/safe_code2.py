import os
import re
import string

def secure_command_processor():
    """Function with complex validation between source and sink"""
    
    # SOURCE: Single user input point
    user_input = input("Enter safe command: ")  # SOURCE: console input
    
    print("Applying security validation...")
    
    # Complex multi-layer validation (SANITIZERS)
    
    # Layer 1: Basic character validation
    if not user_input.isalnum():  # SANITIZER: alphanumeric check
        print("Security Error: Only alphanumeric characters allowed")
        return
    
    # Layer 2: Length validation
    if len(user_input) > 20:  # SANITIZER: length check
        print("Security Error: Input too long (max 20 characters)")
        return
    
    # Layer 3: Whitelist validation using regex
    if not re.match(r'^[a-zA-Z0-9]+$', user_input):  # SANITIZER: regex whitelist
        print("Security Error: Invalid characters detected")
        return
    
    # Layer 4: Blacklist validation for dangerous patterns
    dangerous_patterns = ['system', 'exec', 'eval', 'import', 'open', 'file']
    for pattern in dangerous_patterns:
        if pattern.lower() in user_input.lower():  # SANITIZER: blacklist check
            print(f"Security Error: Dangerous pattern '{pattern}' detected")
            return
    
    # Layer 5: Character set validation
    allowed_chars = set(string.ascii_letters + string.digits)
    if not all(c in allowed_chars for c in user_input):  # SANITIZER: character set validation
        print("Security Error: Unauthorized characters found")
        return
    
    # Layer 6: Additional pattern validation
    if any(char in user_input for char in ['&', '|', ';', '`', '$', '(', ')']):  # SANITIZER: special character check
        print("Security Error: Shell metacharacters not allowed")
        return
    
    print("All security validations passed!")
    validated_input = user_input  # Input is now considered safe
    
    # SINK: Command execution after extensive validation
    safe_command = f"echo 'Safe input: {validated_input}'"
    os.system(safe_command)  # SINK: command execution (should be safe due to validation)
    
    print("Safe command executed successfully")

if __name__ == "__main__":
    secure_command_processor() 
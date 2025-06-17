import os
import time
import hashlib

def process_user_request():
    """Function with long processing path between source and sink"""
    
    # SOURCE: Single user input point
    user_command = input("Enter command to execute: ")  # SOURCE: console input
    
    # Lots of processing in between source and sink
    print("Processing your request...")
    
    # Step 1: Add timestamp
    timestamp = str(int(time.time()))
    processed_command = f"{timestamp}_{user_command}"
    
    # Step 2: Generate hash for logging
    command_hash = hashlib.md5(processed_command.encode()).hexdigest()
    print(f"Request hash: {command_hash}")
    
    # Step 3: Format for execution
    formatted_command = processed_command.replace(f"{timestamp}_", "")
    
    # Step 4: Add logging prefix
    final_command = f"echo 'Executing: {formatted_command}'"
    
    # Step 5: Some conditional logic
    if len(formatted_command) > 0:
        print("Command validation passed")
        
        # Step 6: More processing
        execution_context = {
            'user_input': formatted_command,
            'timestamp': timestamp,
            'hash': command_hash
        }
        
        # Step 7: Extract command for execution
        cmd_to_run = execution_context['user_input']
        
        # Step 8: Final preparation
        ready_command = f"echo 'User says: {cmd_to_run}'"
        
        # SINK: Command execution after long processing chain
        os.system(ready_command)  # SINK: command injection vulnerability
        
        print("Command executed successfully")
    else:
        print("Empty command provided")

if __name__ == "__main__":
    process_user_request() 
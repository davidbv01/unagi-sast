import os

def vulnerable_function():
    name = input("Enter your name: ")
    test = "test"
    greeting = "Hello " + name + name + test
    full_message = greeting + "!"
    
    log_message = "[LOG] " + full_message
    debug_output = log_message.lower()

    os.system("echo " + debug_output)

vulnerable_function()

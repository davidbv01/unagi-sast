import os

def vulnerable_function():
    user_input = input("Enter your name: ") 
    if not user_input.isalnum():  # Simple validation: only alphanumeric characters
        return
    os.system("echo " + user_input)         

vulnerable_function()

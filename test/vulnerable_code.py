import os

def vulnerable_function():
    name = input("Enter your name: ")
    debug = name.lower()
    if not debug.isalnum():  # Simple validation: only alphanumeric characters
        return
    test = debug
    os.system(test)

vulnerable_function()

import os

def vulnerable_function():
    name = input("Enter your name: ")
    test = input("Enter a test string: ")
    test2 = test + name
    test3 = test2 + test
    greeting = "Hello " + name
    debug = greeting.lower()
    if not debug.isalnum():  # Simple validation: only alphanumeric characters
        return
    os.system(debug)

vulnerable_function()

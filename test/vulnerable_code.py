import os

def vulnerable_function():
    name = input("Enter your name: ")
    greeting = "Hello " + name
    debug = greeting.lower()
    os.system(debug)

vulnerable_function()

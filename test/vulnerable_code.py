import os

def vulnerable_function():
    name = input("Enter your name: ")
    debug = name.lower()
    test = debug
    os.system(test)

vulnerable_function()

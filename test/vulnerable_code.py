import os

def vulnerable_function():
    user_input = input("Enter your name: ")
    test = user_input + user_input
    os.system("echo " + test)         

vulnerable_function()
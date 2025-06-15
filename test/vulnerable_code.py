import os

def vulnerable_function():
    user_input = input("Enter your name: ") 
    os.system("echo " + user_input)         

vulnerable_function()
import os

def get_data():
    test = input("Enter your name: ") 
    return test

def random():
    return "random"

def build_query(data):
    return os.system(data)   

query = build_query(get_data())
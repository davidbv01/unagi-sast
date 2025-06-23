import os

def get_data():
    return input("Enter your name: ") 

def random():
    return "random"

def build_query(data):
    return os.system(data)   
query = build_query(get_data())
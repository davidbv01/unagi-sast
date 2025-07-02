from fastapi import FastAPI, Request
from utils import process_user_data, execute_command
import os

app = FastAPI()

@app.post("/process")
async def process_endpoint(request: Request):
    # Source: User input from POST request
    user_data = await request.json()
    user_input = user_data.get("data", "")
    
    # Pass user input to another file's function
    result = process_user_data(user_input)
    return {"result": result}

@app.post("/execute")
async def execute_endpoint(request: Request):
    # Another source: User input that gets passed to a dangerous function
    user_data = await request.json()
    command = user_data.get("command", "")
    
    # This calls a function in utils.py that has a sink
    output = execute_command(command)
    return {"output": output}

@app.get("/config/{config_name}")
async def get_config(config_name: str):
    # Path parameter is also user input
    config_value = process_user_data(config_name)
    return {"config": config_value}
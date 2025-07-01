"""
FastAPI Backend - Main Application
Contains multiple security vulnerabilities for SAST testing
"""
import os
import sys
from fastapi import FastAPI, Request, Response
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from app.api import auth, users, files, admin
from app.core.config import settings
from app.db.database import engine
from app.models import Base

# VULNERABILITY: Hardcoded secret key
SECRET_KEY = "super-secret-key-12345"
secretkey = "super-secret-key-12345"
DEBUG_MODE = True

# VULNERABILITY: Overly permissive CORS
app = FastAPI(
    title="Vulnerable E-Commerce API",
    debug=DEBUG_MODE,
    version="1.0.0"
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # VULNERABILITY: Allow all origins
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Mount static files
app.mount("/static", StaticFiles(directory="static"), name="static")

# Include routers
app.include_router(auth.router, prefix="/api/auth", tags=["auth"])
app.include_router(users.router, prefix="/api/users", tags=["users"])
app.include_router(files.router, prefix="/api/files", tags=["files"])
app.include_router(admin.router, prefix="/api/admin", tags=["admin"])

@app.on_event("startup")
async def startup_event():
    # VULNERABILITY: Database creation without proper error handling
    Base.metadata.create_all(bind=engine)
    
    # VULNERABILITY: Logging sensitive information
    print(f"Database password: {os.getenv('DB_PASSWORD', 'defaultpass')}")
    print(f"Admin token: {SECRET_KEY}")

@app.get("/")
async def root():
    return {"message": "Vulnerable E-Commerce API", "debug": DEBUG_MODE}

@app.get("/health")
async def health_check():
    # VULNERABILITY: Information disclosure
    return {
        "status": "healthy",
        "python_version": sys.version,
        "environment": os.environ.get("ENV", "development"),
        "secret_key": SECRET_KEY[:10] + "...",  # Partial secret exposure
    }

if __name__ == "__main__":
    import uvicorn
    # VULNERABILITY: Running in debug mode in production
    uvicorn.run("main:app", host="0.0.0.0", port=8000, debug=True, reload=True) 
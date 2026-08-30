@echo off
title AI Security Firewall Backend
cd /d "%~dp0"
echo ==============================================================================
echo                 AI Security Firewall Backend (FastAPI)
echo ==============================================================================
echo.

if exist "venv\Scripts\python.exe" (
    echo [INFO] Using virtual environment: venv
    set "PY_CMD=venv\Scripts\python.exe"
) else (
    echo [INFO] Using global Python interpreter
    set "PY_CMD=python"
)

if not exist ".env" (
    echo [WARNING] .env file not found! Creating default .env file...
    (
        echo LLM_MODE=hybrid
        echo SERVER_PORT=8008
        echo SERVER_HOST=0.0.0.0
        echo SUPABASE_URL=https://nsyyulvaedkujuxuguaa.supabase.co
        echo SUPABASE_KEY=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6Im5zeXl1bHZhZWRrdWp1eHVndWFhIiwicm9sZSI6ImFub24iLCJpYXQiOjE3Nzc3MTM4MjQsImV4cCI6MjA5MzI4OTgyNH0.SNQqqEWqF_d7SkAgHJVfxeTLoUBG3PS7OvQ98mHcdrY
        echo API_KEY=YOUR_GEMINI_API_KEY_HERE
    ) > .env
    echo [INFO] Default .env created.
)

echo [INFO] Starting FastAPI server on http://localhost:8008...
echo.
"%PY_CMD%" api_server.py
if errorlevel 1 (
    echo.
    echo [ERROR] Backend server failed to start or crashed.
    pause
)

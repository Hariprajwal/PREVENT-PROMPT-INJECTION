@echo off
title AI Security Firewall Frontend
cd /d "%~dp0"
echo ==============================================================================
echo                 🛡️ AI Security Firewall Frontend (React + Vite)
echo ==============================================================================
echo.

if not exist "node_modules\" (
    echo [INFO] node_modules not found. Installing dependencies via npm...
    call npm install
    if errorlevel 1 (
        echo [ERROR] npm install failed!
        pause
        exit /b 1
    )
)

echo [INFO] Starting Vite development server on http://localhost:5173...
echo.
call npm run dev
if errorlevel 1 (
    echo.
    echo [ERROR] Frontend server stopped unexpectedly.
    pause
)

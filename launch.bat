@echo off
setlocal enabledelayedexpansion
title PREVENT-PROMPT-INJECTION - Application Launcher
cd /d "%~dp0"

set "ROOT_DIR=%~dp0"
set "BACKEND_DIR=%ROOT_DIR%CyberSecurity_For_ai_backend"
set "FRONTEND_DIR=%ROOT_DIR%CyberSecurity_For_ai_frontend"

:MENU
cls
echo ==============================================================================
echo                 PREVENT-PROMPT-INJECTION LAUNCHER
echo              Advanced AI Security Firewall and Guardrails UI
echo ==============================================================================
echo.
echo  Select an option to launch:
echo.
echo    [1] Start Full Application (Backend API + Frontend UI + Open Browser)
echo    [2] Start Backend Only (FastAPI Server - Port 8008)
echo    [3] Start Frontend Only (React Vite UI - Port 5173)
echo    [4] Setup / Verify Dependencies (Python and Node.js)
echo    [5] Exit
echo.
set /p CHOICE="Enter choice [1-5] (Default is 1): "

if "%CHOICE%"=="" set CHOICE=1
if "%CHOICE%"=="1" goto START_FULL
if "%CHOICE%"=="2" goto START_BACKEND
if "%CHOICE%"=="3" goto START_FRONTEND
if "%CHOICE%"=="4" goto SETUP_DEPS
if "%CHOICE%"=="5" goto EXIT_SCRIPT

echo Invalid option selected.
timeout /t 2 >nul
goto MENU

:START_FULL
cls
echo ==============================================================================
echo               Launching PREVENT-PROMPT-INJECTION Full Application
echo ==============================================================================
echo.
echo 1/3 Starting Backend Server (FastAPI on Port 8008)...
start "AI Security Backend (Port 8008)" cmd /k "cd /d "%BACKEND_DIR%" && call start_backend.bat"

echo 2/3 Starting Frontend UI (Vite on Port 5173)...
start "AI Security Frontend (Port 5173)" cmd /k "cd /d "%FRONTEND_DIR%" && call start_frontend.bat"

echo.
echo 3/3 Opening Web App in Browser...
timeout /t 3 >nul
start http://localhost:5173/

echo.
echo ==============================================================================
echo  SUCCESS: Application is running!
echo     - Backend API:  http://localhost:8008
echo     - Frontend UI:   http://localhost:5173
echo ==============================================================================
echo  Keep the opened terminal windows running while using the application.
echo.
pause
goto MENU

:START_BACKEND
cls
echo ==============================================================================
echo                     Launching Backend API Server
echo ==============================================================================
echo.
start "AI Security Backend (Port 8008)" cmd /k "cd /d "%BACKEND_DIR%" && call start_backend.bat"
echo Backend launched in a new window.
timeout /t 3 >nul
goto MENU

:START_FRONTEND
cls
echo ==============================================================================
echo                     Launching Frontend UI Server
echo ==============================================================================
echo.
start "AI Security Frontend (Port 5173)" cmd /k "cd /d "%FRONTEND_DIR%" && call start_frontend.bat"
echo Frontend launched in a new window.
timeout /t 3 >nul
goto MENU

:SETUP_DEPS
cls
echo ==============================================================================
echo                 Checking and Setting Up Dependencies
echo ==============================================================================
echo.

echo [1/2] Checking Backend Python Setup...
if exist "%BACKEND_DIR%\venv\Scripts\python.exe" (
    echo   Virtual environment found in backend\venv.
    echo   Installing/Updating Python requirements...
    "%BACKEND_DIR%\venv\Scripts\python.exe" -m pip install -r "%BACKEND_DIR%\requirements.txt"
) else (
    echo   No venv found in backend folder. Using system python...
    python -m pip install -r "%BACKEND_DIR%\requirements.txt"
)

echo.
echo [2/2] Checking Frontend Node.js Setup...
if exist "%FRONTEND_DIR%\package.json" (
    echo   Installing Frontend npm packages...
    cd /d "%FRONTEND_DIR%"
    call npm install
    cd /d "%ROOT_DIR%"
)

echo.
echo ==============================================================================
echo  Dependencies verification completed.
echo ==============================================================================
pause
goto MENU

:EXIT_SCRIPT
echo.
echo Goodbye!
timeout /t 1 >nul
exit /b 0

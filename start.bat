@echo off
setlocal
cd /d "%~dp0"

REM Security Advisory Processing System - Windows launcher (dev / online install)
if not exist ".venv" (
    echo [setup] Creating virtual environment...
    python -m venv .venv
)
call .venv\Scripts\activate.bat

REM Install deps only if not already importable (robust against partial installs)
python -c "import uvicorn" >nul 2>nul
if errorlevel 1 (
    echo [setup] Installing dependencies...
    python -m pip install -q --upgrade pip
    python -m pip install -q -r requirements.txt
)

echo [run] http://localhost:8000   (UI: /  |  API docs: /docs)
python -m uvicorn app.main:app --host 0.0.0.0 --port 8000

@echo off
setlocal enabledelayedexpansion
cd /d "%~dp0"

REM Security Advisory Processing System - Windows launcher (closed-network first)
REM ASCII-only + CRLF on purpose: Korean text / LF endings break .bat parsing on
REM Korean (CP949) consoles. Keep this file ASCII so it never fails to parse.
REM
REM Closed-network premise: the RUN path never touches the internet.
REM   - Dependencies install ONLY from local offline wheels (vendor\wheels).
REM   - The one-time online step to collect wheels is scripts\prepare_offline.bat.
REM   - To force a PyPI online install on a dev PC, set ADVISORY_ONLINE_INSTALL=1.
REM On any failure we PAUSE so the window stays open and the error is readable.

REM --- 0) Find Python (python first, then py launcher) ----------------------
set "PY=python"
where python >nul 2>nul
if errorlevel 1 (
    where py >nul 2>nul
    if errorlevel 1 (
        echo.
        echo [ERROR] Python not found on PATH.
        echo   - For a fully offline target, use the all-in-one bundle
        echo     ^(build_allinone.py^) which embeds Python - no install needed.
        echo   - Otherwise install Python 3.10+ and check "Add python.exe to PATH".
        goto :fail
    )
    set "PY=py"
)

REM --- 1) Virtual environment ----------------------------------------------
if not exist ".venv" (
    echo [setup] Creating virtual environment...
    %PY% -m venv .venv
    if errorlevel 1 (
        echo [ERROR] Failed to create .venv. Check your Python installation.
        goto :fail
    )
)
call .venv\Scripts\activate.bat
if errorlevel 1 (
    echo [ERROR] Failed to activate .venv ^(.venv\Scripts\activate.bat^).
    echo   Delete the .venv folder and run start.bat again.
    goto :fail
)

REM --- 2) Dependencies (skip if uvicorn already importable) ----------------
python -c "import uvicorn" >nul 2>nul
if errorlevel 1 (
    set "WHEELS=vendor\wheels"
    if defined ADVISORY_WHEELS_DIR set "WHEELS=!ADVISORY_WHEELS_DIR!"
    if exist "!WHEELS!\*.whl" (
        echo [setup] Installing from offline wheels: !WHEELS!  ^(no internet^)
        python -m pip install -q --no-index --find-links "!WHEELS!" -r requirements.txt
        if errorlevel 1 (
            echo [ERROR] Offline install from "!WHEELS!" failed.
            goto :fail
        )
    ) else if "%ADVISORY_ONLINE_INSTALL%"=="1" (
        echo [setup] Online install from PyPI ^(ADVISORY_ONLINE_INSTALL=1^)...
        python -m pip install -q --upgrade pip
        python -m pip install -q -r requirements.txt
        if errorlevel 1 (
            echo [ERROR] Dependency install failed. Check internet / proxy / firewall.
            goto :fail
        )
    ) else (
        echo.
        echo [ERROR] No dependencies and no offline wheels at "!WHEELS!".
        echo   Closed network: on an internet-connected PC run
        echo     scripts\prepare_offline.bat
        echo   then copy the generated "vendor\wheels" folder here with the app.
        echo   To allow a PyPI online install on a dev PC:
        echo     set ADVISORY_ONLINE_INSTALL=1  ^&^&  start.bat
        goto :fail
    )
    python -c "import uvicorn" >nul 2>nul
    if errorlevel 1 (
        echo [ERROR] uvicorn still not importable after install.
        goto :fail
    )
)

REM --- 3) Run --------------------------------------------------------------
echo [run] http://localhost:8000   ^(UI: /  ^|  API docs: /docs^)
echo [run] Press Ctrl+C in this window to stop the server.
python -m uvicorn app.main:app --host 0.0.0.0 --port 8000
set "RC=!errorlevel!"
if not "!RC!"=="0" (
    echo.
    echo [ERROR] Server exited abnormally ^(exit code !RC!^).
    echo   - Most common cause: port 8000 already in use
    echo     ^(if you already ran start.bat once, close that window first^)
    echo   - Check the port:  netstat -ano ^| findstr :8000
    goto :fail
)

echo [run] Server stopped normally.
pause
exit /b 0

:fail
echo.
echo ============================================================
echo  Startup stopped. Read the message above.
echo  This window will NOT auto-close. Press any key to close it.
echo ============================================================
pause
exit /b 1

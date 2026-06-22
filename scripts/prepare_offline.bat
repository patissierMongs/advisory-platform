@echo off
setlocal
cd /d "%~dp0.."

REM Offline deployment prep - run ONCE on an internet-connected PC.
REM Downloads requirements.txt deps as wheels into vendor\wheels so the closed
REM network target can install with --no-index (no internet). This is the ONLY
REM step that needs the internet. ASCII-only + CRLF (CP949-safe .bat).

set "WHEELS=vendor\wheels"
if defined ADVISORY_WHEELS_DIR set "WHEELS=%ADVISORY_WHEELS_DIR%"
if not exist "%WHEELS%" mkdir "%WHEELS%"

echo [prepare] Collecting wheels for requirements.txt into %WHEELS%
python -m pip download -r requirements.txt -d "%WHEELS%"
if errorlevel 1 goto :fail
python -m pip download pip setuptools wheel -d "%WHEELS%"

echo [prepare] Done. Copy "%WHEELS%" with the project to the closed network.
echo [prepare] NOTE: run this on the SAME OS/CPU/Python as the target
echo [prepare]       (e.g. Windows x64, cp312) so binary wheels match.
exit /b 0

:fail
echo [ERROR] pip download failed. Check internet / proxy / firewall.
exit /b 1

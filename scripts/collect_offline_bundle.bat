@echo off
setlocal
cd /d "%~dp0.."

REM All-in-one offline asset collection - run ONCE on an internet-connected PC.
REM Downloads the embedded Python runtimes (3.12 + 3.13, sha256-verified) and the
REM win_amd64 wheels into vendor\bundle. Copy that folder with the project to the
REM closed network, then build there with:
REM     python build_allinone.py --python all --offline
REM This is the ONLY step that needs the internet.
REM ASCII-only + CRLF (CP949-safe .bat).

set "PY=python"
where python >nul 2>nul
if errorlevel 1 (
    where py >nul 2>nul
    if errorlevel 1 (
        echo [ERROR] Python not found on PATH ^(need python or py launcher^).
        echo   - Any Python 3.10+ works here; the bundle target version is separate.
        exit /b 1
    )
    set "PY=py"
)

echo [collect] Using interpreter: %PY%
%PY% scripts\collect_offline_bundle.py %*
if errorlevel 1 goto :fail

echo [collect] Done. Copy the whole project folder including vendor\bundle.
exit /b 0

:fail
echo [ERROR] Collection failed. Check internet / proxy / firewall.
exit /b 1

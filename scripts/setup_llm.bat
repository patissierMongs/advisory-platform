@echo off
REM Local LLM (Ollama) portable setup - ONLINE pull (needs internet)
REM Usage:  scripts\setup_llm.bat [model]   (default: qwen3:8b)
setlocal
set "MODEL=%~1"
if "%MODEL%"=="" set "MODEL=qwen3:8b"

where ollama >nul 2>nul
if errorlevel 1 (
  echo [!] Ollama is not installed.
  echo     Install from https://ollama.com/download then run again.
  exit /b 1
)

echo [setup] Checking Ollama service...
start "" /b ollama serve >nul 2>nul

echo [setup] Pulling model: %MODEL%  (first time, several GB)
ollama pull %MODEL%
if errorlevel 1 ( echo [!] Model pull failed & exit /b 1 )

echo.
echo [done] To enable LLM CVE extraction (current session):
echo     set ADVISORY_LLM_ENABLED=true
echo     set ADVISORY_LLM_MODEL=%MODEL%
echo Then run start.bat to launch the server.
echo Status: http://localhost:8000/api/v1/llm/status
endlocal

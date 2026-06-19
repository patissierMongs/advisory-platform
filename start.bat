@echo off
setlocal enabledelayedexpansion
cd /d "%~dp0"

REM Security Advisory Processing System - Windows launcher (dev / online install)
REM 창이 떴다 바로 닫히는 문제 방지: 어떤 단계에서 실패해도 메시지를 남기고 멈춤(pause).

REM --- 0) Python 확인 (python 우선, 없으면 py 런처) ---------------------------
set "PY=python"
where python >nul 2>nul
if errorlevel 1 (
    where py >nul 2>nul
    if errorlevel 1 (
        echo.
        echo [오류] Python 을 찾을 수 없습니다.
        echo   - https://www.python.org/downloads/ 에서 Python 3.10+ 설치
        echo   - 설치 시 "Add python.exe to PATH" 체크
        echo   - (Microsoft Store 의 python 스텁이면 정식 버전 설치 필요)
        goto :fail
    )
    set "PY=py"
)

REM --- 1) 가상환경 -------------------------------------------------------------
if not exist ".venv" (
    echo [setup] 가상환경 생성 중...
    %PY% -m venv .venv
    if errorlevel 1 (
        echo [오류] 가상환경(.venv) 생성 실패. Python 설치 상태를 확인하세요.
        goto :fail
    )
)
call .venv\Scripts\activate.bat
if errorlevel 1 (
    echo [오류] 가상환경 활성화 실패(.venv\Scripts\activate.bat).
    echo   .venv 폴더를 삭제하고 다시 실행해 보세요.
    goto :fail
)

REM --- 2) 의존성 (uvicorn import 가능하면 건너뜀) ------------------------------
python -c "import uvicorn" >nul 2>nul
if errorlevel 1 (
    echo [setup] 의존성 설치 중... (최초 1회, 수 분 소요 가능)
    python -m pip install -q --upgrade pip
    python -m pip install -q -r requirements.txt
    if errorlevel 1 (
        echo [오류] 의존성 설치 실패. 인터넷 연결/프록시/방화벽을 확인하세요.
        echo   폐쇄망이면 사내 PyPI 미러 또는 오프라인 패키지가 필요합니다.
        goto :fail
    )
    python -c "import uvicorn" >nul 2>nul
    if errorlevel 1 (
        echo [오류] 설치 후에도 uvicorn 을 불러올 수 없습니다.
        goto :fail
    )
)

REM --- 3) 실행 ----------------------------------------------------------------
echo [run] http://localhost:8000   (UI: /  ^|  API docs: /docs)
echo [run] 종료하려면 이 창에서 Ctrl+C 를 누르세요.
python -m uvicorn app.main:app --host 0.0.0.0 --port 8000
set "RC=!errorlevel!"
if not "!RC!"=="0" (
    echo.
    echo [오류] 서버가 비정상 종료했습니다 (exit code !RC!).
    echo   - 자주 나는 원인: 8000 포트를 다른 프로그램이 사용 중
    echo     ^(start.bat 을 이미 한 번 실행했다면 그 창을 먼저 닫으세요^)
    echo   - 포트 사용 확인:  netstat -ano ^| findstr :8000
    echo   - 위에 출력된 빨간 메시지를 그대로 캡처해 공유해 주세요.
    goto :fail
)

echo [run] 서버가 정상 종료되었습니다.
pause
exit /b 0

:fail
echo.
echo ============================================================
echo  실행이 중단되었습니다. 위 메시지를 확인하세요.
echo  이 창은 자동으로 닫히지 않습니다 (아무 키나 누르면 닫힘).
echo ============================================================
pause
exit /b 1

@echo off
setlocal
cd /d "%~dp0.."

REM Re-apply NTFS access restrictions to the data folder.
REM ASCII-only + CRLF on purpose: Korean text / LF endings break .bat parsing on
REM Korean (CP949) consoles. Keep this file ASCII so it never fails to parse.
REM
REM The server applies this automatically on first start. Run this manually when:
REM   - the automatic step printed a warning,
REM   - the data folder was moved, restored from backup, or copied,
REM   - the service account changed.
REM
REM Well-known SIDs are used instead of group names so this works on localized
REM Windows (Korean, etc.) where "Administrators" is not the displayed name.
REM   *S-1-5-18     = SYSTEM
REM   *S-1-5-32-544 = Administrators

set "DATA=%ADVISORY_DATA_DIR%"
if "%DATA%"=="" set "DATA=%CD%\data"

if not exist "%DATA%" (
    echo [ERROR] Data folder not found: "%DATA%"
    echo   Start the server once first, or set ADVISORY_DATA_DIR.
    goto :fail
)

echo [acl] Target: "%DATA%"
echo [acl] Account: %USERDOMAIN%\%USERNAME%

REM /inheritance:r drops inherited ACEs - this is what actually removes the
REM default read access that ordinary users get from the parent folder.
icacls "%DATA%" /inheritance:r /grant:r "*S-1-5-18:(OI)(CI)F" "*S-1-5-32-544:(OI)(CI)F" "%USERDOMAIN%\%USERNAME%:(OI)(CI)F" /T /C /Q
if errorlevel 1 (
    echo [ERROR] icacls failed. Run this window as Administrator and retry.
    goto :fail
)

echo.
echo [acl] Done. Current permissions:
icacls "%DATA%"
echo.
echo [acl] NOTE: this blocks standard users and network share access.
echo [acl]       Other local Administrators on this PC can still take ownership
echo [acl]       and read the files. Use a dedicated low-privilege service
echo [acl]       account if you need protection against them.
pause
exit /b 0

:fail
echo.
pause
exit /b 1

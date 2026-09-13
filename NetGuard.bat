@echo off
REM NetGuard one-click launcher (Windows). Double-click to run.
REM Locates Python, hands off to scripts\launch.py; args are passed through.
REM   NetGuard.bat                 start GUI
REM   NetGuard.bat --list-devices  list capture devices
REM   NetGuard.bat --check         environment self-check only
REM   NetGuard.bat --read x.pcap   offline replay
setlocal enabledelayedexpansion

set "PROJECT_DIR=%~dp0"
set "LAUNCH=%PROJECT_DIR%scripts\launch.py"

if not exist "%LAUNCH%" (
    echo [NetGuard] launch.py not found: %LAUNCH%
    echo [NetGuard] Please keep this script in the NetGuard repository root.
    pause
    exit /b 1
)

set "PY="
if exist "%PROJECT_DIR%.venv\Scripts\python.exe" set "PY=%PROJECT_DIR%.venv\Scripts\python.exe"
if not defined PY (
    where py >nul 2>nul && set "PY=py -3"
)
if not defined PY (
    where python >nul 2>nul && set "PY=python"
)
if not defined PY (
    echo [NetGuard] Python 3.11+ not found on PATH.
    echo [NetGuard] Install Python, then run in the project root:
    echo     python -m venv .venv
    echo     .\.venv\Scripts\python.exe -m pip install -e .
    pause
    exit /b 1
)

%PY% "%LAUNCH%" %*
set "CODE=!ERRORLEVEL!"
if not "!CODE!"=="0" (
    echo.
    echo [NetGuard] exited with code !CODE!.
    pause
)
exit /b !CODE!

@echo off
REM NetGuard Windows 启动脚本（批处理包装）
REM 实际逻辑见 run_netguard.ps1，这里通过 PowerShell 调用。
setlocal

set "PROJECT_DIR=%~dp0.."
set "PS_SCRIPT=%~dp0run_netguard.ps1"

powershell -NoProfile -ExecutionPolicy Bypass -File "%PS_SCRIPT%" %*
exit /b %ERRORLEVEL%

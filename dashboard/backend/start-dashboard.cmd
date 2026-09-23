@echo off
setlocal
cd /d "%~dp0"
set "DASHBOARD_PYTHON=%~dp0.venv\Scripts\python.exe"
if not exist "%DASHBOARD_PYTHON%" set "DASHBOARD_PYTHON=%~dp0..\..\.venv\Scripts\python.exe"
if not exist "%DASHBOARD_PYTHON%" set "DASHBOARD_PYTHON=python"
"%DASHBOARD_PYTHON%" run.py %*

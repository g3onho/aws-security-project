@echo off
setlocal
REM 대시보드 백엔드 기동. 화면 자산은 ..\frontend\ 를 그대로 쓴다.
set "PYTHON_RUNTIME=%USERPROFILE%\.cache\codex-runtimes\codex-primary-runtime\dependencies\python\python.exe"
if exist "%PYTHON_RUNTIME%" (
  "%PYTHON_RUNTIME%" "%~dp0run.py" %*
) else (
  python "%~dp0run.py" %*
)

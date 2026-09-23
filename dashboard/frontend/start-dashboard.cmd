@echo off
setlocal
REM Launch the redesigned backend.
call "%~dp0..\backend\start-dashboard.cmd" %*
exit /b %errorlevel%

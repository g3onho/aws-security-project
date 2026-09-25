@echo off
REM Windows launcher: runs cpustart.sh via Git Bash.
REM bash.exe on PATH may be the WSL stub, so locate Git Bash explicitly.
setlocal
set "SH=%~dp0cpustart.sh"
set "GB="

if exist "%ProgramFiles%\Git\bin\bash.exe" set "GB=%ProgramFiles%\Git\bin\bash.exe"
if not defined GB if exist "%ProgramW6432%\Git\bin\bash.exe" set "GB=%ProgramW6432%\Git\bin\bash.exe"
if not defined GB if exist "%LOCALAPPDATA%\Programs\Git\bin\bash.exe" set "GB=%LOCALAPPDATA%\Programs\Git\bin\bash.exe"

if not defined GB (
  echo Git Bash not found. Install from https://git-scm.com/download/win 1>&2
  exit /b 1
)

"%GB%" "%SH%" %*
exit /b %ERRORLEVEL%

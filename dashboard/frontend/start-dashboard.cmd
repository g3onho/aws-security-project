@echo off
setlocal
REM 서버 코드는 ..\backend\ 로 옮겼다. 이 런처는 그쪽 run.py 를 그대로 호출한다.
REM (기존 더블클릭 습관을 깨지 않기 위해 남겨둔 얇은 위임 스크립트다.)
call "%~dp0..\backend\start-dashboard.cmd" %*

@echo off
setlocal enabledelayedexpansion

set "ROOT=%~dp0"
if "%ROOT:~-1%"=="\" set "ROOT=%ROOT:~0,-1%"
set "PID_FILE=%ROOT%\.pids.tmp"
set "LOG_DIR=%ROOT%\log"

rem Create log directory
if not exist "%LOG_DIR%" mkdir "%LOG_DIR%"

rem Clean up old PID file
if exist "%PID_FILE%" del "%PID_FILE%"

echo ============================================
echo  WatchVuln Start Script
echo ============================================
echo.

echo [1/3] Starting webhook_receiver...
powershell -Command "$p = Start-Process go -ArgumentList 'run','.\web\webhook_receiver.go' -WorkingDirectory '%ROOT%' -RedirectStandardOutput '%LOG_DIR%\webhook_receiver.txt' -RedirectStandardError '%LOG_DIR%\webhook_receiver_err.txt' -WindowStyle Hidden -PassThru; $p.Id | Out-File -Append '%PID_FILE%'"

echo     Waiting for port 1111...
:wait_webhook
timeout /t 1 /nobreak >nul
netstat -ano | findstr ":1111 " | findstr "LISTENING" >nul 2>&1
if errorlevel 1 goto wait_webhook
echo     webhook_receiver is ready!
echo.

echo [2/3] Starting WatchPoc...
powershell -Command "$p = Start-Process go -ArgumentList 'run','.\WatchPoc.go' -WorkingDirectory '%ROOT%\poc' -RedirectStandardOutput '%LOG_DIR%\watchpoc.txt' -RedirectStandardError '%LOG_DIR%\watchpoc_err.txt' -WindowStyle Hidden -PassThru; $p.Id | Out-File -Append '%PID_FILE%'"
echo     WatchPoc started.
echo.

timeout /t 2 /nobreak >nul

echo [3/3] Starting main program...
powershell -Command "$p = Start-Process go -ArgumentList 'run','.','--webhook-url','http://127.0.0.1:1111/webhook','--test' -WorkingDirectory '%ROOT%' -RedirectStandardOutput '%LOG_DIR%\main.txt' -RedirectStandardError '%LOG_DIR%\main_err.txt' -WindowStyle Hidden -PassThru; $p.Id | Out-File -Append '%PID_FILE%'"
echo     Main program started.
echo.

echo ============================================
echo  All programs are running in background.
echo  Logs: log\webhook_receiver.txt
echo        log\watchpoc.txt
echo        log\main.txt
echo.
echo  Press any key to STOP all programs...
echo ============================================
pause >nul

echo.
echo Stopping all programs...

rem Kill by port 1111
for /f "tokens=5" %%p in ('netstat -ano ^| findstr ":1111 " ^| findstr "LISTENING" 2^>nul') do (
    echo Killing process on port 1111 (PID: %%p)
    taskkill /pid %%p /f /t >nul 2>&1
)

rem Kill all go.exe processes
echo Killing all go.exe processes...
taskkill /im go.exe /f /t >nul 2>&1

rem Kill processes by saved PIDs (if any)
if exist "%PID_FILE%" (
    for /f %%p in (%PID_FILE%) do (
        taskkill /pid %%p /f /t >nul 2>&1
    )
    del "%PID_FILE%"
)

timeout /t 1 /nobreak >nul
echo Done. All programs stopped.
echo.
pause
endlocal

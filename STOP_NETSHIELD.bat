@echo off
title NetShield AI - Shutdown Service
color 0C

echo ===============================================================================
echo                STOPPING NETSHIELD AI SERVICES
echo ===============================================================================
echo.

echo [*] Terminating Backend process on port 8000...
for /f "tokens=5" %%a in ('netstat -aon ^| findstr ":8000" ^| findstr "LISTENING"') do (
    taskkill /F /PID %%a >nul 2>nul
    echo [*] Stopped process %%a on port 8000
)

echo [*] Terminating Frontend process on port 3000...
for /f "tokens=5" %%a in ('netstat -aon ^| findstr ":3000" ^| findstr "LISTENING"') do (
    taskkill /F /PID %%a >nul 2>nul
    echo [*] Stopped process %%a on port 3000
)

echo [*] Cleaning up Node and Uvicorn zombie tasks...
taskkill /F /FI "WINDOWTITLE eq NetShield Backend*" >nul 2>nul
taskkill /F /FI "WINDOWTITLE eq NetShield Frontend*" >nul 2>nul

echo.
echo ===============================================================================
echo  All NetShield AI services have been stopped.
echo ===============================================================================
pause

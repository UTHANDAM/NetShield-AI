@echo off
title NetShield AI - Enterprise SOC Platform Launcher
color 0A

echo ===============================================================================
echo                NETSHIELD AI - ENTERPRISE SOC PLATFORM
echo          AI-Powered Network Anomaly Detection & Threat Monitoring
echo ===============================================================================
echo.

:: Check Python
where py >nul 2>nul
if %ERRORLEVEL% EQU 0 (
    set PY_CMD=py -3.12
) else (
    set PY_CMD=python
)

echo [*] Detected Python command: %PY_CMD%
echo [*] Checking backend dependencies...
cd /d "%~dp0backend"
%PY_CMD% -c "import fastapi, uvicorn, sklearn, xgboost" >nul 2>nul
if %ERRORLEVEL% NEQ 0 (
    echo [!] Installing required backend packages...
    %PY_CMD% -m pip install -r requirements.txt
)

echo [*] Launching NetShield AI FastAPI Backend on http://localhost:8000 ...
start "NetShield AI - Backend (Port 8000)" cmd /k "title NetShield Backend && cd /d "%~dp0backend" && %PY_CMD% -m uvicorn app.main:app --host 0.0.0.0 --port 8000 --reload"

echo [*] Waiting for Backend to initialize...
timeout /t 3 /nobreak >nul

echo [*] Launching NetShield AI Next.js Frontend on http://localhost:3000 ...
start "NetShield AI - Frontend (Port 3000)" cmd /k "title NetShield Frontend && cd /d "%~dp0frontend" && npm run dev"

echo [*] Waiting for Frontend dev server to start...
timeout /t 5 /nobreak >nul

echo [*] Opening NetShield AI Web Console in your default browser...
start http://localhost:3000

echo.
echo ===============================================================================
echo  NetShield AI is running!
echo  - Frontend Web UI:    http://localhost:3000
echo  - Backend API Docs:   http://localhost:8000/docs
echo  - Live Traffic Stream: ws://localhost:8000/api/traffic/ws
echo.
echo  Default Credentials:
echo    Administrator: admin@netshield.ai  / Admin@123456
echo    SOC Analyst:   analyst@netshield.ai / Analyst@123456
echo    Viewer:        viewer@netshield.ai  / Viewer@123456
echo.
echo  Run STOP_NETSHIELD.bat to stop all running services.
echo ===============================================================================
pause

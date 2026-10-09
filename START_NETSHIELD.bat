@echo off
echo ===================================================
echo Starting NetShield AI Services via Docker Compose...
echo ===================================================
docker compose up -d
echo.
echo NetShield AI is running!
echo Frontend: http://localhost:3000
echo Backend API: http://localhost:5000/docs
pause

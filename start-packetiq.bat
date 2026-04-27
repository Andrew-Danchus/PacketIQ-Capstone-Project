@echo off
title PacketIQ Launcher

echo Starting PacketIQ...
echo.

docker --version >nul 2>&1
IF ERRORLEVEL 1 (
    echo Docker is not installed or not running.
    echo Please install Docker Desktop and start it.
    pause
    exit /b
)

echo Building and starting containers...
docker compose up --build -d

echo.
echo Waiting for services to start...
timeout /t 8 >nul

echo.
echo Pulling Ollama model if needed...
docker compose exec ollama ollama pull llama3.2

echo.
echo PacketIQ is running.
echo Frontend: http://localhost:5173
echo Backend Docs: http://localhost:8000/docs
echo.
start http://localhost:5173

pause
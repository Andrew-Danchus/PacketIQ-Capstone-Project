@echo off
title PacketIQ Launcher

echo Starting PacketIQ...
echo.

docker info >nul 2>&1
IF %ERRORLEVEL% NEQ 0 (
    echo Docker is not running. Trying to start Docker Desktop...

    start "" "C:\Program Files\Docker\Docker\Docker Desktop.exe"

    echo Waiting for Docker to start...
    timeout /t 20 >nul

    :WAIT_DOCKER
    docker info >nul 2>&1
    IF %ERRORLEVEL% NEQ 0 (
        echo Docker is still starting...
        timeout /t 10 >nul
        goto WAIT_DOCKER
    )
)

echo Docker is running.
echo.

echo Building and starting PacketIQ...
docker compose up --build -d

echo.
echo Pulling Ollama model if needed...
docker compose exec ollama ollama pull llama3.2

echo.
echo PacketIQ is running.
echo Opening browser...
start http://localhost:5173

echo.
echo Leave this window open if you want to see status messages.
pause
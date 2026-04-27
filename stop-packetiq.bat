@echo off
title Stop PacketIQ

echo Stopping PacketIQ...
docker compose down

echo Done.
pause
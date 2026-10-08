@echo off
echo ========================================================
echo Starting GraphCyRAG Interactive Frontend
echo ========================================================
cd /d "%~dp0\..\frontend"
npm run dev
pause

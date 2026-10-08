@echo off
echo ========================================================
echo Starting GraphCyRAG FastAPI Backend Service
echo ========================================================
cd /d "%~dp0\..\backend"
call "..\backend\.venv\Scripts\activate.bat"
python -m uvicorn app.main:app --host 0.0.0.0 --port 8000 --reload
pause

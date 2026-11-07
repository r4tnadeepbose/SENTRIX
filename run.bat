@echo off
rem KeySentry one-click launcher for Windows.
cd /d "%~dp0"
where python >nul 2>nul
if errorlevel 1 (
  echo Python was not found on PATH. Install Python 3.11+ and retry.
  pause
  exit /b 1
)
python run.py %*
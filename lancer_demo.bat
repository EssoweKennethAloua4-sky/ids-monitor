@echo off
cd /d "%~dp0"
python main.py --demo
if errorlevel 1 pause

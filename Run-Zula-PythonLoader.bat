@echo off
setlocal
python "%~dp0Zula-PythonLoader.py"
if errorlevel 1 pause
endlocal

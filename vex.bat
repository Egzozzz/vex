@echo off
REM Try python first, then py
python "%~dp0vex.py" %*
if errorlevel 1 (
    py "%~dp0vex.py" %*
)

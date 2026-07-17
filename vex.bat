@echo off
REM ============================================
REM VEX - Vulnerability Explorer for Windows CMD
REM ============================================
setlocal enabledelayedexpansion

REM Check Python
python --version >nul 2>&1
if %errorlevel% neq 0 (
    py --version >nul 2>&1
    if %errorlevel% neq 0 (
        echo [ERROR] Python bulunamadi! Python'u https://python.org adresinden indirin.
        pause
        exit /b 1
    )
    set PYTHON=py
) else (
    set PYTHON=python
)

REM Find VEX installation directory
set "VEX_DIR=%~dp0"

REM Check/install VEX package
%PYTHON% -c "import vex" >nul 2>&1
if %errorlevel% neq 0 (
    echo [*] VEX ilk kullanim icin kuruluyor...
    cd /d "%VEX_DIR%"
    %PYTHON% -m pip install --upgrade pip setuptools wheel -q
    %PYTHON% -m pip install -e . >nul 2>&1
    if %errorlevel% neq 0 (
        %PYTHON% -m pip install -r requirements.txt >nul 2>&1
    )
    echo [+] VEX hazir!
)

REM Run VEX with all arguments
%PYTHON% -m vex %*

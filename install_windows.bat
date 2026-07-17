@echo off
REM ============================================
REM VEX - Windows Kurulum Scripti
REM ============================================
title VEX Windows Kurulumu
color 0B

echo.
echo ██╗   ██╗███████╗██╗  ██╗
echo ██║   ██║██╔════╝╚██╗██╔╝
echo ██║   ██║█████╗   ╚███╔╝
echo ╚██╗ ██╔╝██╔══╝   ██╔██╗
echo  ╚████╔╝ ███████╗██╔╝ ██╗
echo   ╚═══╝  ╚══════╝╚═╝  ╚═╝
echo VEX - Vulnerability Explorer v0.5.0
echo Windows Kurulum Scripti
echo.

REM Check Python
python --version >nul 2>&1
if %errorlevel% neq 0 (
    py --version >nul 2>&1
    if %errorlevel% neq 0 (
        echo [ERROR] Python bulunamadi!
        echo Lutfen https://www.python.org/downloads/ adresinden Python 3.8+ indirin.
        echo Kurulum sirasinda "Add Python to PATH" secenegini ISARETLEYIN.
        echo.
        pause
        exit /b 1
    )
    set PYTHON=py
) else (
    set PYTHON=python
)

echo [*] Python bulundu: 
%PYTHON% --version

REM Install dependencies
echo.
echo [*] Bagimliliklar yukleniyor...
%PYTHON% -m pip install --upgrade pip -q
%PYTHON% -m pip install -r requirements.txt
if %errorlevel% neq 0 (
    echo [ERROR] Bagimliliklar yuklenemedi!
    pause
    exit /b 1
)
echo [+] Bagimliliklar yuklendi!

REM Install VEX
echo.
echo [*] VEX yukleniyor...
%PYTHON% -m pip install -e .
if %errorlevel% neq 0 (
    echo [WARNING] pip kurulumu basarisiz, dogrudan kullanim icin hazir.
) else (
    echo [+] VEX basariyla yuklendi!
)

REM Test
echo.
echo [*] VEX test ediliyor...
%PYTHON% -m vex --version >nul 2>&1
if %errorlevel% equ 0 (
    echo [+] VEX calisiyor!
) else (
    echo [WARNING] Test basarisiz, vex.bat dosyasini kullanin.
)

echo.
echo ============================================
echo KULLANIM:
echo   vex -u https://site.com
echo   vex.bat -u https://site.com
echo   python -m vex -u https://site.com
echo ============================================
echo.

pause

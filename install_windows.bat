@echo off
REM ============================================
REM VEX - Windows Kurulum Scripti v0.5.0
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
echo Windows Kurulumu
echo.

REM Python kontrol
python --version >nul 2>&1
if %errorlevel% neq 0 (
    py --version >nul 2>&1
    if %errorlevel% neq 0 (
        echo [HATA] Python bulunamadi!
        echo https://python.org adresinden Python 3.8+ indirin.
        echo Kurulumda "Add Python to PATH" secenegini isaretleyin.
        pause
        exit /b 1
    )
    set PYTHON=py
) else (
    set PYTHON=python
)
echo [OK] Python: 
%PYTHON% --version

REM pip'i guncelle
echo.
echo [*] pip guncelleniyor...
%PYTHON% -m pip install --upgrade pip -q

REM Bagimliliklari yukle
echo.
echo [*] Bagimliliklar yukleniyor...
%PYTHON% -m pip install -r requirements.txt
if %errorlevel% neq 0 (
    echo [HATA] Bagimliliklar yuklenemedi!
    pause
    exit /b 1
)
echo [OK] Bagimliliklar yuklendi

REM VEX'i yukle
echo.
echo [*] VEX yukleniyor...
%PYTHON% -m pip install -e .
if %errorlevel% neq 0 (
    echo [UYARI] pip kurulumu basarisiz, dogrudan kullanim hazir.
) else (
    echo [OK] VEX basariyla yuklendi
)

REM AI opsiyonu
echo.
set /p AI_ANSWER=AI motoru (OpenAI) kurulsun mu? [e/H]

if /i "%AI_ANSWER%"=="e" (
    echo [*] AI motoru yukleniyor...
    %PYTHON% -m pip install openai
    echo [OK] AI motoru kuruldu
)

REM Test
echo.
echo [*] VEX test ediliyor...
%PYTHON% -m vex --version >nul 2>&1
if %errorlevel% equ 0 (
    echo [OK] VEX calisiyor!
) else (
    echo [UYARI] Test basarisiz. vex.bat ile deneyin.
)

echo.
echo ============================================
echo KULLANIM:
echo   vex -u https://site.com
echo   vex.bat -u https://site.com
echo   vex.ps1 -u https://site.com
echo   python -m vex -u https://site.com
echo ============================================
echo.
pause

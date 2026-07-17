#!/usr/bin/env pwsh
<#
.SYNOPSIS
    VEX - Vulnerability Explorer for Windows PowerShell
.DESCRIPTION
    Advanced web vulnerability scanner with WAF bypass and stealth mode
#>

param(
    [Parameter(Position=0, ValueFromRemainingArguments=$true)]
    [string[]]$arguments
)

$VexDir = Split-Path -Parent $MyInvocation.MyCommand.Path

# Check Python
$python = $null
try {
    $python = (Get-Command python -ErrorAction Stop).Source
} catch {
    try {
        $python = (Get-Command py -ErrorAction Stop).Source
    } catch {
        Write-Host "[ERROR] Python bulunamadi! https://python.org adresinden indirin." -ForegroundColor Red
        Read-Host "Devam etmek icin bir tusa basin..."
        exit 1
    }
}

# Check/install VEX package
try {
    & $python -c "import vex" -ErrorAction Stop
} catch {
    Write-Host "[*] VEX ilk kullanim icin kuruluyor..." -ForegroundColor Cyan
    Push-Location $VexDir
    & $python -m pip install -e . 2>$null
    if ($LASTEXITCODE -ne 0) {
        & $python -m pip install -r requirements.txt 2>$null
    }
    Pop-Location
    Write-Host "[+] VEX kuruldu!" -ForegroundColor Green
}

# Run VEX
& $python -m vex @arguments

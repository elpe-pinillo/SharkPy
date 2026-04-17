# SharkPy — Windows install
# Usage: Run as Administrator in PowerShell

#Requires -RunAsAdministrator
$ErrorActionPreference = "Stop"

# Check Python
try {
    $v = python --version 2>&1
    Write-Host "[+] Found: $v" -ForegroundColor Green
} catch {
    Write-Host "[-] Python not found. Install Python 3.8+ from https://www.python.org/downloads/" -ForegroundColor Red
    exit 1
}

# Check Npcap
$npcapDll = "$env:SystemRoot\System32\Npcap\wpcap.dll"
if (-not (Test-Path $npcapDll)) {
    Write-Host ""
    Write-Host "[!] Npcap not found — required for packet capture." -ForegroundColor Yellow
    Write-Host "    Download from: https://npcap.com/#download"
    Write-Host "    Check 'Install Npcap in WinPcap API-compatible mode' during install."
    Write-Host ""
    Read-Host "Press Enter once Npcap is installed"
}

Write-Host "[*] Installing Python packages..." -ForegroundColor Green
$reqs = Join-Path $PSScriptRoot "requirements-windows.txt"
python -m pip install --upgrade pip
python -m pip install -r $reqs

Write-Host ""
Write-Host "[+] Done. Run as Administrator:" -ForegroundColor Green
Write-Host "    python Sharkpy\main.py"
Write-Host ""

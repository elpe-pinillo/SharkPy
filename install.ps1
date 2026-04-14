# SharkPy installer for Windows
# Usage: Right-click -> "Run with PowerShell" (as Administrator)
#        or from an admin PowerShell prompt: .\install.ps1

#Requires -RunAsAdministrator
Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

function ok   { param($m) Write-Host "[+] $m" -ForegroundColor Green  }
function warn { param($m) Write-Host "[!] $m" -ForegroundColor Yellow }
function err  { param($m) Write-Host "[-] $m" -ForegroundColor Red; exit 1 }

# --- Check Python ------------------------------------------------------------
ok "Checking Python..."
try {
    $pyver = python --version 2>&1
    ok "Found: $pyver"
} catch {
    err "Python not found. Install Python 3.8+ from https://www.python.org/downloads/ and re-run."
}

# --- Check Npcap -------------------------------------------------------------
ok "Checking Npcap..."
$npcapDll = "$env:SystemRoot\System32\Npcap\wpcap.dll"
if (Test-Path $npcapDll) {
    ok "Npcap already installed."
} else {
    warn "Npcap not found."
    Write-Host ""
    Write-Host "Npcap is required for packet capture (passive sniff mode)."
    Write-Host ""
    Write-Host "  1. Download from:  https://npcap.com/#download"
    Write-Host "  2. Run the installer and check:"
    Write-Host "       [x] Install Npcap in WinPcap API-compatible mode"
    Write-Host "  3. Come back here and press Enter."
    Write-Host ""
    Read-Host "Press Enter to continue"

    if (Test-Path $npcapDll) {
        ok "Npcap detected."
    } else {
        warn "Npcap still not detected -- continuing anyway. Sniff mode may not work."
    }
}

# --- WinDivert via pydivert --------------------------------------------------
ok "WinDivert driver is bundled with pydivert (installed via pip below)."

# --- Install Python packages -------------------------------------------------
ok "Installing Python packages..."
python -m pip install --upgrade pip

# netifaces has no pre-built Windows wheel and requires C++ Build Tools.
# netifaces2 is a drop-in replacement with pre-built wheels -- install it first.
python -m pip install netifaces2

python -m pip install .

ok "SharkPy installed successfully."
Write-Host ""
Write-Host "  Run with:  python Sharkpy\main.py"
Write-Host "  (Administrator required for intercept mode)"
Write-Host ""

# --- Optional: prepare PyInstaller for building SharkPy.exe -----------------
$buildExe = Read-Host "Prepare PyInstaller for building SharkPy.exe? [y/N]"
if ($buildExe -match '^[Yy]') {

    ok "Installing PyInstaller..."
    # Force-reinstall packaging first -- a common pip conflict corrupts it with null bytes
    # which causes PyInstaller to crash with "SyntaxError: source code string cannot contain null bytes"
    python -m pip install --force-reinstall packaging
    python -m pip install pyinstaller

    ok "PyInstaller ready."
    Write-Host ""
    Write-Host "  IMPORTANT: PyInstaller must run as a normal (non-Administrator) user."
    Write-Host "  Close this window, then open a regular Command Prompt or PowerShell and run:"
    Write-Host ""
    Write-Host "    cd $PWD"
    Write-Host "    build.bat"
    Write-Host ""
    Write-Host "  build.bat has been created in this folder for convenience."
}

Write-Host ""
Read-Host "Press Enter to exit"

#!/usr/bin/env bash
# SharkPy — Linux install
# Usage: sudo bash install.sh

set -e

[[ $EUID -ne 0 ]] && { echo "Run as root: sudo bash install.sh"; exit 1; }

echo "[*] Installing system dependencies..."
if command -v apt-get &>/dev/null; then
    apt-get update -qq
    apt-get install -y python3 python3-pip libnetfilter-queue-dev iptables
elif command -v dnf &>/dev/null; then
    dnf install -y python3 python3-pip libnetfilter_queue-devel iptables
elif command -v pacman &>/dev/null; then
    pacman -Sy --noconfirm python python-pip libnetfilter_queue iptables
else
    echo "[-] Unsupported package manager. Install manually: python3, pip, libnetfilter-queue, iptables"
    exit 1
fi

echo "[*] Installing Python packages..."
pip3 install -r "$(dirname "$0")/requirements.txt"

echo ""
echo "[+] Done. Run with:"
echo "    sudo python3 Sharkpy/main.py"
echo ""

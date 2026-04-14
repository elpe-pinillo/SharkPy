#!/usr/bin/env bash
# SharkPy installer — Linux
# Usage: sudo bash install.sh

set -e

# ── Colour helpers ────────────────────────────────────────────────────────────
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; NC='\033[0m'
ok()   { echo -e "${GREEN}[+]${NC} $*"; }
warn() { echo -e "${YELLOW}[!]${NC} $*"; }
err()  { echo -e "${RED}[-]${NC} $*"; exit 1; }

# ── Privilege check ───────────────────────────────────────────────────────────
[[ $EUID -ne 0 ]] && err "Run as root:  sudo bash install.sh"

# ── Detect package manager ────────────────────────────────────────────────────
if command -v apt-get &>/dev/null; then
    PKG="apt-get"
elif command -v dnf &>/dev/null; then
    PKG="dnf"
elif command -v pacman &>/dev/null; then
    PKG="pacman"
else
    err "No supported package manager found (apt / dnf / pacman)."
fi

ok "Package manager: $PKG"

# ── System dependencies ───────────────────────────────────────────────────────
ok "Installing system dependencies..."
case $PKG in
    apt-get)
        apt-get update -qq
        apt-get install -y \
            python3 python3-pip python3-dev \
            build-essential \
            libnetfilter-queue-dev \
            libffi-dev libssl-dev \
            iptables
        ;;
    dnf)
        dnf install -y \
            python3 python3-pip python3-devel \
            gcc \
            libnetfilter_queue-devel \
            iptables
        ;;
    pacman)
        pacman -Sy --noconfirm \
            python python-pip \
            base-devel \
            libnetfilter_queue \
            iptables
        ;;
esac

# ── Python dependencies ───────────────────────────────────────────────────────
ok "Installing Python packages..."
pip3 install --upgrade pip
pip3 install .

ok "SharkPy installed successfully."
echo ""
echo "  Run with:  sudo python3 Sharkpy/main.py"
echo "  (root required for packet interception)"

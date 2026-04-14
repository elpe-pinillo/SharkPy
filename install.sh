#!/usr/bin/env bash
# SharkPy installer — Linux
# Usage: sudo bash install.sh

set -e

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; NC='\033[0m'
ok()   { echo -e "${GREEN}[+]${NC} $*"; }
warn() { echo -e "${YELLOW}[!]${NC} $*"; }
err()  { echo -e "${RED}[-]${NC} $*"; exit 1; }

INSTALL_DIR="/opt/sharkpy"
VENV_DIR="$INSTALL_DIR/venv"
LAUNCHER="/usr/local/bin/sharkpy"

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
            python3 python3-pip python3-dev python3-venv \
            python3-pyqt5 \
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

# ── Copy project files ────────────────────────────────────────────────────────
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

ok "Installing SharkPy to $INSTALL_DIR..."
mkdir -p "$INSTALL_DIR"
cp -r "$SCRIPT_DIR"/. "$INSTALL_DIR/"

# ── Create virtual environment ────────────────────────────────────────────────
ok "Creating Python virtual environment..."
python3 -m venv --system-site-packages "$VENV_DIR"

ok "Installing Python packages into venv..."
"$VENV_DIR/bin/pip" install --upgrade pip setuptools wheel
"$VENV_DIR/bin/pip" install scapy qtmodern cryptography netfilterqueue netifaces

# ── Launcher script ───────────────────────────────────────────────────────────
ok "Creating launcher at $LAUNCHER..."
cat > "$LAUNCHER" <<EOF
#!/usr/bin/env bash
# SharkPy launcher — requires root for packet interception
if [[ \$EUID -ne 0 ]]; then
    exec sudo "\$0" "\$@"
fi
cd "$INSTALL_DIR/Sharkpy"
exec "$VENV_DIR/bin/python" main.py "\$@"
EOF
chmod +x "$LAUNCHER"

ok "SharkPy installed successfully."
echo ""
echo "  Run with:  sharkpy"
echo "  Or:        sudo $VENV_DIR/bin/python $INSTALL_DIR/Sharkpy/main.py"
echo ""

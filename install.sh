#!/bin/bash
set -e

TARGET_DIR="/opt/hulk-server"
VENV_DIR="$TARGET_DIR/venv"

echo "╔══════════════════════════════════════╗"
echo "║     HULK v4 Server — Installer       ║"
echo "╚══════════════════════════════════════╝"
echo ""

if [ "$EUID" -ne 0 ]; then
    echo "[!] Run as root: sudo bash install.sh"
    exit 1
fi

echo "[*] Installing system dependencies..."
apt-get update -qq
apt-get install -y -qq python3 python3-venv python3-pip > /dev/null

echo "[*] Creating $TARGET_DIR..."
mkdir -p "$TARGET_DIR"
cp -r ./*.py "$TARGET_DIR/"
cp requirements.txt "$TARGET_DIR/"

echo "[*] Setting up Python venv..."
python3 -m venv "$VENV_DIR"
"$VENV_DIR/bin/pip" install --upgrade pip -q
"$VENV_DIR/bin/pip" install -r "$TARGET_DIR/requirements.txt" -q

echo "[*] Installing systemd service..."
cp hulk.service /etc/systemd/system/hulk.service
systemctl daemon-reload

echo ""
echo "╔══════════════════════════════════════╗"
echo "║          Installation done!          ║"
echo "╠══════════════════════════════════════╣"
echo "║                                      ║"
echo "║  Run interactively:                  ║"
echo "║    cd $TARGET_DIR              ║"
echo "║    ./venv/bin/python tui.py          ║"
echo "║                                      ║"
echo "║  Or as a service (API-only):         ║"
echo "║    systemctl start hulk              ║"
echo "║    systemctl enable hulk             ║"
echo "║                                      ║"
echo "║  API endpoint:                       ║"
echo "║    http://your-ip:7777               ║"
echo "║                                      ║"
echo "╚══════════════════════════════════════╝"

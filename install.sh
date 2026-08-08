#!/bin/bash
set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
VENV_DIR="$SCRIPT_DIR/venv"

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

echo "[*] Setting up Python venv in $VENV_DIR..."
python3 -m venv "$VENV_DIR"
"$VENV_DIR/bin/pip" install --upgrade pip -q
"$VENV_DIR/bin/pip" install -r "$SCRIPT_DIR/requirements.txt" -q

echo "[*] Installing systemd service..."
cp "$SCRIPT_DIR/hulk.service" /etc/systemd/system/hulk.service
sed -i "s|WorkingDirectory=.*|WorkingDirectory=$SCRIPT_DIR|" /etc/systemd/system/hulk.service
sed -i "s|ExecStart=.*|ExecStart=$VENV_DIR/bin/python $SCRIPT_DIR/tui.py|" /etc/systemd/system/hulk.service
systemctl daemon-reload

echo ""
echo "╔══════════════════════════════════════╗"
echo "║          Installation done!          ║"
echo "╠══════════════════════════════════════╣"
echo "║                                      ║"
echo "║  Run:                                ║"
echo "║    cd $SCRIPT_DIR"
echo "║    ./venv/bin/python tui.py          ║"
echo "║                                      ║"
echo "╚══════════════════════════════════════╝"

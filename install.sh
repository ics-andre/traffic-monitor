#!/usr/bin/env bash
set -euo pipefail

# Ensure script is run as root
if [ "$(id -u)" -ne 0 ]; then
    echo "[!] Error: This installer must be run as root or with sudo." >&2
    exit 1
fi

echo "=========================================================="
echo "      Installing Traffic Monitor Systemd Service          "
echo "=========================================================="

# 1. Check prerequisites
MISSING_PKGS=()
command -v python3 >/dev/null 2>&1 || MISSING_PKGS+=("python3")
command -v tcpdump >/dev/null 2>&1 || MISSING_PKGS+=("tcpdump")

if [ ${#MISSING_PKGS[@]} -gt 0 ]; then
    echo "[*] Missing dependencies: ${MISSING_PKGS[*]}"
    echo "[*] Attempting to install missing dependencies..."
    if command -v apt-get >/dev/null 2>&1; then
        apt-get update -y
        apt-get install -y "${MISSING_PKGS[@]}"
    elif command -v dnf >/dev/null 2>&1; then
        dnf install -y "${MISSING_PKGS[@]}"
    elif command -v yum >/dev/null 2>&1; then
        yum install -y "${MISSING_PKGS[@]}"
    else
        echo "[!] Unsupported package manager. Please manually install: ${MISSING_PKGS[*]}" >&2
        exit 1
    fi
fi

# 2. Setup script location
SCRIPT_SRC="$(dirname "$0")/traffic-monitor.py"
SERVICE_SRC="$(dirname "$0")/traffic-monitor.service"
CONFIG_SRC="$(dirname "$0")/traffic-monitor.default"
BIN_DEST="/usr/local/bin/traffic-monitor.py"
SERVICE_DEST="/etc/systemd/system/traffic-monitor.service"
CONFIG_DEST="/etc/default/traffic-monitor"
LOG_DIR="/var/log/traffic-monitor"

echo "[*] Installing monitor script to ${BIN_DEST}..."
cp "${SCRIPT_SRC}" "${BIN_DEST}"
chmod +x "${BIN_DEST}"

echo "[*] Creating log directory at ${LOG_DIR}..."
mkdir -p "${LOG_DIR}"

if [ -f "${CONFIG_SRC}" ] && [ ! -f "${CONFIG_DEST}" ]; then
    echo "[*] Installing default configuration to ${CONFIG_DEST}..."
    cp "${CONFIG_SRC}" "${CONFIG_DEST}"
else
    echo "[*] Existing configuration preserved at ${CONFIG_DEST}."
fi

echo "[*] Installing systemd service unit to ${SERVICE_DEST}..."
cp "${SERVICE_SRC}" "${SERVICE_DEST}"

# 3. Reload and start systemd service
echo "[*] Reloading systemd daemon..."
systemctl daemon-reload

echo "[*] Enabling and starting traffic-monitor.service..."
systemctl enable --now traffic-monitor.service

# 4. Status check
echo "=========================================================="
if systemctl is-active --quiet traffic-monitor.service; then
    echo "[✓] Traffic Monitor successfully installed and running!"
else
    echo "[!] Warning: Service installed but not active. Check: journalctl -u traffic-monitor"
fi
echo "=========================================================="
echo ""
echo "Useful Commands:"
echo "  - Check status:      sudo systemctl status traffic-monitor"
echo "  - View live traffic: sudo cat ${LOG_DIR}/outbound_traffic_current.txt"
echo "  - Live watch:        watch -n 2 'sudo cat ${LOG_DIR}/outbound_traffic_current.txt'"
echo "  - Daily archives:    ls -lh ${LOG_DIR}/outbound_traffic_*.txt"
echo "  - Stop service:      sudo systemctl stop traffic-monitor"
echo ""

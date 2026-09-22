#!/usr/bin/env bash
set -euo pipefail

if [ "$(id -u)" -ne 0 ]; then
    echo "[!] Error: This script must be run as root or with sudo." >&2
    exit 1
fi

echo "=========================================================="
echo "          Uninstalling Traffic Monitor                    "
echo "=========================================================="

SERVICE_NAME="traffic-monitor.service"
BIN_FILE="/usr/local/bin/traffic-monitor.py"
SERVICE_FILE="/etc/systemd/system/${SERVICE_NAME}"
LOG_DIR="/var/log/traffic-monitor"

# 1. Stop and disable systemd service
if systemctl list-unit-files | grep -q "${SERVICE_NAME}"; then
    echo "[*] Stopping and disabling ${SERVICE_NAME}..."
    systemctl stop "${SERVICE_NAME}" 2>/dev/null || true
    systemctl disable "${SERVICE_NAME}" 2>/dev/null || true
fi

# 2. Remove files
if [ -f "${SERVICE_FILE}" ]; then
    echo "[*] Removing ${SERVICE_FILE}..."
    rm -f "${SERVICE_FILE}"
fi

if [ -f "${BIN_FILE}" ]; then
    echo "[*] Removing ${BIN_FILE}..."
    rm -f "${BIN_FILE}"
fi

echo "[*] Reloading systemd daemon..."
systemctl daemon-reload
systemctl reset-failed 2>/dev/null || true

# 3. Optional log removal
echo "[?] Log directory remains preserved at: ${LOG_DIR}"
echo "    If you wish to delete existing logs, run: sudo rm -rf ${LOG_DIR}"

echo "=========================================================="
echo "[✓] Traffic Monitor uninstallation complete."
echo "=========================================================="

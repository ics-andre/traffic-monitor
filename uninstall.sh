#!/usr/bin/env bash
# ==============================================================================
# Traffic Monitor - Standalone Uninstaller
# Supports direct pipe: curl -sSL <URL>/uninstall.sh | sudo bash
# Or local execution:   sudo ./uninstall.sh [--purge]
# ==============================================================================
set -euo pipefail

if [ "$(id -u)" -ne 0 ]; then
    echo "[!] Error: This script must be run as root or with sudo." >&2
    exit 1
fi

PURGE_LOGS=false
for arg in "$@"; do
    if [ "$arg" == "--purge" ] || [ "$arg" == "-p" ]; then
        PURGE_LOGS=true
    fi
done

echo "=========================================================="
echo "          Uninstalling Traffic Monitor                    "
echo "=========================================================="

SERVICE_NAME="traffic-monitor.service"
BIN_FILE="/usr/local/bin/traffic-monitor.sh"
LEGACY_PY="/usr/local/bin/traffic-monitor.py"
SERVICE_FILE="/etc/systemd/system/${SERVICE_NAME}"
CONFIG_FILE="/etc/default/traffic-monitor"
LOG_DIR="/var/log/traffic-monitor"

# 1. Stop and disable systemd service
if systemctl is-active --quiet "${SERVICE_NAME}" 2>/dev/null || systemctl list-unit-files | grep -q "${SERVICE_NAME}"; then
    echo "[*] Stopping and disabling ${SERVICE_NAME}..."
    systemctl stop "${SERVICE_NAME}" 2>/dev/null || true
    systemctl disable "${SERVICE_NAME}" 2>/dev/null || true
fi

# 2. Remove binary and service unit
if [ -f "${SERVICE_FILE}" ]; then
    echo "[*] Removing service unit ${SERVICE_FILE}..."
    rm -f "${SERVICE_FILE}"
fi

if [ -f "${BIN_FILE}" ]; then
    echo "[*] Removing executable ${BIN_FILE}..."
    rm -f "${BIN_FILE}"
fi

if [ -f "${LEGACY_PY}" ]; then
    echo "[*] Removing legacy executable ${LEGACY_PY}..."
    rm -f "${LEGACY_PY}"
fi

if [ -f "${CONFIG_FILE}" ]; then
    echo "[*] Removing configuration ${CONFIG_FILE}..."
    rm -f "${CONFIG_FILE}"
fi

echo "[*] Reloading systemd daemon..."
systemctl daemon-reload
systemctl reset-failed 2>/dev/null || true

# 3. Handle log directory
if [ "${PURGE_LOGS}" = true ]; then
    echo "[*] Purging log directory at ${LOG_DIR}..."
    rm -rf "${LOG_DIR}"
else
    echo "[?] Log directory preserved at: ${LOG_DIR}"
    echo "    To delete existing log files, run: sudo rm -rf ${LOG_DIR}"
fi

echo "=========================================================="
echo "[✓] Traffic Monitor uninstallation complete."
echo "=========================================================="

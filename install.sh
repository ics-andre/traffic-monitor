#!/usr/bin/env bash
# ==============================================================================
# Traffic Monitor - Standalone One-Click Installer (Pure Bash/Awk - No Python)
# Supports direct pipe: curl -sSL <URL>/install.sh | sudo bash
# Or local execution:   sudo ./install.sh
# ==============================================================================
set -euo pipefail

if [ "$(id -u)" -ne 0 ]; then
    echo "[!] Error: This installer must be run as root or with sudo." >&2
    exit 1
fi

echo "=========================================================="
echo "      Installing Traffic Monitor Systemd Service          "
echo "  (Bidirectional Inbound & Outbound Traffic Monitor)      "
echo "=========================================================="

# 1. Check & install prerequisites (tcpdump and awk)
MISSING_PKGS=()
command -v tcpdump >/dev/null 2>&1 || MISSING_PKGS+=("tcpdump")
command -v awk >/dev/null 2>&1 || MISSING_PKGS+=("gawk")

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

BIN_DEST="/usr/local/bin/traffic-monitor.sh"
LEGACY_PY="/usr/local/bin/traffic-monitor.py"
SERVICE_DEST="/etc/systemd/system/traffic-monitor.service"
CONFIG_DEST="/etc/default/traffic-monitor"
LOG_DIR="/var/log/traffic-monitor"

# Clean legacy python binary if present
rm -f "${LEGACY_PY}"

echo "[*] Creating log directory at ${LOG_DIR}..."
mkdir -p "${LOG_DIR}"

# 2. Deploy Bash Monitor Script (/usr/local/bin/traffic-monitor.sh)
echo "[*] Installing monitor script to ${BIN_DEST}..."
cat << 'EOF' > "${BIN_DEST}"
#!/usr/bin/env bash
# ==============================================================================
# Traffic Monitor - Pure Bash/Awk 24h Bidirectional Network Traffic Aggregator
# Captures both Inbound and Outbound traffic into separate aggregated reports.
# Zero Python dependency. Requires only bash, awk, tcpdump, and coreutils.
# ==============================================================================
set -euo pipefail

CONFIG_FILE="/etc/default/traffic-monitor"
if [ -f "$CONFIG_FILE" ]; then
    # shellcheck disable=SC1090
    source "$CONFIG_FILE"
fi

INTERFACE="${TRAFFIC_MONITOR_INTERFACE:-any}"
FILTER="${TRAFFIC_MONITOR_FILTER:-}"
LOG_DIR="${TRAFFIC_MONITOR_LOG_DIR:-/var/log/traffic-monitor}"
SYNC_INTERVAL="${TRAFFIC_MONITOR_SYNC_INTERVAL:-10}"
RETENTION_DAYS="${TRAFFIC_MONITOR_RETENTION_DAYS:-7}"
EXCLUDE_CONTAINERS="${TRAFFIC_MONITOR_EXCLUDE_CONTAINERS:-true}"
EXCLUDE_NETS="${TRAFFIC_MONITOR_EXCLUDE_NETWORKS:-127.0.0.0/8,169.254.169.254/32}"

mkdir -p "$LOG_DIR"

cleanup_old_logs() {
    local dir="$1"
    local days="$2"
    [ "$days" -le 0 ] && return 0
    local cutoff
    cutoff=$(date -d "${days} days ago" +%Y-%m-%d 2>/dev/null || date -v-${days}d +%Y-%m-%d 2>/dev/null || "")
    if [ -n "$cutoff" ] && [ -d "$dir" ]; then
        for f in "$dir"/{inbound,outbound}_traffic_[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9].txt; do
            [ -e "$f" ] || continue
            local fname
            fname=$(basename "$f")
            local fdate="${fname#*_traffic_}"
            fdate="${fdate%.txt}"
            if [[ "$fdate" < "$cutoff" ]]; then
                rm -f "$f"
            fi
        done
    fi
}

# Initial retention cleanup on startup
cleanup_old_logs "$LOG_DIR" "$RETENTION_DAYS"

# Detect container subnets if enabled
if [ "$EXCLUDE_CONTAINERS" = "true" ] || [ "$EXCLUDE_CONTAINERS" = "1" ] || [ "$EXCLUDE_CONTAINERS" = "yes" ]; then
    CONTAINER_NETS=$(ip -o -4 addr show 2>/dev/null | awk '$2 ~ /^(docker[0-9]+|br-[a-f0-9]+|cni[0-9]+|flannel\.[0-9]+|virbr[0-9]+)/ {print $4}' | tr '\n' ',' | sed 's/,$//' || true)
    if [ -n "$CONTAINER_NETS" ]; then
        if [ -n "$EXCLUDE_NETS" ]; then
            EXCLUDE_NETS="${CONTAINER_NETS},${EXCLUDE_NETS}"
        else
            EXCLUDE_NETS="${CONTAINER_NETS}"
        fi
    fi
fi

# Run tcpdump piped into awk
# shellcheck disable=SC2086
exec tcpdump -i "$INTERFACE" -nn $FILTER -l 2>/dev/null | awk \
    -v log_dir="$LOG_DIR" \
    -v sync_interval="$SYNC_INTERVAL" \
    -v retention="$RETENTION_DAYS" \
    -v exclude_nets="$EXCLUDE_NETS" '
BEGIN {
    current_date = strftime("%Y-%m-%d", systime())
    last_sync = systime()

    # Parse excluded networks into numerical range
    split(exclude_nets, raw_nets, ",")
    net_count = 0
    for (i in raw_nets) {
        gsub(/^[ \t]+|[ \t]+$/, "", raw_nets[i])
        if (raw_nets[i] == "") continue

        n = raw_nets[i]
        if (index(n, "/") == 0) {
            n = n (index(n, ":") > 0 ? "/128" : "/32")
        }

        split(n, parts, "/")
        net_ip = parts[1]
        mask_len = parts[2] + 0

        if (index(net_ip, ".") > 0) {
            split(net_ip, oct, ".")
            net_num = oct[1]*16777216 + oct[2]*65536 + oct[3]*256 + oct[4]
            net_count++
            ex_net_num[net_count] = net_num
            ex_range[net_count] = 2^(32 - mask_len)
            ex_names[net_count] = n
        }
    }
}

function is_excluded(dst,   n_parts, parts, ip_str, oct, ip_num, i) {
    if (index(dst, ".") > 0) {
        n_parts = split(dst, parts, ".")
        if (n_parts >= 5) {
            ip_str = parts[1] "." parts[2] "." parts[3] "." parts[4]
        } else {
            ip_str = dst
        }
    } else {
        ip_str = dst
    }

    if (ip_str in ex_cache) {
        return ex_cache[ip_str]
    }

    if (index(ip_str, ".") > 0) {
        split(ip_str, oct, ".")
        ip_num = oct[1]*16777216 + oct[2]*65536 + oct[3]*256 + oct[4]
        for (i=1; i<=net_count; i++) {
            if (ip_num >= ex_net_num[i] && ip_num < ex_net_num[i] + ex_range[i]) {
                ex_cache[ip_str] = 1
                return 1
            }
        }
    }

    ex_cache[ip_str] = 0
    return 0
}

function save_report(type, date_str, filename,   target, out_file, tmp_file, total_pkts, total_bytes, ex_str, i, ret_str, header_title, col_title) {
    out_file = log_dir "/" filename
    tmp_file = out_file ".tmp"

    if (type == "OUT") {
        header_title = "Outbound Traffic Report"
        col_title = "DESTINATION (IP:PORT)"
    } else {
        header_title = "Inbound Traffic Report"
        col_title = "SOURCE (IP:PORT)"
    }

    print "# " header_title " - Date: " date_str > tmp_file
    print "# Last Updated: " strftime("%Y-%m-%d %H:%M:%S", systime()) >> tmp_file
    ret_str = (retention > 0 ? retention " days" : "unlimited (disabled)")
    print "# Retention Policy: " ret_str >> tmp_file

    ex_str = ""
    for (i=1; i<=net_count; i++) {
        ex_str = (ex_str == "" ? ex_names[i] : ex_str ", " ex_names[i])
    }
    if (ex_str != "") {
        print "# Excluded Networks: " ex_str >> tmp_file
    }
    print "----------------------------------------------------------------------------------" >> tmp_file
    printf "%-42s %-10s %-12s %-15s\n", col_title, "PROTOCOL", "PACKETS", "TOTAL BYTES" >> tmp_file
    print "----------------------------------------------------------------------------------" >> tmp_file

    total_pkts = 0
    total_bytes = 0

    PROCINFO["sorted_in"] = "@val_num_desc"
    if (type == "OUT") {
        for (target in out_bytes) {
            printf "%-42s %-10s %-12d %-15d\n", target, out_proto[target], out_pkts[target], out_bytes[target] >> tmp_file
            total_pkts += out_pkts[target]
            total_bytes += out_bytes[target]
        }
    } else {
        for (target in in_bytes) {
            printf "%-42s %-10s %-12d %-15d\n", target, in_proto[target], in_pkts[target], in_bytes[target] >> tmp_file
            total_pkts += in_pkts[target]
            total_bytes += in_bytes[target]
        }
    }

    print "----------------------------------------------------------------------------------" >> tmp_file
    printf "%-42s %-10s %-12d %-15d\n", "GRAND TOTAL", "-", total_pkts, total_bytes >> tmp_file
    close(tmp_file)

    system("mv -f " tmp_file " " out_file)
}

{
    direction = ""
    src = ""
    dst = ""
    len = 0
    pkt_proto = ""

    # Check direction in Linux cooked SLL/SLL2 header
    for (i = 1; i <= 4 && i <= NF; i++) {
        if ($i == "In") direction = "IN"
        else if ($i == "Out") direction = "OUT"
    }

    for (i = 1; i <= NF; i++) {
        if ($i == ">") {
            src = $(i-1)
            dst = $(i+1)
            sub(/:$/, "", dst)
        }
        if ($i == "length") {
            len = $(i+1) + 0
        }
    }

    # Protocol detection
    if ($0 ~ /: Flags \[/) {
        pkt_proto = "TCP"
    } else if ($0 ~ /: UDP,/) {
        pkt_proto = "UDP"
    } else if ($0 ~ /: ICMP/) {
        pkt_proto = "ICMP"
    } else if ($0 ~ /: GRE/) {
        pkt_proto = "GRE"
    } else if ($0 ~ /: ESP/) {
        pkt_proto = "ESP"
    } else if ($0 ~ /: AH/) {
        pkt_proto = "AH"
    } else {
        match($0, />\s+[^:]+:\s+([A-Za-z0-9_-]+)/, m)
        if (m[1] != "") {
            pkt_proto = toupper(m[1])
            sub(/,$/, "", pkt_proto)
        } else {
            pkt_proto = "OTHER"
        }
    }

    if (len > 0) {
        # Check exclusion for both source and destination
        if (is_excluded(src) || is_excluded(dst)) {
            next
        }

        if (direction == "IN") {
            in_pkts[src]++
            in_bytes[src] += len
            in_proto[src] = pkt_proto
        } else {
            out_pkts[dst]++
            out_bytes[dst] += len
            out_proto[dst] = pkt_proto
        }
    }

    now = systime()
    today = strftime("%Y-%m-%d", now)
    if (today != current_date) {
        save_report("OUT", current_date, "outbound_traffic_" current_date ".txt")
        save_report("IN", current_date, "inbound_traffic_" current_date ".txt")
        delete out_pkts
        delete out_bytes
        delete out_proto
        delete in_pkts
        delete in_bytes
        delete in_proto
        current_date = today
    }

    if (now - last_sync >= sync_interval) {
        save_report("OUT", current_date, "outbound_traffic_current.txt")
        save_report("IN", current_date, "inbound_traffic_current.txt")
        last_sync = now
    }
}
END {
    save_report("OUT", current_date, "outbound_traffic_" current_date ".txt")
    save_report("IN", current_date, "inbound_traffic_" current_date ".txt")
    save_report("OUT", current_date, "outbound_traffic_current.txt")
    save_report("IN", current_date, "inbound_traffic_current.txt")
}
'
EOF
chmod +x "${BIN_DEST}"

# 3. Deploy Default Configuration (/etc/default/traffic-monitor)
if [ ! -f "${CONFIG_DEST}" ]; then
    echo "[*] Installing default configuration to ${CONFIG_DEST}..."
    cat << 'EOF' > "${CONFIG_DEST}"
# Configuration for Traffic Monitor Service (/etc/default/traffic-monitor)

# Network interface to listen on (default: any)
TRAFFIC_MONITOR_INTERFACE=any

# Direction or pcap filter passed to tcpdump
# Leave empty (default) to capture both Inbound and Outbound traffic
# Set to "-Q out" for Outbound-only, or "-Q in" for Inbound-only
TRAFFIC_MONITOR_FILTER=""

# Log storage directory (default: /var/log/traffic-monitor)
TRAFFIC_MONITOR_LOG_DIR=/var/log/traffic-monitor

# Live snapshot disk sync interval in seconds (default: 10)
TRAFFIC_MONITOR_SYNC_INTERVAL=10

# Retention period in days for daily archives (default: 7)
# Archived files older than this count will be automatically purged.
# Set to 0 or negative to keep archives indefinitely.
TRAFFIC_MONITOR_RETENTION_DAYS=7

# Automatically detect and exclude local container bridge networks
# (e.g., Docker docker0, Harbor br-*, Podman, CNI, virbr)
TRAFFIC_MONITOR_EXCLUDE_CONTAINERS=true

# Additional IP addresses or CIDR blocks to exclude (comma-separated)
# Example: "127.0.0.0/8,169.254.169.254/32,10.101.0.12/32"
TRAFFIC_MONITOR_EXCLUDE_NETWORKS="127.0.0.0/8,169.254.169.254/32"
EOF
else
    echo "[*] Existing configuration preserved at ${CONFIG_DEST}."
    # If upgrading from outbound-only to bidirectional, clear legacy -Q out filter
    sed -i 's/^TRAFFIC_MONITOR_FILTER="-Q out"/TRAFFIC_MONITOR_FILTER=""/' "${CONFIG_DEST}" 2>/dev/null || true
fi

# 4. Deploy Systemd Unit (/etc/systemd/system/traffic-monitor.service)
echo "[*] Installing systemd service unit to ${SERVICE_DEST}..."
# Unmask if previously masked (remove symlink to /dev/null if present)
systemctl unmask traffic-monitor.service 2>/dev/null || true
rm -f "${SERVICE_DEST}"

cat << 'EOF' > "${SERVICE_DEST}"
[Unit]
Description=Bidirectional Network Traffic Monitor (24h Auto-Rotate)
After=network.target

[Service]
Type=simple
ExecStart=/usr/local/bin/traffic-monitor.sh
Restart=always
RestartSec=5
KillMode=mixed
TimeoutStopSec=10

# Environment configuration
EnvironmentFile=-/etc/default/traffic-monitor

[Install]
WantedBy=multi-user.target
EOF

# 5. Reload and start/restart systemd service
echo "[*] Reloading systemd daemon..."
systemctl daemon-reload

echo "[*] Enabling and restarting traffic-monitor.service..."
systemctl enable traffic-monitor.service
systemctl restart traffic-monitor.service

# 6. Status check
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
echo "  - View OUTBOUND:     sudo cat ${LOG_DIR}/outbound_traffic_current.txt"
echo "  - View INBOUND:      sudo cat ${LOG_DIR}/inbound_traffic_current.txt"
echo "  - Live watch OUT:    watch -n 2 'sudo cat ${LOG_DIR}/outbound_traffic_current.txt'"
echo "  - Live watch IN:     watch -n 2 'sudo cat ${LOG_DIR}/inbound_traffic_current.txt'"
echo "  - Daily archives:    ls -lh ${LOG_DIR}/*_traffic_*.txt"
echo "  - Stop service:      sudo systemctl stop traffic-monitor"
echo "  - Edit config:       sudo nano ${CONFIG_DEST}"
echo ""

#!/usr/bin/env bash
# ==============================================================================
# Traffic Monitor - Pure Bash/Awk 24h Outbound Network Traffic Aggregator
# Zero Python dependency. Requires only bash, awk, tcpdump, and coreutils.
# ==============================================================================
set -euo pipefail

CONFIG_FILE="/etc/default/traffic-monitor"
if [ -f "$CONFIG_FILE" ]; then
    # shellcheck disable=SC1090
    source "$CONFIG_FILE"
fi

INTERFACE="${TRAFFIC_MONITOR_INTERFACE:-any}"
FILTER="${TRAFFIC_MONITOR_FILTER:--Q out}"
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
        for f in "$dir"/outbound_traffic_[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9].txt; do
            [ -e "$f" ] || continue
            local fname
            fname=$(basename "$f")
            local fdate="${fname#outbound_traffic_}"
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

function save_report(date_str, filename,   target, out_file, tmp_file, total_pkts, total_bytes, ex_str, i, ret_str) {
    out_file = log_dir "/" filename
    tmp_file = out_file ".tmp"

    print "# Outbound Traffic Report - Date: " date_str > tmp_file
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
    print "------------------------------------------------------------------------" >> tmp_file
    printf "%-42s %-12s %-15s\n", "DESTINATION (IP:PORT)", "PACKETS", "TOTAL BYTES" >> tmp_file
    print "------------------------------------------------------------------------" >> tmp_file

    total_pkts = 0
    total_bytes = 0

    PROCINFO["sorted_in"] = "@val_num_desc"
    for (target in bytes) {
        printf "%-42s %-12d %-15d\n", target, pkts[target], bytes[target] >> tmp_file
        total_pkts += pkts[target]
        total_bytes += bytes[target]
    }

    print "------------------------------------------------------------------------" >> tmp_file
    printf "%-42s %-12d %-15d\n", "GRAND TOTAL", total_pkts, total_bytes >> tmp_file
    close(tmp_file)

    system("mv -f " tmp_file " " out_file)
}

{
    dst = ""
    len = 0
    for (i=1; i<=NF; i++) {
        if ($i == ">") {
            dst = $(i+1)
            sub(/:$/, "", dst)
        }
        if ($i == "length") {
            len = $(i+1) + 0
        }
    }

    if (dst != "" && len > 0) {
        if (is_excluded(dst)) {
            next
        }

        pkts[dst]++
        bytes[dst] += len
    }

    now = systime()
    today = strftime("%Y-%m-%d", now)
    if (today != current_date) {
        save_report(current_date, "outbound_traffic_" current_date ".txt")
        delete pkts
        delete bytes
        current_date = today
    }

    if (now - last_sync >= sync_interval) {
        save_report(current_date, "outbound_traffic_current.txt")
        last_sync = now
    }
}
END {
    save_report(current_date, "outbound_traffic_" current_date ".txt")
    save_report(current_date, "outbound_traffic_current.txt")
}
'

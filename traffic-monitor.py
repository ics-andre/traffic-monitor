#!/usr/bin/env python3
"""
Traffic Monitor - 24-Hour Aggregated Outbound Network Traffic Monitor
Monitors network traffic using tcpdump, aggregates bytes and packets per destination IP:port,
and automatically rotates logs every 24 hours (midnight).
"""

import subprocess
import re
import sys
import signal
import os
import time
from datetime import datetime

# Configuration defaults (can be overridden via environment variables)
LOG_DIR = os.environ.get("TRAFFIC_MONITOR_LOG_DIR", "/var/log/traffic-monitor")
INTERFACE = os.environ.get("TRAFFIC_MONITOR_INTERFACE", "any")
DIRECTION_FILTER = os.environ.get("TRAFFIC_MONITOR_FILTER", "-Q out")  # Outbound only
SYNC_INTERVAL = int(os.environ.get("TRAFFIC_MONITOR_SYNC_INTERVAL", "10"))

stats = {}
current_date = datetime.now().strftime("%Y-%m-%d")
last_disk_sync = time.time()
proc = None


def generate_report(target_date):
    lines = []
    lines.append(f"# Outbound Traffic Report - Date: {target_date}")
    lines.append(f"# Last Updated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    lines.append("-" * 72)
    header = f"{'DESTINATION (IP:PORT)':<42} {'PACKETS':<12} {'TOTAL BYTES':<15}"
    lines.append(header)
    lines.append("-" * 72)

    # Sort descending by total bytes
    sorted_targets = sorted(stats.items(), key=lambda x: x[1]["bytes"], reverse=True)
    total_bytes_all = sum(x["bytes"] for x in stats.values())
    total_pkts_all = sum(x["packets"] for x in stats.values())

    for dst, data in sorted_targets:
        lines.append(f"{dst:<42} {data['packets']:<12} {data['bytes']:<15}")

    lines.append("-" * 72)
    lines.append(f"{'GRAND TOTAL':<42} {total_pkts_all:<12} {total_bytes_all:<15}")
    return "\n".join(lines) + "\n"


def save_to_file(filename, content):
    os.makedirs(LOG_DIR, exist_ok=True)
    filepath = os.path.join(LOG_DIR, filename)
    temp_filepath = filepath + ".tmp"
    with open(temp_filepath, "w") as f:
        f.write(content)
    os.replace(temp_filepath, filepath)


def on_shutdown(sig, frame):
    global proc
    report = generate_report(current_date)
    save_to_file(f"outbound_traffic_{current_date}.txt", report)
    save_to_file("outbound_traffic_current.txt", report)
    if proc and proc.poll() is None:
        proc.terminate()
        try:
            proc.wait(timeout=2)
        except subprocess.TimeoutExpired:
            proc.kill()
    sys.exit(0)


def main():
    global current_date, last_disk_sync, proc

    signal.signal(signal.SIGTERM, on_shutdown)
    signal.signal(signal.SIGINT, on_shutdown)

    # Build tcpdump command arguments
    cmd = ["tcpdump", "-i", INTERFACE, "-nn"]
    if DIRECTION_FILTER:
        cmd.extend(DIRECTION_FILTER.split())
    cmd.append("-l")

    try:
        proc = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            text=True,
            bufsize=1
        )
    except FileNotFoundError:
        sys.stderr.write("Error: tcpdump command not found. Please install tcpdump.\n")
        sys.exit(1)

    for line in proc.stdout:
        # Check for 24-hour day rollover (midnight)
        today = datetime.now().strftime("%Y-%m-%d")
        if today != current_date:
            # 1. Save final report for the elapsed day
            final_report = generate_report(current_date)
            save_to_file(f"outbound_traffic_{current_date}.txt", final_report)

            # 2. Reset counter for the new day
            stats.clear()
            current_date = today

        # Parse tcpdump format: IP src > dst: protocol, length X
        match = re.search(r">\s+([^\s]+?):\s+.*?length\s+(\d+)", line)
        if match:
            dst, length = match.group(1), int(match.group(2))
            if dst not in stats:
                stats[dst] = {"packets": 0, "bytes": 0}
            stats[dst]["packets"] += 1
            stats[dst]["bytes"] += length

        # Periodic sync to current snapshot file
        now = time.time()
        if now - last_disk_sync >= SYNC_INTERVAL:
            current_report = generate_report(current_date)
            save_to_file("outbound_traffic_current.txt", current_report)
            last_disk_sync = now


if __name__ == "__main__":
    main()

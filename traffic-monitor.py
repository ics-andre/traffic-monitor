#!/usr/bin/env python3
"""
Traffic Monitor - 24-Hour Aggregated Outbound Network Traffic Monitor
Monitors network traffic using tcpdump, aggregates bytes and packets per destination IP:port,
and automatically rotates logs every 24 hours (midnight).

Supports excluding specific destination IPs or subnets (e.g. local Docker/container bridge networks,
loopback, or cloud link-local addresses).
"""

import subprocess
import re
import sys
import signal
import os
import time
import ipaddress
import argparse
from datetime import datetime

# Default Configuration
DEFAULT_LOG_DIR = "/var/log/traffic-monitor"
DEFAULT_INTERFACE = "any"
DEFAULT_FILTER = "-Q out"
DEFAULT_SYNC_INTERVAL = 10


def detect_container_subnets():
    """Detect local container bridge subnets (Docker, Podman, CNI, bridge interfaces)."""
    detected = []
    try:
        out = subprocess.check_output(["ip", "-o", "-4", "addr", "show"], text=True)
        for line in out.splitlines():
            parts = line.split()
            if len(parts) >= 4:
                iface = parts[1]
                cidr = parts[3]
                if re.match(r"^(docker\d+|br-[a-f0-9]+|cni\d+|flannel\.\d+|virbr\d+)", iface):
                    try:
                        net = ipaddress.ip_network(cidr, strict=False)
                        if net not in detected:
                            detected.append(net)
                    except ValueError:
                        pass
    except Exception:
        pass
    return detected


def parse_excluded_networks(raw_str, include_containers=True):
    """Parse comma/space separated list of IPs and CIDRs into ip_network objects."""
    networks = []
    if include_containers:
        networks.extend(detect_container_subnets())

    if raw_str:
        # Split by comma or whitespace
        items = re.split(r"[,\s]+", raw_str.strip())
        for item in items:
            item = item.strip()
            if not item:
                continue
            try:
                if "/" not in item:
                    # Single IP address -> /32 or /128
                    item = item + ("/128" if ":" in item else "/32")
                net = ipaddress.ip_network(item, strict=False)
                if net not in networks:
                    networks.append(net)
            except ValueError:
                sys.stderr.write(f"Warning: Invalid IP/CIDR in exclusion list ignored: {item}\n")

    return networks


class TrafficMonitor:
    def __init__(self, log_dir, interface, direction_filter, sync_interval, excluded_networks):
        self.log_dir = log_dir
        self.interface = interface
        self.direction_filter = direction_filter
        self.sync_interval = sync_interval
        self.excluded_networks = excluded_networks
        self.exclusion_cache = {}

        self.stats = {}
        self.current_date = datetime.now().strftime("%Y-%m-%d")
        self.last_disk_sync = time.time()
        self.proc = None

    def is_excluded(self, dst_endpoint):
        """Check if destination IP belongs to excluded networks/IPs."""
        # Extract IP string from 'IP.PORT' or 'IPv6.PORT'
        if "." in dst_endpoint:
            ip_str = dst_endpoint.rsplit(".", 1)[0]
        else:
            ip_str = dst_endpoint

        if ip_str in self.exclusion_cache:
            return self.exclusion_cache[ip_str]

        try:
            ip_obj = ipaddress.ip_address(ip_str)
            for net in self.excluded_networks:
                if ip_obj in net:
                    self.exclusion_cache[ip_str] = True
                    return True
            self.exclusion_cache[ip_str] = False
            return False
        except ValueError:
            self.exclusion_cache[ip_str] = False
            return False

    def generate_report(self, target_date):
        lines = []
        lines.append(f"# Outbound Traffic Report - Date: {target_date}")
        lines.append(f"# Last Updated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        if self.excluded_networks:
            ex_str = ", ".join(str(n) for n in self.excluded_networks)
            lines.append(f"# Excluded Networks: {ex_str}")
        lines.append("-" * 72)
        header = f"{'DESTINATION (IP:PORT)':<42} {'PACKETS':<12} {'TOTAL BYTES':<15}"
        lines.append(header)
        lines.append("-" * 72)

        # Sort descending by total bytes
        sorted_targets = sorted(self.stats.items(), key=lambda x: x[1]["bytes"], reverse=True)
        total_bytes_all = sum(x["bytes"] for x in self.stats.values())
        total_pkts_all = sum(x["packets"] for x in self.stats.values())

        for dst, data in sorted_targets:
            lines.append(f"{dst:<42} {data['packets']:<12} {data['bytes']:<15}")

        lines.append("-" * 72)
        lines.append(f"{'GRAND TOTAL':<42} {total_pkts_all:<12} {total_bytes_all:<15}")
        return "\n".join(lines) + "\n"

    def save_to_file(self, filename, content):
        os.makedirs(self.log_dir, exist_ok=True)
        filepath = os.path.join(self.log_dir, filename)
        temp_filepath = filepath + ".tmp"
        with open(temp_filepath, "w") as f:
            f.write(content)
        os.replace(temp_filepath, filepath)

    def on_shutdown(self, sig, frame):
        report = self.generate_report(self.current_date)
        self.save_to_file(f"outbound_traffic_{self.current_date}.txt", report)
        self.save_to_file("outbound_traffic_current.txt", report)
        if self.proc and self.proc.poll() is None:
            self.proc.terminate()
            try:
                self.proc.wait(timeout=2)
            except subprocess.TimeoutExpired:
                self.proc.kill()
        sys.exit(0)

    def run(self):
        signal.signal(signal.SIGTERM, self.on_shutdown)
        signal.signal(signal.SIGINT, self.on_shutdown)

        cmd = ["tcpdump", "-i", self.interface, "-nn"]
        if self.direction_filter:
            cmd.extend(self.direction_filter.split())
        cmd.append("-l")

        try:
            self.proc = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL,
                text=True,
                bufsize=1
            )
        except FileNotFoundError:
            sys.stderr.write("Error: tcpdump command not found. Please install tcpdump.\n")
            sys.exit(1)

        for line in self.proc.stdout:
            # Check for 24-hour day rollover (midnight)
            today = datetime.now().strftime("%Y-%m-%d")
            if today != self.current_date:
                final_report = self.generate_report(self.current_date)
                self.save_to_file(f"outbound_traffic_{self.current_date}.txt", final_report)
                self.stats.clear()
                self.current_date = today

            # Parse tcpdump format: IP src > dst: protocol, length X
            match = re.search(r">\s+([^\s]+?):\s+.*?length\s+(\d+)", line)
            if match:
                dst, length = match.group(1), int(match.group(2))

                # Check exclusion filter
                if self.is_excluded(dst):
                    continue

                if dst not in self.stats:
                    self.stats[dst] = {"packets": 0, "bytes": 0}
                self.stats[dst]["packets"] += 1
                self.stats[dst]["bytes"] += length

            # Periodic sync to current snapshot file
            now = time.time()
            if now - self.last_disk_sync >= self.sync_interval:
                current_report = self.generate_report(self.current_date)
                self.save_to_file("outbound_traffic_current.txt", current_report)
                self.last_disk_sync = now


def main():
    parser = argparse.ArgumentParser(description="24-Hour Outbound Traffic Monitor")
    parser.add_argument("--log-dir", default=os.environ.get("TRAFFIC_MONITOR_LOG_DIR", DEFAULT_LOG_DIR),
                        help=f"Directory to save traffic logs (default: {DEFAULT_LOG_DIR})")
    parser.add_argument("--interface", "-i", default=os.environ.get("TRAFFIC_MONITOR_INTERFACE", DEFAULT_INTERFACE),
                        help=f"Network interface (default: {DEFAULT_INTERFACE})")
    parser.add_argument("--filter", default=os.environ.get("TRAFFIC_MONITOR_FILTER", DEFAULT_FILTER),
                        help=f"Direction filter for tcpdump (default: {DEFAULT_FILTER})")
    parser.add_argument("--sync-interval", type=int,
                        default=int(os.environ.get("TRAFFIC_MONITOR_SYNC_INTERVAL", DEFAULT_SYNC_INTERVAL)),
                        help=f"Disk sync interval in seconds (default: {DEFAULT_SYNC_INTERVAL})")
    parser.add_argument("--exclude-networks",
                        default=os.environ.get("TRAFFIC_MONITOR_EXCLUDE_NETWORKS", ""),
                        help="Comma-separated IPs/CIDRs to exclude (e.g. '127.0.0.0/8,169.254.169.254')")
    parser.add_argument("--exclude-containers",
                        default=os.environ.get("TRAFFIC_MONITOR_EXCLUDE_CONTAINERS", "true").lower() in ("true", "1", "yes"),
                        action=argparse.BooleanOptionalAction,
                        help="Automatically detect and exclude local container bridge networks (default: true)")

    args = parser.parse_args()

    excluded = parse_excluded_networks(args.exclude_networks, include_containers=args.exclude_containers)

    monitor = TrafficMonitor(
        log_dir=args.log_dir,
        interface=args.interface,
        direction_filter=args.filter,
        sync_interval=args.sync_interval,
        excluded_networks=excluded
    )
    monitor.run()


if __name__ == "__main__":
    main()

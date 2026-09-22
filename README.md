# Traffic Monitor

A lightweight, automated 24-hour outbound network traffic monitor and aggregator for Linux. Built on top of `tcpdump` and Python, managed as a resilient `systemd` service.

## Overview

Unlike standard packet sniffing tools that flood terminal scrollbacks with millions of individual packet records, **Traffic Monitor** groups and aggregates network flow per destination endpoint (`IP:Port`). It tracks packet counts and cumulative transferred bytes in real-time, automatically rotating logs every 24 hours.

### Key Features

* **Real-time Flow Aggregation**: Summarizes traffic per unique `DESTINATION (IP:PORT)`. No redundant per-packet log spam.
* **Auto-Sorted by Volume**: Endpoints consuming the highest bandwidth always appear at the top (descending sort by bytes).
* **Automatic Container & IP Exclusion**: Filters out traffic to local container networks (`docker0`, `br-*`, Podman, CNI, virbr) and custom IP/CIDR blocks to focus strictly on real external/cross-cloud network traffic.
* **Automatic 24-Hour Log Rotation**: Automatically saves the completed day's report at midnight (`00:00`) to `outbound_traffic_YYYY-MM-DD.txt` and resets daily counters without stopping or dropping captured packets.
* **Periodic Live Snapshot**: Flushes current day-to-date traffic metrics every 10 seconds to `outbound_traffic_current.txt`.
* **Zero Data Loss on Shutdown**: Intercepts `SIGTERM` and `SIGINT` signals so when the system shuts down or the service stops/restarts, the latest metrics are safely synced to disk.
* **Systemd Native**: Automatic restart on failure, auto-start on boot, standard log integration.

---

## Directory Structure

```text
.
├── traffic-monitor.py       # Core Python traffic aggregator
├── traffic-monitor.service  # Systemd service unit file
├── install.sh               # One-step automated installation script
├── uninstall.sh             # Uninstallation and cleanup script
└── README.md                # Documentation and usage guide
```

---

## Prerequisites

* Linux OS (Ubuntu/Debian, RHEL/Rocky/Alma/CentOS, Amazon Linux, etc.)
* `python3` (v3.6+)
* `tcpdump`
* Root or `sudo` privileges

---

## Installation

### Method 1: Quick Install via `curl` (Recommended)

You can install and start the service directly in a single command without cloning:

```bash
curl -fsSL https://raw.githubusercontent.com/ics-andre/traffic-monitor/main/install.sh | sudo bash
```

> **Note for Private Repository Access:**  
> If the repository is private, authenticate using a GitHub Personal Access Token (PAT):
> ```bash
> curl -fsSL -H "Authorization: token <YOUR_GITHUB_TOKEN>" \
>   https://raw.githubusercontent.com/ics-andre/traffic-monitor/main/install.sh | sudo bash
> ```
> Or if using `gh` CLI:
> ```bash
> gh api repos/ics-andre/traffic-monitor/contents/install.sh -H "Accept: application/vnd.github.raw" | sudo bash
> ```

---

### Method 2: Install via Git Clone

1. Clone this repository onto your server:
   ```bash
   git clone https://github.com/ics-andre/traffic-monitor.git
   cd traffic-monitor
   ```

2. Run the installer:
   ```bash
   sudo ./install.sh
   ```

The installer script automatically:
* Verifies and installs missing dependencies (`python3`, `tcpdump`).
* Deploys the standalone executable to `/usr/local/bin/traffic-monitor.py`.
* Sets up `/etc/default/traffic-monitor` for configuration.
* Creates the log directory at `/var/log/traffic-monitor/`.
* Deploys, enables, and starts/restarts the systemd unit `traffic-monitor.service`.

---

## Usage & Operations

### Checking Service Status

```bash
sudo systemctl status traffic-monitor
```

### Viewing Live Traffic Metrics

To view the active day's aggregated outbound traffic:
```bash
sudo cat /var/log/traffic-monitor/outbound_traffic_current.txt
```

To continuously watch live traffic updates (refreshes every 2 seconds):
```bash
watch -n 2 'sudo cat /var/log/traffic-monitor/outbound_traffic_current.txt'
```

### Viewing Archived Daily Reports

Each day at `00:00` (midnight), a completed summary is archived:
```bash
ls -lh /var/log/traffic-monitor/
```

Example listing:
```text
/var/log/traffic-monitor/
├── outbound_traffic_current.txt       # Real-time running total for today
├── outbound_traffic_2026-09-22.txt    # Archived report for 2026-09-22
└── outbound_traffic_2026-09-23.txt    # Archived report for 2026-09-23
```

---

## Log Output Format

Reports are rendered in an easy-to-read tabular format:

```text
# Outbound Traffic Report - Date: 2026-09-23
# Last Updated: 2026-09-23 00:15:30
------------------------------------------------------------------------
DESTINATION (IP:PORT)                      PACKETS      TOTAL BYTES    
------------------------------------------------------------------------
10.101.64.10.6379                          17201        13803520       
10.101.0.4.9009                            533          3511054        
10.151.10.136.1514                         390          181836         
10.101.0.4.3100                            282          89153          
10.126.1.6.9443                            330          57915          
10.101.0.10.53234                          25           36431          
169.254.169.254.80                         823          25341          
10.101.0.14.8200                           66           11316          
------------------------------------------------------------------------
GRAND TOTAL                                19650        17716566       
```

---

## Custom Configuration & IP/Container Exclusion

You can customize the monitor behavior, including excluding local container networks or specific IP addresses, by editing `/etc/default/traffic-monitor`:

```bash
sudo tee /etc/default/traffic-monitor << 'EOF'
# Network interface to listen on (default: any)
TRAFFIC_MONITOR_INTERFACE=any

# Direction filter passed to tcpdump (default: -Q out)
TRAFFIC_MONITOR_FILTER="-Q out"

# Log storage directory (default: /var/log/traffic-monitor)
TRAFFIC_MONITOR_LOG_DIR=/var/log/traffic-monitor

# Live snapshot sync interval in seconds (default: 10)
TRAFFIC_MONITOR_SYNC_INTERVAL=10

# Automatically detect and exclude local container bridge networks
# (e.g., Docker docker0, Harbor br-*, Podman, CNI, virbr)
TRAFFIC_MONITOR_EXCLUDE_CONTAINERS=true

# Additional IP addresses or CIDR blocks to exclude (comma-separated)
# Example: loopback, cloud metadata, or host IP:
TRAFFIC_MONITOR_EXCLUDE_NETWORKS="127.0.0.0/8,169.254.169.254/32"
EOF
```

After modifying the configuration, restart the service to apply changes:
```bash
sudo systemctl restart traffic-monitor
```

---

## Uninstallation

### One-Liner via `curl`

To cleanly stop the service and remove all installed files:
```bash
curl -fsSL https://raw.githubusercontent.com/ics-andre/traffic-monitor/main/uninstall.sh | sudo bash
```

To uninstall **and** delete all stored log files at `/var/log/traffic-monitor`:
```bash
curl -fsSL https://raw.githubusercontent.com/ics-andre/traffic-monitor/main/uninstall.sh | sudo bash -s -- --purge
```

---

### Local Uninstallation

If you cloned the repository:
```bash
sudo ./uninstall.sh          # Preserves /var/log/traffic-monitor
# or
sudo ./uninstall.sh --purge  # Also removes log directory
```

---

## License

MIT License. See [LICENSE](LICENSE) for details.

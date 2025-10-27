# Per-User Data Transfer Tracker (XDP Version)

An eBPF-based tool to track network traffic per user in real-time, with support for specifying the network interface to monitor.

## Features

- Track network traffic on a per-user basis
- Monitor specific network interfaces via command line
- Log total bytes transferred for each user
- Real-time statistics with configurable intervals
- Minimal performance overhead using eBPF

## Building

```bash
make build-xdp
```

## Usage

```bash
sudo ./pdtt_xdp_user -i <interface> [-l <logfile>] [-t <interval>]
```

### Options

- `-i <interface>` - Network interface to monitor (required, e.g., eth0, wlan0, lo)
- `-l <logfile>` - Path to log file (default: /var/log/pdtt_stats.log)
- `-t <interval>` - Statistics logging interval in seconds (default: 10)
- `-h` - Show help message

### Examples

Monitor eth0 interface with default settings:
```bash
sudo ./pdtt_xdp_user -i eth0
```

Monitor wlan0 with custom log file and 5-second interval:
```bash
sudo ./pdtt_xdp_user -i wlan0 -l /tmp/traffic.log -t 5
```

Monitor loopback interface:
```bash
sudo ./pdtt_xdp_user -i lo
```

## Output

The tool logs statistics to the specified file (default: `/var/log/pdtt_stats.log`) with the following format:

```
=== Network Statistics Report [2024-01-15 10:30:00] ===
UID: 1000 | Username: john
  Total: 1048576 bytes
---
UID: 1001 | Username: jane
  Total: 524288 bytes
---
```

Statistics are also displayed on the console in real-time.

## Requirements

- Linux kernel 5.0 or later with eBPF support
- Root/sudo privileges
- libbpf, libelf, and zlib libraries
- clang compiler
- bpftool

## How It Works

The tool uses eBPF cgroup socket filters to track network traffic:

1. Attaches to the cgroup hierarchy to intercept socket operations
2. Tracks ingress (RX) and egress (TX) traffic per user ID
3. Maintains a hash map of statistics indexed by UID
4. Periodically logs cumulative statistics to file

## Stopping the Tool

Press Ctrl+C to gracefully stop the tracker. Final statistics will be logged before exit.

## Troubleshooting

If you encounter "Failed to attach program to cgroup" errors:
- Ensure you're running with sudo/root privileges
- Check that your kernel supports eBPF cgroup programs
- Verify cgroup v2 is mounted at /sys/fs/cgroup

If interface not found:
- Use `ip link show` to list available interfaces
- Ensure the interface name is correct and the interface exists

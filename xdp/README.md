# Pawsey Data Transfer Tracker

An eBPF-based tool to track network traffic per user in real-time, with
support for specifying the network interface to monitor. Logs source and
destination IP addresses for each connection.

## Features

- Track network traffic on a per-user basis
- Monitor specific network interfaces via command line
- Log source and destination IP addresses for each connection
- Log total bytes transferred for each user
- Per-user log files with configurable prefix
- Real-time statistics with configurable intervals
- Minimal performance overhead using eBPF

## Building

```bash
make build-xdp
```

## Usage

```bash
sudo ./pdtt_xdp_user -i <interface> [-l <prefix>] [-t <interval>]
```

### Options

- `-i <interface>` - Network interface to monitor (required, e.g., eth0,
  wlan0, lo)
- `-l <prefix>` - Log file prefix (default: /var/log/pdtt). Log files are
  created as `<prefix>-<username>.log`
- `-t <interval>` - Statistics logging interval in seconds (default: 10)
- `-h` - Show help message

### Examples

Monitor eth0 interface with default settings:

```bash
sudo ./pdtt_xdp_user -i eth0
```

Monitor wlan0 with custom log prefix and 5-second interval:

```bash
sudo ./pdtt_xdp_user -i wlan0 -l /tmp/traffic -t 5
```

Monitor loopback interface:

```bash
sudo ./pdtt_xdp_user -i lo
```

## Output

The tool creates separate log files for each user with the format
`<prefix>-<username>.log`. For example, with the default prefix
`/var/log/pdtt`, user `john` would have `/var/log/pdtt-john.log`.

Each log file contains entries with source/destination IP addresses and
byte counts:

```
=== Network Statistics Report [2024-01-15 10:30:00] ===
Connection: 192.168.1.100 -> 93.184.216.34
  TX: 524288 bytes | RX: 1048576 bytes | Total: 1572864 bytes
---
Connection: 192.168.1.100 -> 8.8.8.8
  TX: 262144 bytes | RX: 131072 bytes | Total: 393216 bytes
---
Total traffic: 1966080 bytes
```

Statistics are also displayed on the console in real-time.

## Requirements

- Linux kernel 5.0 or later with eBPF support
- Root/sudo privileges
- libbpf, libelf, and zlib libraries
- clang compiler
- bpftool

## How It Works

The tool uses eBPF XDP filters to track network traffic:

1. Attaches to the specified network interface using XDP
2. Extracts source and destination IP addresses from packets
3. Maps socket connections to user IDs
4. Tracks ingress (RX) and egress (TX) traffic per connection
5. Maintains hash maps of statistics indexed by connection and UID
6. Periodically logs per-connection statistics to per-user log files

## Stopping the Tool

Press Ctrl+C to gracefully stop the tracker. Final statistics will be logged
before exit.

## Troubleshooting

If you encounter "Failed to attach program to cgroup" errors:

- Ensure you're running with sudo/root privileges
- Check that your kernel supports eBPF cgroup programs
- Verify cgroup v2 is mounted at /sys/fs/cgroup

If interface not found:

- Use `ip link show` to list available interfaces
- Ensure the interface name is correct and the interface exists

If log files are not created:

- Verify write permissions for the log directory
- Check that the log prefix path exists

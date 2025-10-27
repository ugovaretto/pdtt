# Pawsey Data Transfer Tracker (pddt)

## Overview

An eBPF-based network monitoring tool that tracks data transfer statistics per
user. The program monitors network packets and logs the total amount of bytes
transferred for each user.

## Available Versions

This project includes three versions:

1. **Socket-based version** - Uses cgroup socket filters
2. **TC-based version** - Uses traffic control (TC) hooks  
3. **XDP version** - Supports per-interface monitoring with command-line interface selection ⭐ **NEW**

## Features

- Tracks TX/RX bytes and packets per user ID
- Logs statistics to configurable log files
- Real-time monitoring with configurable intervals
- Support for socket, TC, and XDP eBPF attachment
- User-friendly log output with timestamps
- **Command-line interface selection (XDP version)**

## Requirements

- Linux kernel with eBPF support (kernel 5.0+ recommended)
- clang/llvm compiler
- libbpf development library
- bpftool
- Root privileges for loading eBPF programs

### Installation (Ubuntu/Debian)

```bash
sudo apt update
sudo apt install -y clang llvm libelf-dev libbpf-dev \
    linux-headers-$(uname -r) bpftool
```

### Installation (RHEL/CentOS)

```bash
sudo yum install -y clang llvm elfutils-libelf-devel libbpf-devel \
    kernel-devel bpftool
```

## Building

```bash
# Build socket-based version
make build

# Build TC (traffic control) version
make build-tc

# Build XDP version (recommended)
make build-xdp

# Build all versions
make all
```

## Usage

### XDP Version (Recommended - with interface selection)

```bash
# Build the XDP version
make build-xdp

# Run with required interface parameter
sudo ./pdtt_xdp_user -i eth0

# Run with custom log file and interval
sudo ./pdtt_xdp_user -i wlan0 -l /tmp/traffic.log -t 5

# Monitor loopback interface
sudo ./pdtt_xdp_user -i lo

# Show help
./pdtt_xdp_user -h
```

**Command-line options for XDP version:**
- `-i <interface>` - Network interface to monitor (required, e.g., eth0, wlan0, lo)
- `-l <logfile>` - Path to log file (default: /var/log/pdtt_stats.log)
- `-t <interval>` - Statistics logging interval in seconds (default: 10)
- `-h` - Show help message

See [README_XDP.md](README_XDP.md) for detailed XDP version documentation.

### Socket-based version

```bash
# Build and install
sudo make install

# Run the daemon
sudo ./pdtt_user
```

### TC-based version

```bash
# Build and install
sudo make install-tc

# Load eBPF program
sudo make test-load

# Run the daemon
sudo ./pdtt_user_tc
```

## Testing

```bash
# Test XDP version
sudo ./test_xdp.sh [interface]

# Run all tests
make test

# Run specific test
make test-single TEST=basic_load
make test-single TEST=network_traffic
make test-single TEST=cleanup

# Test TC version
make test-tc
```

## Log Output

### XDP Version Output

```
=== Network Statistics Report [2025-10-27 14:30:00] ===
UID: 1000 | Username: john
  Total: 1048576 bytes
---
UID: 1001 | Username: jane
  Total: 524288 bytes
---
```

### Socket/TC Version Output

```
=== Network Statistics Report [2025-10-27 14:30:00] ===
UID: 1000 | Username: user
  TX: 2048 bytes (15 packets)
  RX: 4096 bytes (20 packets)
  Total: 6144 bytes (35 packets)
---
```

## Configuration

- Stats interval: 10 seconds (configurable via `-t` option in XDP version)
- Log file location: `/var/log/pdtt_stats.log` (configurable via `-l` option in XDP version)
- Max users tracked: 1024 (configurable in eBPF program)

## Security Considerations

- Requires root privileges to load eBPF programs
- Only tracks network traffic metadata (no packet content inspection)
- Uses kernel-safe eBPF helper functions
- Respects eBPF verifier constraints

## Troubleshooting

### General

- Ensure eBPF is enabled: `cat /proc/sys/net/core/bpf_jit_enable`
- Check kernel logs: `dmesg | grep -i bpf`
- Check log file permissions: `ls -la /var/log/pdtt_stats.log`

### XDP Version Specific

- If interface not found, use `ip link show` to list available interfaces
- Ensure the interface name is correct and exists
- Check that cgroup v2 is mounted at /sys/fs/cgroup
- Verify you're running with sudo/root privileges

### TC Version Specific

- Verify interface permissions for TC attachment
- Check TC filters: `sudo tc filter show dev lo`

## Unloading

```bash
# Unload TC filters
make unload

# Stop any daemon with Ctrl+C or kill signal
```

## Files

- `pdtt_kern.c` / `pdtt_user.c` - Socket-based version
- `pdtt_kern_tc.c` / `pdtt_user_tc.c` - TC-based version  
- `pdtt_xdp_kern.c` / `pdtt_xdp_user.c` - XDP version with interface selection
- `Makefile` - Build configuration
- `test_xdp.sh` - XDP version test script
- `README_XDP.md` - Detailed XDP version documentation

## License

GPL (required for eBPF programs)

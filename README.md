# Pawsey Data Transfer Tracker (pddt)

## Overview

An eBPF-based network monitoring tool that tracks data transfer statistics per
user. The program monitors network packets and logs the total amount of bytes
transferred for each user.

## Features

- Tracks TX/RX bytes and packets per user ID
- Logs statistics to `/var/log/pdtt_stats.log`
- Real-time monitoring with configurable intervals
- Support for both socket and TC (traffic control) eBPF attachment
- User-friendly log output with timestamps

## Requirements

- Linux kernel with eBPF support (kernel 4.14+)
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

# Build both versions
make all
```

## Usage

### Socket-based version

```bash
# Build and install
sudo make install

# Run the daemon
sudo ./pdtt_user
```

### TC-based version (recommended for better visibility)

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

Statistics are logged to `/var/log/pdtt_stats.log` every 10 seconds:

```
=== Network Statistics Report [2025-10-27 14:30:00] ===
UID: 1000 | Username: user
  TX: 2048 bytes (15 packets)
  RX: 4096 bytes (20 packets)
  Total: 6144 bytes (35 packets)
---
```

## Configuration

- Stats interval: 10 seconds (configurable in `pdtt_user.c`)
- Log file location: `/var/log/pdtt_stats.log`
- Max users tracked: 1024 (configurable in eBPF program)

## Security Considerations

- Requires root privileges to load eBPF programs
- Only tracks network traffic metadata (no packet content inspection)
- Uses kernel-safe eBPF helper functions
- Respects eBPF verifier constraints

## Troubleshooting

- Ensure eBPF is enabled: `cat /proc/sys/net/core/bpf_jit_enable`
- Check kernel logs: `dmesg | grep -i bpf`
- Verify interface permissions for TC attachment
- Check log file permissions: `ls -la /var/log/pdtt_stats.log`

## Unloading

```bash
# Unload TC filters
make unload

# Stop the daemon with Ctrl+C or kill signal
```

## Features

- Tracks TX/RX bytes and packets per user ID
- Logs statistics to `/var/log/pdtt_stats.log`
- Real-time monitoring with configurable intervals
- Support for both socket and TC (traffic control) eBPF attachment
- User-friendly log output with timestamps

## Requirements

- Linux kernel with eBPF support (kernel 4.14+)
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

# Build both versions
make all
```

## Usage

### Socket-based version

```bash
# Build and install
sudo make install

# Run the daemon
sudo ./pdtt_user
```

### TC-based version (recommended for better visibility)

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

Statistics are logged to `/var/log/pdtt_stats.log` every 10 seconds:

```
=== Network Statistics Report [2025-10-27 14:30:00] ===
UID: 1000 | Username: user
  TX: 2048 bytes (15 packets)
  RX: 4096 bytes (20 packets)
  Total: 6144 bytes (35 packets)
---
```

## Configuration

- Stats interval: 10 seconds (configurable in `pdtt_user.c`)
- Log file location: `/var/log/pdtt_stats.log`
- Max users tracked: 1024 (configurable in eBPF program)

## Security Considerations

- Requires root privileges to load eBPF programs
- Only tracks network traffic metadata (no packet content inspection)
- Uses kernel-safe eBPF helper functions
- Respects eBPF verifier constraints

## Troubleshooting

- Ensure eBPF is enabled: `cat /proc/sys/net/core/bpf_jit_enable`
- Check kernel logs: `dmesg | grep -i bpf`
- Verify interface permissions for TC attachment
- Check log file permissions: `ls -la /var/log/pdtt_stats.log`

## Unloading

```bash
# Unload TC filters
make unload

# Stop the daemon with Ctrl+C or kill signal
```


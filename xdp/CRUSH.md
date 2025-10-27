# Pawsey Data Transfer Tracker (pddt) - Development Guide

## Project Overview

eBPF XDP-based filter for per-user tracking of network data transfer with
source and destination IP address logging.

## Build Commands

```bash
# Build XDP program and userspace daemon
make build

# Build (same as above)
make all

# Clean build artifacts
make clean

# Install with root privileges
sudo make install
```

## Testing Commands

```bash
# Run XDP test
make test

# Manual test with specific interface
sudo ./test_xdp.sh [interface]
```

## Usage

```bash
# Run with required interface parameter
sudo ./pdtt_xdp_user -i eth0

# Run with custom log prefix and interval
sudo ./pdtt_xdp_user -i wlan0 -l /tmp/traffic -t 5

# Monitor loopback interface
sudo ./pdtt_xdp_user -i lo

# Show help
./pdtt_xdp_user -h
```

## Log Files

Log files are created per-user with the format `<prefix>-<username>.log`.
For example, with prefix `/var/log/pdtt`, the log file for user `john` would
be `/var/log/pdtt-john.log`.

## Code Style Guidelines

### eBPF/C Programming

- Use kernel coding style (Linux kernel conventions)
- 8-space indentation, no tabs
- 80-character line limit where practical
- Function names: snake_case
- Variables: snake_case
- Constants: UPPER_CASE

### Imports/Includes

- Kernel includes first, then standard library, then project headers
- Use `#include <linux/bpf.h>` for eBPF functionality
- Include guards for all header files

### Error Handling

- Always check return values from eBPF helper functions
- Use appropriate error codes from `linux/errno.h`
- Log errors with `bpf_printk()` for debugging

### Memory Management

- Use eBPF maps for data storage
- Respect stack size limitations (512 bytes)
- Use BPF_PERF_OUTPUT for userspace communication

### Naming Conventions

- Map names: descriptive, snake_case (e.g., `user_data_stats`)
- Program sections: use SEC() macro with descriptive names
- Struct names: snake_case with_t suffix for typedefs

### Security

- Validate all input data
- Use bounds checking on array access
- Follow eBPF verifier requirements

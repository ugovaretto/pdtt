# Pawsey Data Transfer Tracker (pddt) - Development Guide

## Project Overview
eBPF filter for per-user tracking of data transferred between local systems and external servers.

## Build Commands
```bash
# Build eBPF program and userspace daemon
make build

# Build TC (traffic control) version
make build-tc

# Build all versions
make all

# Clean build artifacts
make clean

# Install with root privileges
sudo make install
```

## Testing Commands
```bash
# Run all tests
make test

# Run specific test
make test-single TEST=<test_name>
# Available tests: basic_load, network_traffic, cleanup

# Load and test eBPF TC program
sudo make test-load

# Unload TC program
make unload
```

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
- Struct names: snake_case with _t suffix for typedefs

### Security
- Validate all input data
- Use bounds checking on array access
- Follow eBPF verifier requirements
# SPDX-License-Identifier: BSD-3-Clause
# Copyright (c) 2025 Ugo Varetto <ugo.varetto@pawsey.org.au>
#!/bin/bash

set -e

echo "=== Testing  Pawsey Data Traffic Tracker (pdtt) ==="
echo

if [ "$EUID" -ne 0 ]; then
  echo "Please run as root (sudo)"
  exit 1
fi

LOG_FILE="/tmp/pdtt_test_$$.log"
INTERFACE="${1:-lo}"

echo "Using interface: $INTERFACE"
echo "Log file: $LOG_FILE"
echo

if ! ip link show "$INTERFACE" >/dev/null 2>&1; then
  echo "Error: Interface $INTERFACE not found"
  echo "Available interfaces:"
  ip -brief link show
  exit 1
fi

echo "Building the tool..."
make build-xdp

echo
echo "Starting tracker in background (10 seconds)..."
timeout 10 ./pdtt_xdp_user -i "$INTERFACE" -l "$LOG_FILE" -t 3 &
PID=$!

sleep 2

echo "Generating some network traffic..."
ping -c 5 127.0.0.1 >/dev/null 2>&1 || true
curl -s http://example.com >/dev/null 2>&1 || true

wait $PID || true

echo
echo "=== Log file contents ==="
if [ -f "$LOG_FILE" ]; then
  cat "$LOG_FILE"
  echo
  echo "Test completed successfully!"
  rm -f "$LOG_FILE"
else
  echo "Warning: Log file not created"
fi

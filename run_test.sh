#!/bin/bash

# Test script for pdtt eBPF program
# Usage: ./run_test.sh <test_name>

TEST_NAME=$1
LOG_FILE="/var/log/pdtt_stats.log"

if [ -z "$TEST_NAME" ]; then
    echo "Usage: $0 <test_name>"
    echo "Available tests: basic_load, network_traffic, cleanup"
    exit 1
fi

case $TEST_NAME in
    "basic_load")
        echo "Testing basic eBPF program load..."
        make build
        if [ $? -eq 0 ]; then
            echo "✓ Build successful"
        else
            echo "✗ Build failed"
            exit 1
        fi
        ;;
    
    "network_traffic")
        echo "Testing network traffic tracking..."
        make test-load
        sleep 1
        
        # Generate some network traffic
        ping -c 3 127.0.0.1 > /dev/null 2>&1
        curl -s http://127.0.0.1 > /dev/null 2>&1 || true
        
        sleep 2
        make unload
        
        if [ -f "$LOG_FILE" ]; then
            echo "✓ Log file created"
            echo "Recent log entries:"
            tail -5 "$LOG_FILE"
        else
            echo "✗ Log file not created"
            exit 1
        fi
        ;;
    
    "cleanup")
        echo "Cleaning up test environment..."
        make unload
        make clean
        rm -f "$LOG_FILE"
        echo "✓ Cleanup complete"
        ;;
    
    *)
        echo "Unknown test: $TEST_NAME"
        echo "Available tests: basic_load, network_traffic, cleanup"
        exit 1
        ;;
esac

echo "Test '$TEST_NAME' completed successfully"
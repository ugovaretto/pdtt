CC = clang
CFLAGS = -O2 -g -Wall -Wextra
LDFLAGS = -lbpf -lelf -lz

all: pdtt_user

# Generate skeleton header from eBPF program
pdtt_kern.skel.h: pdtt_kern.o
	bpftool gen skeleton pdtt_kern.o > pdtt_kern.skel.h

pdtt_kern_tc.skel.h: pdtt_kern_tc.o
	bpftool gen skeleton pdtt_kern_tc.o > pdtt_kern_tc.skel.h

# Compile userspace program
pdtt_user: pdtt_user.c pdtt_kern.skel.h
	$(CC) $(CFLAGS) -o pdtt_user pdtt_user.c $(LDFLAGS)

pdtt_user_tc: pdtt_user.c pdtt_kern_tc.skel.h
	$(CC) $(CFLAGS) -DUSE_TC -o pdtt_user_tc pdtt_user.c $(LDFLAGS)

# Compile eBPF program
pdtt_kern.o: pdtt_kern.c
	$(CC) $(CFLAGS) -target bpf -c pdtt_kern.c -o pdtt_kern.o

pdtt_kern_tc.o: pdtt_kern_tc.c
	$(CC) $(CFLAGS) -target bpf -c pdtt_kern_tc.c -o pdtt_kern_tc.o

# Build everything
build: pdtt_kern.o pdtt_user

build-tc: pdtt_kern_tc.o pdtt_user_tc

# Clean build artifacts
clean:
	rm -f *.o *.skel.h pdtt_user pdtt_user_tc

# Install (requires root)
install: build
	sudo cp pdtt_user /usr/local/bin/
	sudo mkdir -p /var/log
	sudo touch /var/log/pdtt_stats.log
	sudo chmod 666 /var/log/pdtt_stats.log

install-tc: build-tc
	sudo cp pdtt_user_tc /usr/local/bin/
	sudo mkdir -p /var/log
	sudo touch /var/log/pdtt_stats.log
	sudo chmod 666 /var/log/pdtt_stats.log

# Run tests
test: build
	sudo ./pdtt_user &
	sleep 2
	sudo pkill pdtt_user

test-tc: build-tc
	sudo ./pdtt_user_tc &
	sleep 2
	sudo pkill pdtt_user_tc

# Run specific test
test-single: build
	@if [ -z "$(TEST)" ]; then \
		echo "Usage: make test-single TEST=<test_name>"; \
		exit 1; \
	fi
	sudo ./run_test.sh $(TEST)

# Load and test eBPF program
test-load: build
	sudo ip link set dev lo up
	sudo tc qdisc add dev lo clsact
	sudo tc filter add dev lo ingress bpf da obj pdtt_kern_tc.o sec ingress_tracker
	sudo tc filter add dev lo egress bpf da obj pdtt_kern_tc.o sec egress_tracker
	@echo "eBPF program loaded. Run 'sudo tc filter show dev lo' to verify."

# Unload eBPF program
unload:
	sudo tc qdisc del dev lo clsact 2>/dev/null || true

.PHONY: all build build-tc clean install install-tc test test-tc test-single test-load unload
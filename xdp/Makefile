CC = clang
CFLAGS = -O2 -g -Wall -Wextra
LDFLAGS = -lbpf -lelf -lz

all: pdtt_xdp_user

pdtt_xdp_kern.skel.h: pdtt_xdp_kern.o
	bpftool gen skeleton pdtt_xdp_kern.o > pdtt_xdp_kern.skel.h

pdtt_xdp_user: pdtt_xdp_user.c pdtt_xdp_kern.skel.h
	$(CC) $(CFLAGS) -o pdtt_xdp_user pdtt_xdp_user.c $(LDFLAGS)

pdtt_xdp_kern.o: pdtt_xdp_kern.c
	$(CC) $(CFLAGS) -target bpf -D__TARGET_ARCH_x86 -c pdtt_xdp_kern.c -o pdtt_xdp_kern.o

build: pdtt_xdp_kern.o pdtt_xdp_user

clean:
	rm -f *.o *.skel.h pdtt_xdp_user

install: build
	sudo cp pdtt_xdp_user /usr/local/bin/
	sudo mkdir -p /var/log
	sudo touch /var/log/pdtt_stats.log
	sudo chmod 666 /var/log/pdtt_stats.log

test: build
	sudo ./test_xdp.sh

.PHONY: all build clean install test

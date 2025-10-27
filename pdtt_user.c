#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <signal.h>
#include <time.h>
#include <sys/resource.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include <linux/types.h>
#include "pdtt_kern.skel.h"

struct user_data_stats {
    __u32 uid;
    __u64 tx_bytes;
    __u64 rx_bytes;
    __u64 tx_packets;
    __u64 rx_packets;
    char username[16];
};

#define LOG_FILE "/var/log/pdtt_stats.log"
#define STATS_INTERVAL 10

static volatile bool running = true;

void sig_handler(int sig)
{
    running = false;
}

void log_user_stats(int map_fd)
{
    __u32 key = 0, next_key;
    struct user_data_stats stats;
    FILE *log_file;
    time_t now;
    char timestamp[64];
    
    log_file = fopen(LOG_FILE, "a");
    if (!log_file) {
        fprintf(stderr, "Failed to open log file: %s\n", strerror(errno));
        return;
    }
    
    time(&now);
    strftime(timestamp, sizeof(timestamp), "%Y-%m-%d %H:%M:%S", localtime(&now));
    
    fprintf(log_file, "\n=== Network Statistics Report [%s] ===\n", timestamp);
    
    while (bpf_map_get_next_key(map_fd, &key, &next_key) == 0) {
        if (bpf_map_lookup_elem(map_fd, &next_key, &stats) == 0) {
            fprintf(log_file, "UID: %u | Username: %s\n", stats.uid, stats.username);
            fprintf(log_file, "  TX: %lu bytes (%lu packets)\n", 
                   stats.tx_bytes, stats.tx_packets);
            fprintf(log_file, "  RX: %lu bytes (%lu packets)\n", 
                   stats.rx_bytes, stats.rx_packets);
            fprintf(log_file, "  Total: %lu bytes (%lu packets)\n", 
                   stats.tx_bytes + stats.rx_bytes, 
                   stats.tx_packets + stats.rx_packets);
            fprintf(log_file, "---\n");
        }
        key = next_key;
    }
    
    fclose(log_file);
}

int main(int argc, char **argv)
{
    struct pdtt_kern *skel;
    int map_fd;
    int err;
    
    printf("Pawsey Data Transfer Tracker - Userspace Daemon\n");
    printf("Logging statistics to: %s\n", LOG_FILE);
    printf("Stats interval: %d seconds\n", STATS_INTERVAL);
    
    signal(SIGINT, sig_handler);
    signal(SIGTERM, sig_handler);
    
    skel = pdtt_kern__open();
    if (!skel) {
        fprintf(stderr, "Failed to open BPF skeleton\n");
        return 1;
    }
    
    err = pdtt_kern__load(skel);
    if (err) {
        fprintf(stderr, "Failed to load BPF program: %s\n", strerror(err));
        pdtt_kern__destroy(skel);
        return 1;
    }
    
    err = pdtt_kern__attach(skel);
    if (err) {
        fprintf(stderr, "Failed to attach BPF program: %s\n", strerror(err));
        pdtt_kern__destroy(skel);
        return 1;
    }
    
    map_fd = bpf_map__fd(skel->maps.user_stats_map);
    if (map_fd < 0) {
        fprintf(stderr, "Failed to get map file descriptor\n");
        pdtt_kern__detach(skel);
        pdtt_kern__destroy(skel);
        return 1;
    }
    
    printf("BPF program loaded and attached successfully\n");
    printf("Tracking network traffic per user...\n");
    
    while (running) {
        sleep(STATS_INTERVAL);
        if (running) {
            log_user_stats(map_fd);
        }
    }
    
    printf("\nFinal statistics report:\n");
    log_user_stats(map_fd);
    
    pdtt_kern__detach(skel);
    pdtt_kern__destroy(skel);
    
    printf("Pdtt daemon stopped\n");
    return 0;
}
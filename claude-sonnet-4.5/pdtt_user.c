#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <signal.h>
#include <time.h>
#include <sys/resource.h>
#include <sys/socket.h>
#include <linux/if_packet.h>
#include <arpa/inet.h>
#include <linux/if_ether.h>
#include <fcntl.h>
#include <pwd.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include <linux/types.h>
#ifdef USE_TC
#include "pdtt_kern_tc.skel.h"
#else
#include "pdtt_kern.skel.h"
#endif

struct user_data_stats {
    __u32 uid;
    __u64 tx_bytes;
    __u64 rx_bytes;
    __u64 tx_packets;
    __u64 rx_packets;
    char username[16];
    __u32 saddr;
    __u32 daddr;
    __u16 sport;
    __u16 dport;
};

#define DEFAULT_LOG_PREFIX "/var/log/pdtt"
#define STATS_INTERVAL 10

static volatile bool running = true;
static char *log_prefix = NULL;

void sig_handler(int sig __attribute__((unused)))
{
    running = false;
}

const char* get_username(__u32 uid)
{
    struct passwd *pw = getpwuid(uid);
    if (pw) {
        return pw->pw_name;
    }
    return "unknown";
}

void log_user_stats(int map_fd)
{
    __u32 key = 0, next_key;
    struct user_data_stats stats;
    FILE *log_file;
    time_t now;
    char timestamp[64];
    char saddr_str[INET_ADDRSTRLEN];
    char daddr_str[INET_ADDRSTRLEN];
    char user_log_path[512];
    
    time(&now);
    strftime(timestamp, sizeof(timestamp), "%Y-%m-%d %H:%M:%S", localtime(&now));
    
    while (bpf_map_get_next_key(map_fd, &key, &next_key) == 0) {
        if (bpf_map_lookup_elem(map_fd, &next_key, &stats) == 0) {
            const char *username = get_username(stats.uid);
            
            snprintf(user_log_path, sizeof(user_log_path), "%s-%s.log", log_prefix, username);
            
            log_file = fopen(user_log_path, "a");
            if (!log_file) {
                fprintf(stderr, "Failed to open log file %s: %s\n", user_log_path, strerror(errno));
                key = next_key;
                continue;
            }
            
            inet_ntop(AF_INET, &stats.saddr, saddr_str, INET_ADDRSTRLEN);
            inet_ntop(AF_INET, &stats.daddr, daddr_str, INET_ADDRSTRLEN);
            
            fprintf(log_file, "\n=== Network Statistics Report [%s] ===\n", timestamp);
            fprintf(log_file, "UID: %u | Username: %s\n", stats.uid, username);
            fprintf(log_file, "  Source: %s:%u\n", saddr_str, ntohs(stats.sport));
            fprintf(log_file, "  Destination: %s:%u\n", daddr_str, ntohs(stats.dport));
            fprintf(log_file, "  TX: %llu bytes (%llu packets)\n", 
                   stats.tx_bytes, stats.tx_packets);
            fprintf(log_file, "  RX: %llu bytes (%llu packets)\n", 
                   stats.rx_bytes, stats.rx_packets);
            fprintf(log_file, "  Total: %llu bytes (%llu packets)\n", 
                   stats.tx_bytes + stats.rx_bytes, 
                   stats.tx_packets + stats.rx_packets);
            fprintf(log_file, "---\n");
            
            fclose(log_file);
        }
        key = next_key;
    }
}

void usage(const char *prog)
{
    fprintf(stderr, "Usage: %s [-p <prefix>] [-t <interval>]\n", prog);
    fprintf(stderr, "  -p <prefix>     Log file prefix (default: %s)\n", DEFAULT_LOG_PREFIX);
    fprintf(stderr, "                  Log files will be named <prefix>-<username>.log\n");
    fprintf(stderr, "  -t <interval>   Statistics interval in seconds (default: %d)\n", STATS_INTERVAL);
    fprintf(stderr, "  -h              Display this help message\n");
    fprintf(stderr, "\nExample:\n");
    fprintf(stderr, "  sudo %s\n", prog);
    fprintf(stderr, "  sudo %s -p /var/log/network -t 5\n", prog);
}

int main(int argc, char **argv)
{
#ifdef USE_TC
    struct pdtt_kern_tc *skel;
#else
    struct pdtt_kern *skel;
#endif
    int map_fd;
    int err;
    int stats_interval = STATS_INTERVAL;
    int opt;
    
    log_prefix = DEFAULT_LOG_PREFIX;
    
    while ((opt = getopt(argc, argv, "p:t:h")) != -1) {
        switch (opt) {
        case 'p':
            log_prefix = optarg;
            break;
        case 't':
            stats_interval = atoi(optarg);
            if (stats_interval <= 0) {
                fprintf(stderr, "Invalid interval: %s\n", optarg);
                return 1;
            }
            break;
        case 'h':
        default:
            usage(argv[0]);
            return opt == 'h' ? 0 : 1;
        }
    }
    
    printf("Pawsey Data Transfer Tracker - Userspace Daemon\n");
    printf("Log file prefix: %s\n", log_prefix);
    printf("Stats interval: %d seconds\n", stats_interval);
    
    signal(SIGINT, sig_handler);
    signal(SIGTERM, sig_handler);
    
#ifdef USE_TC
    skel = pdtt_kern_tc__open();
#else
    skel = pdtt_kern__open();
#endif
    if (!skel) {
        fprintf(stderr, "Failed to open BPF skeleton\n");
        return 1;
    }
    
#ifdef USE_TC
    err = pdtt_kern_tc__load(skel);
#else
    err = pdtt_kern__load(skel);
#endif
    if (err) {
        fprintf(stderr, "Failed to load BPF program: %s\n", strerror(err));
#ifdef USE_TC
        pdtt_kern_tc__destroy(skel);
#else
        pdtt_kern__destroy(skel);
#endif
        return 1;
    }
    
#ifdef USE_TC
    // TC programs are attached via tc commands, not via libbpf attach
    // Just load the program to access the maps
    printf("Note: TC program should be loaded via 'make test-load' first\n");
    err = 0; // Skip attachment for TC
#else
    err = pdtt_kern__attach(skel);
    if (err) {
        fprintf(stderr, "Failed to attach BPF program: %s\n", strerror(err));
        pdtt_kern__destroy(skel);
        return 1;
    }
    
    // For cgroup socket filter, we need to attach to a cgroup
    // Try to attach to the current process cgroup
    int cgroup_fd = open("/sys/fs/cgroup", O_RDONLY);
    if (cgroup_fd < 0) {
        fprintf(stderr, "Failed to open cgroup directory: %s\n", strerror(errno));
        pdtt_kern__detach(skel);
        pdtt_kern__destroy(skel);
        return 1;
    }
    
    int prog_fd = bpf_program__fd(skel->progs.cgroup_skb_ingress);
    if (bpf_prog_attach(prog_fd, cgroup_fd, BPF_CGROUP_INET_INGRESS, BPF_F_ALLOW_MULTI) < 0) {
        fprintf(stderr, "Failed to attach BPF program to cgroup ingress: %s\n", strerror(errno));
        close(cgroup_fd);
        pdtt_kern__detach(skel);
        pdtt_kern__destroy(skel);
        return 1;
    }
    
    prog_fd = bpf_program__fd(skel->progs.cgroup_skb_egress);
    if (bpf_prog_attach(prog_fd, cgroup_fd, BPF_CGROUP_INET_EGRESS, BPF_F_ALLOW_MULTI) < 0) {
        fprintf(stderr, "Failed to attach BPF program to cgroup egress: %s\n", strerror(errno));
        close(cgroup_fd);
        pdtt_kern__detach(skel);
        pdtt_kern__destroy(skel);
        return 1;
    }
    
    printf("BPF cgroup socket filter attached (cgroup_fd=%d)\n", cgroup_fd);
    close(cgroup_fd);
#endif
    if (err) {
        fprintf(stderr, "Failed to attach BPF program: %s\n", strerror(err));
#ifdef USE_TC
        pdtt_kern_tc__destroy(skel);
#else
        pdtt_kern__destroy(skel);
#endif
        return 1;
    }
    
    map_fd = bpf_map__fd(skel->maps.user_stats_map);
    if (map_fd < 0) {
        fprintf(stderr, "Failed to get map file descriptor\n");
#ifdef USE_TC
        pdtt_kern_tc__destroy(skel);
#else
        pdtt_kern__detach(skel);
        pdtt_kern__destroy(skel);
#endif
        return 1;
    }
    
    printf("BPF program loaded and attached successfully\n");
    printf("Tracking network traffic per user...\n");
    
    while (running) {
        sleep(stats_interval);
        if (running) {
            log_user_stats(map_fd);
        }
    }
    
    printf("\nFinal statistics report:\n");
    log_user_stats(map_fd);
    
#ifdef USE_TC
    pdtt_kern_tc__destroy(skel);
#else
    pdtt_kern__detach(skel);
    pdtt_kern__destroy(skel);
#endif
    
    printf("Pdtt daemon stopped\n");
    return 0;
}
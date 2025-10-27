// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2025 Ugo Varetto <ugo.varetto@pawsey.org.au>

/**
 * @file pdtt_xdp_user.c
 * @brief Userspace control program for per-user network traffic
 *        tracker
 *
 * This program loads eBPF programs into the kernel, attaches them to
 * appropriate hook points, and periodically reads statistics from
 * eBPF maps to generate per-user log files.
 *
 * Features:
 * - Loads and manages multiple eBPF programs (XDP, cgroup, kprobes)
 * - Attaches cgroup programs to system cgroup hierarchy
 * - Periodically reads and logs per-user and per-connection stats
 * - Generates separate log files for each user
 * - Handles graceful shutdown with final statistics dump
 *
 * Usage:
 *   sudo ./pdtt_xdp_user -i <interface> [-p <prefix>] [-t <interval>]
 */

#include <arpa/inet.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <errno.h>
#include <fcntl.h>
#include <linux/types.h>
#include <net/if.h>
#include <pwd.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/resource.h>
#include <time.h>
#include <unistd.h>

#include "pdtt_xdp_kern.skel.h"

/**
 * @struct user_data_stats
 * @brief Per-user network statistics (matches kernel structure)
 */
struct user_data_stats {
  __u32 uid;          /** User ID */
  __u64 tx_bytes;     /** Total bytes transmitted */
  __u64 rx_bytes;     /** Total bytes received */
  __u64 tx_packets;   /** Total packets transmitted */
  __u64 rx_packets;   /** Total packets received */
  char username[16];  /** Username (cached) */
};

/**
 * @struct sock_key
 * @brief Connection identifier (matches kernel structure)
 */
struct sock_key {
  __u32 saddr;  /** Source IP address */
  __u32 daddr;  /** Destination IP address */
  __u16 sport;  /** Source port */
  __u16 dport;  /** Destination port */
};

/**
 * @struct conn_stats
 * @brief Per-connection statistics (matches kernel structure)
 */
struct conn_stats {
  __u32 uid;         /** User ID owning connection */
  __u32 saddr;       /** Source IP */
  __u32 daddr;       /** Destination IP */
  __u16 sport;       /** Source port */
  __u16 dport;       /** Destination port */
  __u64 tx_bytes;    /** Bytes transmitted */
  __u64 rx_bytes;    /** Bytes received */
  __u64 tx_packets;  /** Packets transmitted */
  __u64 rx_packets;  /** Packets received */
};

#define DEFAULT_LOG_PREFIX "/var/log/pdtt"
#define STATS_INTERVAL 10

static volatile bool running = true;
static char *log_prefix = NULL;

/**
 * @brief Signal handler for graceful shutdown
 *
 * Sets running flag to false when SIGINT or SIGTERM is received,
 * allowing main loop to exit cleanly and dump final statistics.
 *
 * @param sig Signal number (unused)
 */
void sig_handler(int sig __attribute__((unused))) { running = false; }

/**
 * @brief Resolve UID to username
 *
 * Looks up username from system password database using UID.
 *
 * @param uid User ID to resolve
 * @return Username string, or "unknown" if lookup fails
 *
 * Note: Returns pointer to static data in passwd structure. Should
 * not be freed by caller.
 */
const char *get_username(uid_t uid) {
  struct passwd *pw = getpwuid(uid);
  if (pw) {
    return pw->pw_name;
  }
  return "unknown";
}

/**
 * @brief Read and log per-user aggregate statistics
 *
 * Iterates through user_stats_map, reads statistics for each user,
 * and appends to per-user log files. Also prints summary to console.
 *
 * Processing flow:
 * 1. Iterate all entries in user_stats_map
 * 2. For each user, resolve UID to username
 * 3. Open/create log file: <prefix>-<username>.log
 * 4. Write timestamp and total bytes transferred
 * 5. Print summary to console
 *
 * @param map_fd File descriptor for user_stats_map
 *
 * Log file format:
 *   === Network Statistics Report [timestamp] ===
 *   UID: <uid> | Username: <username>
 *     Total: <bytes> bytes
 *   ---
 */
void log_user_stats(int map_fd) {
  __u32 key = 0, next_key;
  struct user_data_stats stats;
  FILE *log_file;
  time_t now;
  char timestamp[64];
  char user_log_path[512];

  time(&now);
  strftime(timestamp, sizeof(timestamp), "%Y-%m-%d %H:%M:%S",
           localtime(&now));

  /* Iterate all users in map */
  while (bpf_map_get_next_key(map_fd, &key, &next_key) == 0) {
    if (bpf_map_lookup_elem(map_fd, &next_key, &stats) == 0) {
      const char *username = get_username(stats.uid);
      __u64 total_bytes = stats.tx_bytes + stats.rx_bytes;

      /* Build per-user log file path */
      snprintf(user_log_path, sizeof(user_log_path), "%s-%s.log",
               log_prefix, username);

      /* Open log file in append mode */
      log_file = fopen(user_log_path, "a");
      if (!log_file) {
        fprintf(stderr, "Failed to open log file %s: %s\n",
                user_log_path, strerror(errno));
        key = next_key;
        continue;
      }

      /* Write statistics to log file */
      fprintf(log_file,
              "\n=== Network Statistics Report [%s] ===\n",
              timestamp);
      fprintf(log_file, "UID: %u | Username: %s\n", stats.uid,
              username);
      fprintf(log_file, "  Total: %llu bytes\n", total_bytes);
      fprintf(log_file, "---\n");

      fclose(log_file);

      /* Print to console (overwrite same line) */
      printf("\rUID: %u (%s) - Total: %llu bytes", stats.uid,
             username, total_bytes);
      fflush(stdout);
    }
    key = next_key;
  }
}

/**
 * @brief Read and log per-connection detailed statistics
 *
 * Iterates through conn_stats_map, reads statistics for each
 * connection, and appends detailed information to per-user log files.
 *
 * Processing flow:
 * 1. Iterate all entries in conn_stats_map
 * 2. For each connection, extract UID and resolve to username
 * 3. Convert IP addresses to dotted notation
 * 4. Convert port numbers from network to host byte order
 * 5. Open per-user log file
 * 6. Write connection details (source, dest, TX, RX)
 *
 * @param conn_map_fd File descriptor for conn_stats_map
 *
 * Log file format:
 *   === Per-Connection Statistics [timestamp] ===
 *   UID: <uid> | Username: <username>
 *     Source: <ip>:<port>
 *     Destination: <ip>:<port>
 *     TX: <bytes> bytes (<packets> packets)
 *     RX: <bytes> bytes (<packets> packets)
 *     Total: <bytes> bytes
 *   ---
 */
void log_connection_stats(int conn_map_fd) {
  struct sock_key key = {0}, next_key;
  struct conn_stats stats;
  FILE *log_file;
  time_t now;
  char timestamp[64];
  char saddr_str[INET_ADDRSTRLEN];
  char daddr_str[INET_ADDRSTRLEN];
  char user_log_path[512];

  time(&now);
  strftime(timestamp, sizeof(timestamp), "%Y-%m-%d %H:%M:%S",
           localtime(&now));

  /* Iterate all connections in map */
  while (bpf_map_get_next_key(conn_map_fd, &key, &next_key) == 0) {
    if (bpf_map_lookup_elem(conn_map_fd, &next_key, &stats) == 0) {
      const char *username = get_username(stats.uid);

      snprintf(user_log_path, sizeof(user_log_path), "%s-%s.log",
               log_prefix, username);

      log_file = fopen(user_log_path, "a");
      if (!log_file) {
        fprintf(stderr, "Failed to open log file %s: %s\n",
                user_log_path, strerror(errno));
        key = next_key;
        continue;
      }

      /* Convert IP addresses to dotted notation */
      inet_ntop(AF_INET, &stats.saddr, saddr_str, INET_ADDRSTRLEN);
      inet_ntop(AF_INET, &stats.daddr, daddr_str, INET_ADDRSTRLEN);

      /* Write detailed connection statistics */
      fprintf(log_file,
              "\n=== Per-Connection Statistics [%s] ===\n",
              timestamp);
      fprintf(log_file, "UID: %u | Username: %s\n", stats.uid,
              username);
      fprintf(log_file, "  Source: %s:%u\n", saddr_str,
              ntohs(stats.sport));
      fprintf(log_file, "  Destination: %s:%u\n", daddr_str,
              ntohs(stats.dport));
      fprintf(log_file, "  TX: %llu bytes (%llu packets)\n",
              stats.tx_bytes, stats.tx_packets);
      fprintf(log_file, "  RX: %llu bytes (%llu packets)\n",
              stats.rx_bytes, stats.rx_packets);
      fprintf(log_file, "  Total: %llu bytes\n",
              stats.tx_bytes + stats.rx_bytes);
      fprintf(log_file, "---\n");

      fclose(log_file);
    }
    key = next_key;
  }
}

/**
 * @brief Print usage information
 *
 * @param prog Program name (argv[0])
 */
void usage(const char *prog) {
  fprintf(stderr,
          "Usage: %s -i <interface> [-p <prefix>] [-t <interval>]\n",
          prog);
  fprintf(stderr,
          "  -i <interface>  Network interface to monitor "
          "(required)\n");
  fprintf(stderr,
          "  -p <prefix>     Log file prefix (default: %s)\n",
          DEFAULT_LOG_PREFIX);
  fprintf(stderr,
          "                  Log files will be named "
          "<prefix>-<username>.log\n");
  fprintf(stderr,
          "  -t <interval>   Statistics interval in seconds "
          "(default: %d)\n",
          STATS_INTERVAL);
  fprintf(stderr, "  -h              Display this help message\n");
  fprintf(stderr, "\nExample:\n");
  fprintf(stderr, "  sudo %s -i eth0\n", prog);
  fprintf(stderr, "  sudo %s -i wlan0 -p /var/log/network -t 5\n",
          prog);
}

/**
 * @brief Main program entry point
 *
 * Program flow:
 * 1. Parse command-line arguments
 * 2. Validate network interface exists
 * 3. Load BPF skeleton (compiled eBPF programs)
 * 4. Load eBPF programs into kernel
 * 5. Attach cgroup programs to system cgroup
 * 6. Get file descriptors for BPF maps
 * 7. Enter main loop:
 *    - Sleep for configured interval
 *    - Read and log statistics from maps
 * 8. On shutdown:
 *    - Dump final statistics
 *    - Detach all programs
 *    - Cleanup resources
 *
 * @param argc Argument count
 * @param argv Argument vector
 * @return 0 on success, 1 on error
 *
 * Note: Requires root privileges for BPF operations
 */
int main(int argc, char **argv) {
  struct pdtt_xdp_kern *skel;
  int map_fd, conn_map_fd;
  int err;
  char *ifname = NULL;
  int ifindex;
  int stats_interval = STATS_INTERVAL;
  int opt;
  int cgroup_fd = -1;

  log_prefix = DEFAULT_LOG_PREFIX;

  /* Parse command-line arguments */
  while ((opt = getopt(argc, argv, "i:p:t:h")) != -1) {
    switch (opt) {
    case 'i':
      ifname = optarg;
      break;
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

  /* Validate required arguments */
  if (!ifname) {
    fprintf(stderr, "Error: Network interface not specified\n\n");
    usage(argv[0]);
    return 1;
  }

  /* Convert interface name to index */
  ifindex = if_nametoindex(ifname);
  if (!ifindex) {
    fprintf(stderr, "Error: Invalid interface '%s': %s\n", ifname,
            strerror(errno));
    return 1;
  }

  /* Print configuration */
  printf("Pawsey Data Transfer Tracker\n");
  printf("Interface: %s (index: %d)\n", ifname, ifindex);
  printf("Log file prefix: %s\n", log_prefix);
  printf("Statistics interval: %d seconds\n", stats_interval);
  printf("\n");

  /* Install signal handlers for graceful shutdown */
  signal(SIGINT, sig_handler);
  signal(SIGTERM, sig_handler);

  /* Open BPF skeleton (loads program metadata) */
  skel = pdtt_xdp_kern__open();
  if (!skel) {
    fprintf(stderr, "Failed to open BPF skeleton\n");
    return 1;
  }

  /* Load BPF programs into kernel (includes verification) */
  err = pdtt_xdp_kern__load(skel);
  if (err) {
    fprintf(stderr, "Failed to load BPF program: %d\n", err);
    pdtt_xdp_kern__destroy(skel);
    return 1;
  }

  /*
   * Attach cgroup programs to system cgroup hierarchy
   * This enables tracking of all processes on the system
   */
  cgroup_fd = open("/sys/fs/cgroup", O_RDONLY);
  if (cgroup_fd < 0) {
    fprintf(stderr,
            "Warning: Failed to open cgroup directory: %s\n",
            strerror(errno));
  } else {
    /* Attach ingress (RX) program */
    int prog_fd = bpf_program__fd(skel->progs.cgroup_skb_ingress);
    if (bpf_prog_attach(prog_fd, cgroup_fd,
                        BPF_CGROUP_INET_INGRESS,
                        BPF_F_ALLOW_MULTI) < 0) {
      fprintf(stderr,
              "Warning: Failed to attach ingress program to "
              "cgroup: %s\n",
              strerror(errno));
    } else {
      printf("Attached cgroup ingress program\n");
    }

    /* Attach egress (TX) program */
    prog_fd = bpf_program__fd(skel->progs.cgroup_skb_egress);
    if (bpf_prog_attach(prog_fd, cgroup_fd,
                        BPF_CGROUP_INET_EGRESS,
                        BPF_F_ALLOW_MULTI) < 0) {
      fprintf(stderr,
              "Warning: Failed to attach egress program to "
              "cgroup: %s\n",
              strerror(errno));
    } else {
      printf("Attached cgroup egress program\n");
    }
  }

  /* Get file descriptors for BPF maps */
  map_fd = bpf_map__fd(skel->maps.user_stats_map);
  if (map_fd < 0) {
    fprintf(stderr, "Failed to get map file descriptor\n");
    if (cgroup_fd >= 0)
      close(cgroup_fd);
    pdtt_xdp_kern__destroy(skel);
    return 1;
  }

  conn_map_fd = bpf_map__fd(skel->maps.conn_stats_map);
  if (conn_map_fd < 0) {
    fprintf(stderr,
            "Failed to get connection stats map file descriptor\n");
    if (cgroup_fd >= 0)
      close(cgroup_fd);
    pdtt_xdp_kern__destroy(skel);
    return 1;
  }

  printf("BPF program loaded successfully\n");
  printf("Tracking per-user network traffic...\n\n");

  /*
   * Main statistics logging loop
   * Runs until SIGINT/SIGTERM received
   */
  while (running) {
    sleep(stats_interval);
    if (running) {
      log_user_stats(map_fd);
      log_connection_stats(conn_map_fd);
    }
  }

  /* Dump final statistics before exit */
  printf("\n\nFinal statistics report:\n");
  log_user_stats(map_fd);
  log_connection_stats(conn_map_fd);
  printf("\n");

  /* Cleanup: detach cgroup programs */
  if (cgroup_fd >= 0) {
    bpf_prog_detach2(bpf_program__fd(skel->progs.cgroup_skb_ingress),
                     cgroup_fd, BPF_CGROUP_INET_INGRESS);
    bpf_prog_detach2(bpf_program__fd(skel->progs.cgroup_skb_egress),
                     cgroup_fd, BPF_CGROUP_INET_EGRESS);
    close(cgroup_fd);
  }

  /* Cleanup: destroy skeleton (unloads programs, closes maps) */
  pdtt_xdp_kern__destroy(skel);

  printf("Tracker stopped\n");
  return 0;
}

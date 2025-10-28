// SPDX-License-Identifier: GPL-2.0
// Copyright (c) 2025 Ugo Varetto <ugo.varetto@pawsey.org.au>

/**
 * @file pdtt_xdp_kern.c
 * @brief eBPF kernel-space programs for per-user network traffic
 *        tracking
 *
 * This file contains multiple eBPF programs that work together to
 * track network traffic per user. It uses a multi-layered approach
 * with XDP, cgroup programs, sockops, and kprobes to ensure
 * comprehensive packet tracking at different stages of the network
 * stack.
 *
 * Architecture:
 * - XDP programs: Early packet processing at NIC driver level
 * - Cgroup programs: Socket-level tracking with UID context
 * - Sockops programs: Connection establishment tracking
 * - Kprobes: Kernel function instrumentation for TCP/UDP syscalls
 *
 * The programs share data through three eBPF maps:
 * - user_stats_map: Per-user aggregate statistics
 * - conn_uid_map: Maps network connections to user IDs
 * - conn_stats_map: Per-connection detailed statistics
 */

#include <linux/types.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/ptrace.h>
#include <linux/socket.h>
#include <linux/tcp.h>
#include <linux/udp.h>

#define XDP_ACT_PASS 2
#define MAX_USERS 1024

/**
 * @struct user_data_stats
 * @brief Per-user aggregate network traffic statistics
 *
 * Stores cumulative network statistics for a single user across all
 * their network connections.
 */
struct user_data_stats {
  __u32 uid;         /** User ID */
  __u64 tx_bytes;    /** Total bytes transmitted */
  __u64 rx_bytes;    /** Total bytes received */
  __u64 tx_packets;  /** Total packets transmitted */
  __u64 rx_packets;  /** Total packets received */
  __u32 pid;         /** Process ID (from last connection) */
  char username[16]; /** Username (cached for convenience) */
};

/**
 * @struct sock_key
 * @brief Network connection identifier (4-tuple)
 *
 * Uniquely identifies a network connection using source/destination
 * IP addresses and ports. All fields are in network byte order for
 * consistency.
 */
struct sock_key {
  __u32 saddr; /** Source IP address (network byte order) */
  __u32 daddr; /** Destination IP address (network byte order) */
  __u16 sport; /** Source port (network byte order) */
  __u16 dport; /** Destination port (network byte order) */
};

/**
 * @struct conn_stats
 * @brief Per-connection network statistics with user association
 *
 * Stores detailed statistics for individual network connections,
 * including which user owns the connection and the process name.
 */
struct conn_stats {
  __u32 uid;        /** User ID owning this connection */
  __u32 saddr;      /** Source IP address */
  __u32 daddr;      /** Destination IP address */
  __u16 sport;      /** Source port */
  __u16 dport;      /** Destination port */
  __u64 tx_bytes;   /** Bytes transmitted on this connection */
  __u64 rx_bytes;   /** Bytes received on this connection */
  __u64 tx_packets; /** Packets transmitted on this connection */
  __u64 rx_packets; /** Packets received on this connection */
  __u32 pid;        /** Process ID */
  char username[16]; /** Process name (cached for convenience) */
};

/**
 * @var user_stats_map
 * @brief BPF hash map storing per-user aggregate statistics
 *
 * Key: User ID (__u32)
 * Value: user_data_stats structure
 * Max entries: 1024 users
 *
 * This map accumulates all network traffic for each user across all
 * their connections.
 */
struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __uint(max_entries, MAX_USERS);
  __type(key, __u32);
  __type(value, struct user_data_stats);
} user_stats_map SEC(".maps");

/**
 * @var conn_uid_map
 * @brief BPF LRU hash map mapping connections to user IDs
 *
 * Key: sock_key (connection 4-tuple)
 * Value: User ID (__u32)
 * Max entries: 65536 connections
 *
 * This map is populated by sockops program when connections are
 * established, allowing other programs (like XDP) to associate
 * packets with users. Uses LRU eviction to handle connection churn.
 */
struct {
  __uint(type, BPF_MAP_TYPE_LRU_HASH);
  __uint(max_entries, 65536);
  __type(key, struct sock_key);
  __type(value, __u32);
} conn_uid_map SEC(".maps");

/**
 * @var conn_stats_map
 * @brief BPF LRU hash map storing per-connection statistics
 *
 * Key: sock_key (connection 4-tuple)
 * Value: conn_stats structure
 * Max entries: 65536 connections
 *
 * Tracks detailed statistics for each individual connection. Uses
 * LRU eviction to automatically remove old connections.
 */
struct {
  __uint(type, BPF_MAP_TYPE_LRU_HASH);
  __uint(max_entries, 65536);
  __type(key, struct sock_key);
  __type(value, struct conn_stats);
} conn_stats_map SEC(".maps");

/**
 * @brief XDP program for early packet processing and statistics
 *        tracking
 *
 * This program runs at the earliest point in the network stack,
 * immediately after the NIC driver receives a packet. It parses
 * packet headers to extract connection information and updates
 * statistics if the connection is already tracked.
 *
 * Processing flow:
 * 1. Validate packet bounds (required by eBPF verifier)
 * 2. Filter for IPv4 packets only
 * 3. Parse IP header
 * 4. Extract TCP/UDP port information if available
 * 5. Look up UID from conn_uid_map
 * 6. Update per-user and per-connection RX statistics
 * 7. Pass packet to network stack
 *
 * @param ctx XDP context containing packet data pointers
 * @return XDP_ACT_PASS to continue packet processing
 *
 * Note: This program can only track packets for connections already
 * established and recorded in conn_uid_map by sockops program.
 */
SEC("xdp")
int xdp_tracker_func(struct xdp_md *ctx) {
  void *data = (void *)(long)ctx->data;
  void *data_end = (void *)(long)ctx->data_end;
  struct ethhdr *eth = data;
  struct iphdr *iph;
  __u64 bytes;

  /* Verify Ethernet header is within packet bounds */
  if ((void *)(eth + 1) > data_end)
    return XDP_ACT_PASS;

  /* Only process IPv4 packets */
  if (eth->h_proto != bpf_htons(ETH_P_IP))
    return XDP_ACT_PASS;

  /* Parse IP header and verify bounds */
  iph = (struct iphdr *)(eth + 1);
  if ((void *)(iph + 1) > data_end)
    return XDP_ACT_PASS;

  /* Calculate total packet size */
  bytes = data_end - data;

  /* Debug logging (visible in /sys/kernel/debug/tracing/trace_pipe) */
  bpf_printk("XDP: saddr=%pI4 daddr=%pI4", &iph->saddr, &iph->daddr);

  /* Build connection key from IP addresses */
  struct sock_key key = {
      .saddr = iph->saddr,
      .daddr = iph->daddr,
      .sport = 0,
      .dport = 0,
  };

  /* Extract port numbers for TCP/UDP protocols */
  if (iph->protocol == IPPROTO_TCP) {
    struct tcphdr *tcph = (struct tcphdr *)(iph + 1);
    if ((void *)(tcph + 1) > data_end)
      return XDP_ACT_PASS;
    key.sport = tcph->source;
    key.dport = tcph->dest;
  } else if (iph->protocol == IPPROTO_UDP) {
    struct udphdr *udph = (struct udphdr *)(iph + 1);
    if ((void *)(udph + 1) > data_end)
      return XDP_ACT_PASS;
    key.sport = udph->source;
    key.dport = udph->dest;
  }

  /* Look up UID for this connection */
  __u32 *uid_ptr = bpf_map_lookup_elem(&conn_uid_map, &key);
  if (uid_ptr) {
    __u32 uid = *uid_ptr;

    /* Update per-user statistics atomically */
    struct user_data_stats *stats = bpf_map_lookup_elem(&user_stats_map, &uid);
    if (stats) {
      __sync_fetch_and_add(&stats->rx_bytes, bytes);
      __sync_fetch_and_add(&stats->rx_packets, 1);
    }

    /* Update per-connection statistics atomically */
    struct conn_stats *conn_stats = bpf_map_lookup_elem(&conn_stats_map, &key);
    if (conn_stats) {
      __sync_fetch_and_add(&conn_stats->rx_bytes, bytes);
      __sync_fetch_and_add(&conn_stats->rx_packets, 1);
    }
  }

  /* Always pass packet to network stack for normal processing */
  return XDP_ACT_PASS;
}

/**
 * @brief Sockops program for tracking socket connection establishment
 *
 * This program is called when sockets transition to established state
 * (both active and passive connections). It creates the mapping
 * between network connections and user IDs, which is used by other
 * programs.
 *
 * Processing flow:
 * 1. Extract UID of process creating/accepting connection
 * 2. Filter for IPv4 connections only (family == 2)
 * 3. Handle connection establishment events
 * 4. Build connection key from socket 4-tuple
 * 5. Store UID in conn_uid_map
 * 6. Initialize conn_stats_map entry
 * 7. Initialize user_stats_map entry if needed
 *
 * @param skops Socket operations context
 * @return 0 to continue socket operation
 *
 * Note: This is the only place where the UID→connection mapping is
 * created. Without this program, XDP and cgroup programs cannot
 * attribute packets to users.
 */
SEC("sockops")
int sockops_tracker(struct bpf_sock_ops *skops) {
  /* Extract UID from current process (lower 32 bits of uid_gid) */
  __u32 uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;

  /* Only track IPv4 connections (family 2 = AF_INET) */
  if (skops->family != 2)
    return 0;

  /* Handle connection establishment events */
  switch (skops->op) {
  case BPF_SOCK_OPS_ACTIVE_ESTABLISHED_CB:    /* Outgoing connection */
  case BPF_SOCK_OPS_PASSIVE_ESTABLISHED_CB: { /* Incoming connection */

    /* Build connection key from socket 4-tuple */
    struct sock_key key = {
        .saddr = skops->local_ip4,
        .daddr = skops->remote_ip4,
        .sport = skops->local_port,
        /* Remote port needs conversion: host order → network order */
        .dport = bpf_htonl(skops->remote_port) >> 16,
    };

    /* Debug logging */
    bpf_printk("SOCKOPS: local=%pI4:%d remote=%pI4:%d uid=%u",
               &skops->local_ip4, skops->local_port, &skops->remote_ip4,
               skops->remote_port, uid);

    /* Store UID for this connection (enables XDP tracking) */
    bpf_map_update_elem(&conn_uid_map, &key, &uid, BPF_ANY);

    /* Initialize per-connection statistics */
    struct conn_stats new_conn_stats = {
        .uid = uid,
        .saddr = key.saddr,
        .daddr = key.daddr,
        .sport = key.sport,
        .dport = key.dport,
        .tx_bytes = 0,
        .rx_bytes = 0,
        .tx_packets = 0,
        .rx_packets = 0,
        .pid = 0,
        .username = "",
    };
    /* Cache process ID and name for user-friendly display */
    new_conn_stats.pid = bpf_get_current_pid_tgid() >> 32;
    bpf_get_current_comm(&new_conn_stats.username, sizeof(new_conn_stats.username));
    bpf_map_update_elem(&conn_stats_map, &key, &new_conn_stats, BPF_ANY);

    /* Initialize per-user statistics if this is first connection */
    struct user_data_stats *stats = bpf_map_lookup_elem(&user_stats_map, &uid);
    if (!stats) {
      struct user_data_stats new_stats = {
          .uid = uid,
          .tx_bytes = 0,
          .rx_bytes = 0,
          .tx_packets = 0,
          .rx_packets = 0,
          .pid = 0,
          .username = "",
      };
      /* Cache process ID and name for user-friendly display */
      new_stats.pid = bpf_get_current_pid_tgid() >> 32;
      bpf_get_current_comm(&new_stats.username, sizeof(new_stats.username));
      bpf_map_update_elem(&user_stats_map, &uid, &new_stats, BPF_ANY);
    }
    break;
  }
  }

  return 0;
}

/**
 * @brief Cgroup program for tracking socket creation
 *
 * This program is called whenever a process creates a new socket.
 * It ensures that user_stats_map has an entry for every user who
 * creates sockets, even before any connections are established.
 *
 * @param sk Socket being created (unused in this implementation)
 * @return 1 to allow socket creation
 */
SEC("cgroup/sock_create")
int sock_create_tracker(struct bpf_sock *sk __attribute__((unused))) {
  __u32 uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;

  /* Initialize user stats entry if not exists */
  struct user_data_stats *stats = bpf_map_lookup_elem(&user_stats_map, &uid);
  if (!stats) {
    struct user_data_stats new_stats = {
        .uid = uid,
        .tx_bytes = 0,
        .rx_bytes = 0,
        .tx_packets = 0,
        .rx_packets = 0,
        .pid = 0,
        .username = "",
    };
    bpf_get_current_comm(&new_stats.username, sizeof(new_stats.username));
    bpf_map_update_elem(&user_stats_map, &uid, &new_stats, BPF_ANY);
  }

  return 1;
}

/**
 * @brief Cgroup SKB ingress program for tracking received packets
 *
 * This program is attached to cgroup and processes every incoming
 * packet at the socket level. It has access to socket context,
 * allowing it to determine the UID directly.
 *
 * Processing flow:
 * 1. Extract UID from socket context (two methods for reliability)
 * 2. Skip root and invalid UIDs
 * 3. Parse IP header to build connection key
 * 4. Note: source/dest are swapped because packet is incoming
 * 5. Update per-user statistics (create entry if needed)
 * 6. Update per-connection statistics (create entry if needed)
 *
 * @param skb Socket buffer context
 * @return 1 to accept packet
 *
 * Note: Connection key uses local address as saddr and remote
 * address as daddr (opposite of packet headers) to match the key
 * created by sockops program.
 */
SEC("cgroup_skb/ingress")
int cgroup_skb_ingress(struct __sk_buff *skb) {
  /* Try to get UID from socket cookie (upper 32 bits) */
  __u64 uid_gid = bpf_get_socket_cookie(skb);
  __u32 uid = (uid_gid >> 32) & 0xFFFFFFFF;

  /* Fallback to direct socket UID lookup */
  if (!uid)
    uid = bpf_get_socket_uid(skb);

  /* Skip root and invalid UIDs */
  if (uid == 0 || uid == 0xFFFFFFFF)
    return 1;

  __u64 bytes = skb->len;

  /* Parse IP header */
  void *data = (void *)(long)skb->data;
  void *data_end = (void *)(long)skb->data_end;
  struct iphdr *iph = data;

  if ((void *)(iph + 1) > data_end)
    return 1;

  /* Only handle IPv4 */
  if (iph->version != 4)
    return 1;

  /*
   * Build connection key with swapped addresses
   * (packet direction is remote→local, but we want local→remote key)
   */
  struct sock_key key = {
      .saddr = iph->daddr, /* Local (destination in packet) */
      .daddr = iph->saddr, /* Remote (source in packet) */
      .sport = 0,
      .dport = 0,
  };

  /* Extract ports (also swapped) */
  if (iph->protocol == IPPROTO_TCP) {
    struct tcphdr *tcph = (struct tcphdr *)(iph + 1);
    if ((void *)(tcph + 1) > data_end)
      return 1;
    key.sport = tcph->dest;   /* Local port */
    key.dport = tcph->source; /* Remote port */
  } else if (iph->protocol == IPPROTO_UDP) {
    struct udphdr *udph = (struct udphdr *)(iph + 1);
    if ((void *)(udph + 1) > data_end)
      return 1;
    key.sport = udph->dest;
    key.dport = udph->source;
  }

  /* Update or create per-user statistics */
  struct user_data_stats *stats = bpf_map_lookup_elem(&user_stats_map, &uid);
  if (!stats) {
    struct user_data_stats new_stats = {
        .uid = uid,
        .tx_bytes = 0,
        .rx_bytes = bytes,
        .tx_packets = 0,
        .rx_packets = 1,
        .pid = 0,
        .username = "",
    };
    bpf_get_current_comm(&new_stats.username, sizeof(new_stats.username));
    bpf_map_update_elem(&user_stats_map, &uid, &new_stats, BPF_ANY);
  } else {
    __sync_fetch_and_add(&stats->rx_bytes, bytes);
    __sync_fetch_and_add(&stats->rx_packets, 1);
  }

  /* Update or create per-connection statistics */
  struct conn_stats *conn_stats = bpf_map_lookup_elem(&conn_stats_map, &key);
  if (!conn_stats) {
    struct conn_stats new_conn_stats = {
        .uid = uid,
        .saddr = key.saddr,
        .daddr = key.daddr,
        .sport = key.sport,
        .dport = key.dport,
        .tx_bytes = 0,
        .rx_bytes = bytes,
        .tx_packets = 0,
        .rx_packets = 1,
        .pid = 0,
        .username = "",
    };
    bpf_map_update_elem(&conn_stats_map, &key, &new_conn_stats, BPF_ANY);
  } else {
    __sync_fetch_and_add(&conn_stats->rx_bytes, bytes);
    __sync_fetch_and_add(&conn_stats->rx_packets, 1);
  }

  return 1;
}

/**
 * @brief Cgroup SKB egress program for tracking transmitted packets
 *
 * This program is attached to cgroup and processes every outgoing
 * packet at the socket level. Similar to ingress program but handles
 * transmission direction.
 *
 * Processing flow:
 * 1. Extract UID from socket context
 * 2. Skip root and invalid UIDs
 * 3. Parse IP header to build connection key
 * 4. Note: source/dest match packet headers (not swapped like
 *    ingress)
 * 5. Update per-user TX statistics
 * 6. Update per-connection TX statistics
 *
 * @param skb Socket buffer context
 * @return 1 to allow packet transmission
 */
SEC("cgroup_skb/egress")
int cgroup_skb_egress(struct __sk_buff *skb) {
  __u64 uid_gid = bpf_get_socket_cookie(skb);
  __u32 uid = (uid_gid >> 32) & 0xFFFFFFFF;

  if (!uid)
    uid = bpf_get_socket_uid(skb);

  if (uid == 0 || uid == 0xFFFFFFFF)
    return 1;

  __u64 bytes = skb->len;

  void *data = (void *)(long)skb->data;
  void *data_end = (void *)(long)skb->data_end;
  struct iphdr *iph = data;

  if ((void *)(iph + 1) > data_end)
    return 1;

  if (iph->version != 4)
    return 1;

  /*
   * Build connection key from packet headers
   * (no swapping needed for egress)
   */
  struct sock_key key = {
      .saddr = iph->saddr, /* Local (source in packet) */
      .daddr = iph->daddr, /* Remote (destination in packet) */
      .sport = 0,
      .dport = 0,
  };

  if (iph->protocol == IPPROTO_TCP) {
    struct tcphdr *tcph = (struct tcphdr *)(iph + 1);
    if ((void *)(tcph + 1) > data_end)
      return 1;
    key.sport = tcph->source;
    key.dport = tcph->dest;
  } else if (iph->protocol == IPPROTO_UDP) {
    struct udphdr *udph = (struct udphdr *)(iph + 1);
    if ((void *)(udph + 1) > data_end)
      return 1;
    key.sport = udph->source;
    key.dport = udph->dest;
  }

  /* Update or create per-user statistics */
  struct user_data_stats *stats = bpf_map_lookup_elem(&user_stats_map, &uid);
  if (!stats) {
    struct user_data_stats new_stats = {
        .uid = uid,
        .tx_bytes = bytes,
        .rx_bytes = 0,
        .tx_packets = 1,
        .rx_packets = 0,
        .pid = 0,
        .username = "",
    };
    bpf_get_current_comm(&new_stats.username, sizeof(new_stats.username));
    bpf_map_update_elem(&user_stats_map, &uid, &new_stats, BPF_ANY);
  } else {
    __sync_fetch_and_add(&stats->tx_bytes, bytes);
    __sync_fetch_and_add(&stats->tx_packets, 1);
  }

  /* Update or create per-connection statistics */
  struct conn_stats *conn_stats = bpf_map_lookup_elem(&conn_stats_map, &key);
  if (!conn_stats) {
    struct conn_stats new_conn_stats = {
        .uid = uid,
        .saddr = key.saddr,
        .daddr = key.daddr,
        .sport = key.sport,
        .dport = key.dport,
        .tx_bytes = bytes,
        .rx_bytes = 0,
        .tx_packets = 1,
        .rx_packets = 0,
        .pid = 0,
        .username = "",
    };
    bpf_map_update_elem(&conn_stats_map, &key, &new_conn_stats, BPF_ANY);
  } else {
    __sync_fetch_and_add(&conn_stats->tx_bytes, bytes);
    __sync_fetch_and_add(&conn_stats->tx_packets, 1);
  }

  return 1;
}

/**
 * @brief Kprobe for tcp_sendmsg kernel function
 *
 * Instruments the tcp_sendmsg kernel function to track TCP data
 * transmission. This provides an additional tracking layer that
 * captures data at the syscall level.
 *
 * Function signature: int tcp_sendmsg(struct sock *sk,
 *                                      struct msghdr *msg, size_t size)
 *
 * @param ctx CPU register context (pt_regs)
 * @return 0 to continue function execution
 *
 * Note: Extracts size parameter (third argument) via PT_REGS_PARM3
 */
SEC("kprobe/tcp_sendmsg")
int kprobe_tcp_sendmsg(struct pt_regs *ctx) {
  __u32 uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
  __u64 size = PT_REGS_PARM3(ctx); /* Third parameter = size */

  /* Skip root and invalid UIDs */
  if (uid == 0 || uid == 0xFFFFFFFF)
    return 0;

  /* Update or create user statistics */
  struct user_data_stats *stats = bpf_map_lookup_elem(&user_stats_map, &uid);
  if (!stats) {
    struct user_data_stats new_stats = {
        .uid = uid,
        .tx_bytes = size,
        .rx_bytes = 0,
        .tx_packets = 1,
        .rx_packets = 0,
        .pid = 0,
        .username = "",
    };
    bpf_get_current_comm(&new_stats.username, sizeof(new_stats.username));
    bpf_map_update_elem(&user_stats_map, &uid, &new_stats, BPF_ANY);
  } else {
    __sync_fetch_and_add(&stats->tx_bytes, size);
    __sync_fetch_and_add(&stats->tx_packets, 1);
  }

  return 0;
}

/**
 * @brief Kprobe for tcp_cleanup_rbuf kernel function
 *
 * Instruments tcp_cleanup_rbuf which is called when TCP data is read
 * from the receive buffer. This indicates data has been delivered to
 * userspace.
 *
 * Function signature: void tcp_cleanup_rbuf(struct sock *sk,
 *                                            int copied)
 *
 * @param ctx CPU register context (pt_regs)
 * @return 0 to continue function execution
 *
 * Note: Extracts copied parameter (second argument) via
 * PT_REGS_PARM2
 */
SEC("kprobe/tcp_cleanup_rbuf")
int kprobe_tcp_cleanup_rbuf(struct pt_regs *ctx) {
  __u32 uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
  __u64 copied = PT_REGS_PARM2(ctx); /* Second parameter = copied */

  /* Skip invalid cases */
  if (uid == 0 || uid == 0xFFFFFFFF || copied <= 0)
    return 0;

  struct user_data_stats *stats = bpf_map_lookup_elem(&user_stats_map, &uid);
  if (!stats) {
    struct user_data_stats new_stats = {
        .uid = uid,
        .tx_bytes = 0,
        .rx_bytes = copied,
        .tx_packets = 0,
        .rx_packets = 1,
        .pid = 0,
        .username = "",
    };
    bpf_get_current_comm(&new_stats.username, sizeof(new_stats.username));
    bpf_map_update_elem(&user_stats_map, &uid, &new_stats, BPF_ANY);
  } else {
    __sync_fetch_and_add(&stats->rx_bytes, copied);
    __sync_fetch_and_add(&stats->rx_packets, 1);
  }

  return 0;
}

/**
 * @brief Kprobe for udp_sendmsg kernel function
 *
 * Instruments the udp_sendmsg kernel function to track UDP data
 * transmission.
 *
 * Function signature: int udp_sendmsg(struct sock *sk,
 *                                      struct msghdr *msg, size_t len)
 *
 * @param ctx CPU register context (pt_regs)
 * @return 0 to continue function execution
 */
SEC("kprobe/udp_sendmsg")
int kprobe_udp_sendmsg(struct pt_regs *ctx) {
  __u32 uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
  __u64 len = PT_REGS_PARM3(ctx);

  if (uid == 0 || uid == 0xFFFFFFFF)
    return 0;

  struct user_data_stats *stats = bpf_map_lookup_elem(&user_stats_map, &uid);
  if (!stats) {
    struct user_data_stats new_stats = {
        .uid = uid,
        .tx_bytes = len,
        .rx_bytes = 0,
        .tx_packets = 1,
        .rx_packets = 0,
        .pid = 0,
        .username = "",
    };
    bpf_get_current_comm(&new_stats.username, sizeof(new_stats.username));
    bpf_map_update_elem(&user_stats_map, &uid, &new_stats, BPF_ANY);
  } else {
    __sync_fetch_and_add(&stats->tx_bytes, len);
    __sync_fetch_and_add(&stats->tx_packets, 1);
  }

  return 0;
}

/**
 * @brief Kprobe for udp_recvmsg kernel function
 *
 * Instruments the udp_recvmsg kernel function to track UDP data
 * reception.
 *
 * Function signature: int udp_recvmsg(struct sock *sk,
 *                                      struct msghdr *msg, size_t len, ...)
 *
 * @param ctx CPU register context (pt_regs)
 * @return 0 to continue function execution
 */
SEC("kprobe/udp_recvmsg")
int kprobe_udp_recvmsg(struct pt_regs *ctx) {
  __u32 uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
  __u64 len = PT_REGS_PARM3(ctx);

  if (uid == 0 || uid == 0xFFFFFFFF)
    return 0;

  struct user_data_stats *stats = bpf_map_lookup_elem(&user_stats_map, &uid);
  if (!stats) {
    struct user_data_stats new_stats = {
        .uid = uid,
        .tx_bytes = 0,
        .rx_bytes = len,
        .tx_packets = 0,
        .rx_packets = 1,
        .pid = 0,
        .username = "",
    };
    bpf_get_current_comm(&new_stats.username, sizeof(new_stats.username));
    bpf_map_update_elem(&user_stats_map, &uid, &new_stats, BPF_ANY);
  } else {
    __sync_fetch_and_add(&stats->rx_bytes, len);
    __sync_fetch_and_add(&stats->rx_packets, 1);
  }

  return 0;
}

/* License declaration required by eBPF verifier */
char _license[] SEC("license") = "GPL";

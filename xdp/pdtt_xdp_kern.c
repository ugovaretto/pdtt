// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2025 Ugo Varetto <ugo.varetto@pawsey.org.au>

#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/in.h>
#include <linux/socket.h>
#include <linux/ptrace.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_tracing.h>
#include <linux/types.h>

#define XDP_ACT_PASS 2
#define MAX_USERS 1024

struct user_data_stats {
    __u32 uid;
    __u64 tx_bytes;
    __u64 rx_bytes;
    __u64 tx_packets;
    __u64 rx_packets;
    char username[16];
};

struct sock_key {
    __u32 saddr;
    __u32 daddr;
    __u16 sport;
    __u16 dport;
};

struct conn_stats {
    __u32 uid;
    __u32 saddr;
    __u32 daddr;
    __u16 sport;
    __u16 dport;
    __u64 tx_bytes;
    __u64 rx_bytes;
    __u64 tx_packets;
    __u64 rx_packets;
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, MAX_USERS);
    __type(key, __u32);
    __type(value, struct user_data_stats);
} user_stats_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 65536);
    __type(key, struct sock_key);
    __type(value, __u32);
} conn_uid_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 65536);
    __type(key, struct sock_key);
    __type(value, struct conn_stats);
} conn_stats_map SEC(".maps");

SEC("xdp")
int xdp_tracker_func(struct xdp_md *ctx)
{
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;
    struct ethhdr *eth = data;
    struct iphdr *iph;
    __u64 bytes;
    
    if ((void *)(eth + 1) > data_end)
        return XDP_ACT_PASS;
    
    if (eth->h_proto != bpf_htons(ETH_P_IP))
        return XDP_ACT_PASS;
    
    iph = (struct iphdr *)(eth + 1);
    if ((void *)(iph + 1) > data_end)
        return XDP_ACT_PASS;
    
    bytes = data_end - data;
    
    bpf_printk("XDP: saddr=%pI4 daddr=%pI4", &iph->saddr, &iph->daddr);
    
    struct sock_key key = {
        .saddr = iph->saddr,
        .daddr = iph->daddr,
        .sport = 0,
        .dport = 0,
    };
    
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
    
    __u32 *uid_ptr = bpf_map_lookup_elem(&conn_uid_map, &key);
    if (uid_ptr) {
        __u32 uid = *uid_ptr;
        struct user_data_stats *stats = bpf_map_lookup_elem(&user_stats_map, &uid);
        if (stats) {
            __sync_fetch_and_add(&stats->rx_bytes, bytes);
            __sync_fetch_and_add(&stats->rx_packets, 1);
        }
        
        struct conn_stats *conn_stats = bpf_map_lookup_elem(&conn_stats_map, &key);
        if (conn_stats) {
            __sync_fetch_and_add(&conn_stats->rx_bytes, bytes);
            __sync_fetch_and_add(&conn_stats->rx_packets, 1);
        }
    }
    
    return XDP_ACT_PASS;
}

SEC("sockops")
int sockops_tracker(struct bpf_sock_ops *skops)
{
    __u32 uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
    
    if (skops->family != 2)
        return 0;
    
    switch (skops->op) {
    case BPF_SOCK_OPS_ACTIVE_ESTABLISHED_CB:
    case BPF_SOCK_OPS_PASSIVE_ESTABLISHED_CB:
    {
        struct sock_key key = {
            .saddr = skops->local_ip4,
            .daddr = skops->remote_ip4,
            .sport = skops->local_port,
            .dport = bpf_htonl(skops->remote_port) >> 16,
        };
        
        bpf_printk("SOCKOPS: local=%pI4:%d remote=%pI4:%d uid=%u", 
                   &skops->local_ip4, skops->local_port, 
                   &skops->remote_ip4, skops->remote_port, uid);
        
        bpf_map_update_elem(&conn_uid_map, &key, &uid, BPF_ANY);
        
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
        };
        bpf_map_update_elem(&conn_stats_map, &key, &new_conn_stats, BPF_ANY);
        
        struct user_data_stats *stats = bpf_map_lookup_elem(&user_stats_map, &uid);
        if (!stats) {
            struct user_data_stats new_stats = {
                .uid = uid,
                .tx_bytes = 0,
                .rx_bytes = 0,
                .tx_packets = 0,
                .rx_packets = 0,
            };
            bpf_get_current_comm(&new_stats.username, sizeof(new_stats.username));
            bpf_map_update_elem(&user_stats_map, &uid, &new_stats, BPF_ANY);
        }
        break;
    }
    }
    
    return 0;
}

SEC("cgroup/sock_create")
int sock_create_tracker(struct bpf_sock *sk __attribute__((unused)))
{
    __u32 uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
    
    struct user_data_stats *stats = bpf_map_lookup_elem(&user_stats_map, &uid);
    if (!stats) {
        struct user_data_stats new_stats = {
            .uid = uid,
            .tx_bytes = 0,
            .rx_bytes = 0,
            .tx_packets = 0,
            .rx_packets = 0,
        };
        bpf_get_current_comm(&new_stats.username, sizeof(new_stats.username));
        bpf_map_update_elem(&user_stats_map, &uid, &new_stats, BPF_ANY);
    }
    
    return 1;
}

SEC("cgroup_skb/ingress")
int cgroup_skb_ingress(struct __sk_buff *skb)
{
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
    
    struct sock_key key = {
        .saddr = iph->daddr,
        .daddr = iph->saddr,
        .sport = 0,
        .dport = 0,
    };
    
    if (iph->protocol == IPPROTO_TCP) {
        struct tcphdr *tcph = (struct tcphdr *)(iph + 1);
        if ((void *)(tcph + 1) > data_end)
            return 1;
        key.sport = tcph->dest;
        key.dport = tcph->source;
    } else if (iph->protocol == IPPROTO_UDP) {
        struct udphdr *udph = (struct udphdr *)(iph + 1);
        if ((void *)(udph + 1) > data_end)
            return 1;
        key.sport = udph->dest;
        key.dport = udph->source;
    }
    
    struct user_data_stats *stats = bpf_map_lookup_elem(&user_stats_map, &uid);
    if (!stats) {
        struct user_data_stats new_stats = {
            .uid = uid,
            .tx_bytes = 0,
            .rx_bytes = bytes,
            .tx_packets = 0,
            .rx_packets = 1,
        };
        bpf_get_current_comm(&new_stats.username, sizeof(new_stats.username));
        bpf_map_update_elem(&user_stats_map, &uid, &new_stats, BPF_ANY);
    } else {
        __sync_fetch_and_add(&stats->rx_bytes, bytes);
        __sync_fetch_and_add(&stats->rx_packets, 1);
    }
    
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
        };
        bpf_map_update_elem(&conn_stats_map, &key, &new_conn_stats, BPF_ANY);
    } else {
        __sync_fetch_and_add(&conn_stats->rx_bytes, bytes);
        __sync_fetch_and_add(&conn_stats->rx_packets, 1);
    }
    
    return 1;
}

SEC("cgroup_skb/egress")
int cgroup_skb_egress(struct __sk_buff *skb)
{
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
    
    struct sock_key key = {
        .saddr = iph->saddr,
        .daddr = iph->daddr,
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
    
    struct user_data_stats *stats = bpf_map_lookup_elem(&user_stats_map, &uid);
    if (!stats) {
        struct user_data_stats new_stats = {
            .uid = uid,
            .tx_bytes = bytes,
            .rx_bytes = 0,
            .tx_packets = 1,
            .rx_packets = 0,
        };
        bpf_get_current_comm(&new_stats.username, sizeof(new_stats.username));
        bpf_map_update_elem(&user_stats_map, &uid, &new_stats, BPF_ANY);
    } else {
        __sync_fetch_and_add(&stats->tx_bytes, bytes);
        __sync_fetch_and_add(&stats->tx_packets, 1);
    }
    
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
        };
        bpf_map_update_elem(&conn_stats_map, &key, &new_conn_stats, BPF_ANY);
    } else {
        __sync_fetch_and_add(&conn_stats->tx_bytes, bytes);
        __sync_fetch_and_add(&conn_stats->tx_packets, 1);
    }
    
    return 1;
}

SEC("kprobe/tcp_sendmsg")
int kprobe_tcp_sendmsg(struct pt_regs *ctx)
{
        __u32 uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
        __u64 size = PT_REGS_PARM3(ctx);
        
        if (uid == 0 || uid == 0xFFFFFFFF)
                return 0;
        
        struct user_data_stats *stats = bpf_map_lookup_elem(&user_stats_map, &uid);
        if (!stats) {
                struct user_data_stats new_stats = {
                        .uid = uid,
                        .tx_bytes = size,
                        .rx_bytes = 0,
                        .tx_packets = 1,
                        .rx_packets = 0,
                };
                bpf_get_current_comm(&new_stats.username, sizeof(new_stats.username));
                bpf_map_update_elem(&user_stats_map, &uid, &new_stats, BPF_ANY);
        } else {
                __sync_fetch_and_add(&stats->tx_bytes, size);
                __sync_fetch_and_add(&stats->tx_packets, 1);
        }
        
        return 0;
}

SEC("kprobe/tcp_cleanup_rbuf")
int kprobe_tcp_cleanup_rbuf(struct pt_regs *ctx)
{
        __u32 uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
        __u64 copied = PT_REGS_PARM2(ctx);
        
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
                };
                bpf_get_current_comm(&new_stats.username, sizeof(new_stats.username));
                bpf_map_update_elem(&user_stats_map, &uid, &new_stats, BPF_ANY);
        } else {
                __sync_fetch_and_add(&stats->rx_bytes, copied);
                __sync_fetch_and_add(&stats->rx_packets, 1);
        }
        
        return 0;
}

SEC("kprobe/udp_sendmsg")
int kprobe_udp_sendmsg(struct pt_regs *ctx)
{
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
                };
                bpf_get_current_comm(&new_stats.username, sizeof(new_stats.username));
                bpf_map_update_elem(&user_stats_map, &uid, &new_stats, BPF_ANY);
        } else {
                __sync_fetch_and_add(&stats->tx_bytes, len);
                __sync_fetch_and_add(&stats->tx_packets, 1);
        }
        
        return 0;
}

SEC("kprobe/udp_recvmsg")
int kprobe_udp_recvmsg(struct pt_regs *ctx)
{
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
                };
                bpf_get_current_comm(&new_stats.username, sizeof(new_stats.username));
                bpf_map_update_elem(&user_stats_map, &uid, &new_stats, BPF_ANY);
        } else {
                __sync_fetch_and_add(&stats->rx_bytes, len);
                __sync_fetch_and_add(&stats->rx_packets, 1);
        }
        
        return 0;
}

char _license[] SEC("license") = "GPL";

#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/socket.h>
#include <linux/in.h>
#include <stdbool.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <linux/types.h>

#define MAX_USERS 1024
#define MAX_FILENAME_LEN 256

struct user_data_stats {
    __u32 uid;
    __u64 tx_bytes;
    __u64 rx_bytes;
    __u64 tx_packets;
    __u64 rx_packets;
    char username[16];
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, MAX_USERS);
    __type(key, __u32);
    __type(value, struct user_data_stats);
} user_stats_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    __type(key, __u32);
    __type(value, __u32);
} events SEC(".maps");

static __always_inline void update_user_stats(struct __sk_buff *skb, __u32 uid, bool is_tx)
{
    struct user_data_stats *stats;
    struct user_data_stats new_stats = {};
    __u64 bytes = skb->len;
    
    stats = bpf_map_lookup_elem(&user_stats_map, &uid);
    if (!stats) {
        new_stats.uid = uid;
        new_stats.tx_bytes = is_tx ? bytes : 0;
        new_stats.rx_bytes = is_tx ? 0 : bytes;
        new_stats.tx_packets = is_tx ? 1 : 0;
        new_stats.rx_packets = is_tx ? 0 : 1;
        bpf_get_current_comm(&new_stats.username, sizeof(new_stats.username));
        bpf_map_update_elem(&user_stats_map, &uid, &new_stats, BPF_ANY);
    } else {
        if (is_tx) {
            __sync_fetch_and_add(&stats->tx_bytes, bytes);
            __sync_fetch_and_add(&stats->tx_packets, 1);
        } else {
            __sync_fetch_and_add(&stats->rx_bytes, bytes);
            __sync_fetch_and_add(&stats->rx_packets, 1);
        }
    }
}

SEC("socket")
int socket_filter(struct __sk_buff *skb)
{
    __u32 uid = bpf_get_socket_uid(skb);
    
    if (uid == 0xFFFFFFFF) {
        return 0;
    }
    
    bool is_tx = (skb->mark & 0x1000000) ? false : true;
    
    update_user_stats(skb, uid, is_tx);
    
    return 0;
}

char _license[] SEC("license") = "GPL";
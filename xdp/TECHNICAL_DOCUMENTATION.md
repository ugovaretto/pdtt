# Pawsey Data Traffic Tracker (pdtt)

## Table of Contents

1. [Overview](#overview)
2. [eBPF Fundamentals](#ebpf-fundamentals)
3. [XDP (eXpress Data Path)](#xdp-express-data-path)
4. [Kprobes](#kprobes)
5. [PDTT Architecture](#pdtt-architecture)
6. [Implementation Details](#implementation-details)
7. [Data Structures](#data-structures)
8. [Program Flow](#program-flow)
9. [Security and Performance](#security-and-performance-considerations)

## Overview

The Pawsey Data Transfer Tracker (PDTT) is an eBPF-based network
monitoring tool that tracks network traffic per user in real-time. It
uses multiple eBPF program types (XDP, cgroup programs, kprobes, and
sockops) to intercept network packets at different stages of the
networking stack and associate them with user IDs.

## eBPF Fundamentals

### What is eBPF?

eBPF (extended Berkeley Packet Filter) is a revolutionary technology
in the Linux kernel that allows running sandboxed programs in kernel
space without changing kernel source code or loading kernel modules.
Originally designed for packet filtering, eBPF has evolved into a
general-purpose execution engine for safe, efficient kernel
programming.

### Key Characteristics

1. **Safety**: eBPF programs are verified by the kernel verifier
   before execution to ensure they:
   - Terminate (no infinite loops)
   - Don't access invalid memory
   - Don't crash the kernel
   - Have bounded complexity

2. **Performance**: eBPF programs are JIT (Just-In-Time) compiled to
   native machine code for optimal performance.

3. **Event-Driven**: eBPF programs are triggered by kernel events
   (packet arrival, system calls, function calls, etc.).

4. **Maps for Data Storage**: eBPF uses maps as the primary data
   structure for:
   - Storing state between program invocations
   - Communicating between kernel and userspace
   - Sharing data between different eBPF programs

### eBPF Program Types

eBPF supports multiple program types, each designed for specific
kernel hooks:

- **XDP (eXpress Data Path)**: Processes packets at the earliest
  point in the network stack
- **Socket programs**: Filter and monitor socket operations
- **Kprobes/Kretprobes**: Dynamically instrument kernel functions
- **Tracepoints**: Static instrumentation points in the kernel
- **Cgroup programs**: Control and monitor cgroup operations

### eBPF Maps

Maps are key-value data structures shared between eBPF programs and
userspace. Types include:

- **BPF_MAP_TYPE_HASH**: Standard hash table
- **BPF_MAP_TYPE_ARRAY**: Array indexed by integers
- **BPF_MAP_TYPE_LRU_HASH**: Hash table with automatic Least
  Recently Used eviction
- **BPF_MAP_TYPE_PERF_EVENT_ARRAY**: High-performance event
  streaming

### eBPF Workflow

1. **Write**: Create eBPF program in C with special annotations
2. **Compile**: Use clang to compile to eBPF bytecode
3. **Load**: Load bytecode into kernel using bpf() syscall
4. **Verify**: Kernel verifier checks program safety
5. **Attach**: Attach program to specific hook points
6. **Execute**: Program runs on events, stores data in maps
7. **Read**: Userspace reads data from maps

## XDP (eXpress Data Path)

### What is XDP?

XDP is an eBPF-based high-performance packet processing framework
that runs at the earliest possible point in the network stack - right
after the NIC driver receives a packet, before any kernel networking
code (skb allocation, protocol parsing, etc.).

### XDP Architecture

```
┌─────────────────────┐
│   Network Card      │
└──────────┬──────────┘
           │ DMA
           ▼
┌─────────────────────┐
│   NIC Driver        │
└──────────┬──────────┘
           │
           ▼
┌─────────────────────┐
│   XDP Program       │ ◄── Earliest intercept point
│   (eBPF)            │
└──────────┬──────────┘
           │
           ▼
   ┌───────┴───────┐
   │               │
   ▼               ▼
XDP_PASS        XDP_DROP
   │               │
   ▼               X
┌─────────────────────┐
│  Network Stack      │
│  (skb allocation,   │
│   IP processing)    │
└─────────────────────┘
```

### XDP Actions

XDP programs must return one of these actions:

- **XDP_PASS (2)**: Pass packet to normal network stack
- **XDP_DROP**: Drop packet immediately (DDoS mitigation)
- **XDP_TX**: Transmit packet back out same interface
- **XDP_REDIRECT**: Redirect to another interface
- **XDP_ABORTED**: Error condition, drop packet

### XDP Operating Modes

1. **Native/Driver Mode**: XDP runs in NIC driver (fastest, requires
   driver support)
2. **Offloaded Mode**: XDP runs on NIC hardware (requires SmartNIC)
3. **Generic Mode**: XDP runs in kernel network stack (slower, but
   works everywhere)

### XDP Context

XDP programs receive a `struct xdp_md` context:

```c
struct xdp_md {
    __u32 data;          // Pointer to packet data start
    __u32 data_end;      // Pointer to packet data end
    __u32 data_meta;     // Pointer to metadata area
    __u32 ingress_ifindex; // Interface index
    __u32 rx_queue_index;  // RX queue index
};
```

### XDP Performance Benefits

- **Zero-copy**: Direct packet access without allocation
- **Early drop**: Drop malicious packets before expensive processing
- **Bypass overhead**: Skip socket buffer (skb) allocation and
  initialization
- **CPU efficiency**: Process millions of packets per second per
  core

## Kprobes

### What are Kprobes?

Kprobes (Kernel Probes) are a dynamic instrumentation mechanism that
allows inserting breakpoints at almost any kernel instruction. When
combined with eBPF, kprobes enable powerful runtime kernel function
tracing without modifying kernel code.

### Kprobe Types

1. **kprobe**: Fires before the probed function executes
   - Access function arguments via `PT_REGS_PARM*` macros
   - Cannot see return value

2. **kretprobe**: Fires when probed function returns
   - Access return value
   - Cannot access original arguments (unless saved)

### How Kprobes Work

```
┌──────────────────────────────────┐
│   Original Kernel Function       │
│                                  │
│   int tcp_sendmsg(...) {         │
│   ◄─── kprobe inserts breakpoint │
│       // function body           │
│       ...                        │
│       return ret;                │
│   ◄─── kretprobe                │
│   }                              │
└──────────────────────────────────┘
          │
          ▼
┌──────────────────────────────────┐
│   eBPF Kprobe Handler            │
│                                  │
│   - Extract arguments            │
│   - Get current UID              │
│   - Update statistics maps       │
│   - Return 0 (continue)          │
└──────────────────────────────────┘
```

### PT_REGS Macros

eBPF kprobes access function arguments through CPU registers:

```c
PT_REGS_PARM1(ctx)  // First argument
PT_REGS_PARM2(ctx)  // Second argument
PT_REGS_PARM3(ctx)  // Third argument
// ... up to PARM5
PT_REGS_RC(ctx)     // Return value (kretprobe)
```

### Kprobe Limitations

1. **Unstable ABI**: Kernel functions can change between versions
2. **Performance overhead**: Every function call triggers eBPF
   execution
3. **Verifier restrictions**: Limited stack size, loop bounds
4. **Safety checks**: Cannot crash probed function

## PDTT Architecture

### Multi-Layer Tracking Strategy

PDTT uses a defense-in-depth approach with multiple eBPF program
types to ensure comprehensive packet tracking:

```
┌─────────────────────────────────────────────────────────┐
│                    User Space                           │
│  ┌──────────────────────────────────────────────────┐  │
│  │  pdtt_xdp_user.c                                 │  │
│  │  - Loads eBPF programs                           │  │
│  │  - Reads statistics from maps                    │  │
│  │  - Generates per-user log files                  │  │
│  └────────────┬─────────────────────────────────────┘  │
└───────────────┼─────────────────────────────────────────┘
                │ bpf() syscalls, map operations
═══════════════════════════════════════════════════════════
                │
┌───────────────┼─────────────────────────────────────────┐
│               ▼          Kernel Space                   │
│  ┌─────────────────────────────────────────────────┐   │
│  │              eBPF Maps                          │   │
│  │  ┌──────────────┐  ┌──────────────────────┐    │   │
│  │  │user_stats_map│  │  conn_uid_map        │    │   │
│  │  │(per-user)    │  │  (socket→uid)        │    │   │
│  │  └──────────────┘  └──────────────────────┘    │   │
│  │  ┌──────────────────────────────────────┐      │   │
│  │  │       conn_stats_map                 │      │   │
│  │  │       (per-connection)               │      │   │
│  │  └──────────────────────────────────────┘      │   │
│  └─────────────────────────────────────────────────┘   │
│         ▲           ▲           ▲           ▲           │
│         │           │           │           │           │
│  ┌──────┴──┐  ┌────┴────┐ ┌────┴────┐ ┌────┴─────┐    │
│  │  XDP    │  │ cgroup  │ │ sockops │ │ kprobes  │    │
│  │ (early) │  │(ingress)│ │(connect)│ │(syscalls)│    │
│  │         │  │(egress) │ │         │ │          │    │
│  └────┬────┘  └────┬────┘ └────┬────┘ └────┬─────┘    │
│       │            │           │           │            │
│       ▼            ▼           ▼           ▼            │
│  ┌─────────────────────────────────────────────────┐   │
│  │          Network Stack / TCP/IP Layer           │   │
│  └─────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────┘
```

### Why Multiple Program Types?

Each eBPF program type captures traffic at different layers:

1. **XDP Programs**: Capture packets at NIC level (ingress only,
   early)
   - Pros: Fastest, sees all packets first
   - Cons: No socket/process context, ingress only

2. **Cgroup Programs**: Capture packets at socket level (both
   directions)
   - Pros: Has UID context, sees both ingress/egress
   - Cons: May miss some edge cases

3. **Sockops Programs**: Track socket connection establishment
   - Pros: Maps connections to UIDs
   - Cons: Only connection events, not data transfer

4. **Kprobes**: Instrument kernel network functions
   - Pros: Reliable UID association, protocol-specific
   - Cons: Performance overhead, kernel version dependent

By combining all approaches, PDTT ensures no traffic is missed.

## Implementation Details

### Kernel Space (pdtt_xdp_kern.c)

#### Map Definitions

```c
// Per-user aggregate statistics
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, MAX_USERS);  // 1024 users
    __type(key, __u32);               // UID
    __type(value, struct user_data_stats);
} user_stats_map SEC(".maps");

// Connection to UID mapping
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);  // Auto-eviction
    __uint(max_entries, 65536);            // 64K connections
    __type(key, struct sock_key);          // 4-tuple
    __type(value, __u32);                  // UID
} conn_uid_map SEC(".maps");

// Per-connection statistics
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 65536);
    __type(key, struct sock_key);
    __type(value, struct conn_stats);
} conn_stats_map SEC(".maps");
```

**Design Rationale**:

- `user_stats_map`: Regular hash table since user count is bounded
- `conn_uid_map` and `conn_stats_map`: LRU hash tables to
  automatically evict old connections
- Large max_entries for connection maps to handle high connection
  counts

#### XDP Program (xdp_tracker_func)

```c
SEC("xdp")
int xdp_tracker_func(struct xdp_md *ctx)
```

**Execution Flow**:

1. **Packet Bounds Checking**:

   ```c
   void *data = (void *)(long)ctx->data;
   void *data_end = (void *)(long)ctx->data_end;
   struct ethhdr *eth = data;
   
   if ((void *)(eth + 1) > data_end)
       return XDP_ACT_PASS;  // Invalid packet
   ```

   - eBPF verifier requires bounds checking before memory access
   - Prevents buffer overflow attacks

2. **Protocol Filtering**:

   ```c
   if (eth->h_proto != bpf_htons(ETH_P_IP))
       return XDP_ACT_PASS;  // Only process IPv4
   ```

   - XDP processes raw Ethernet frames
   - Filter for IPv4 packets only

3. **IP Header Parsing**:

   ```c
   struct iphdr *iph = (struct iphdr *)(eth + 1);
   if ((void *)(iph + 1) > data_end)
       return XDP_ACT_PASS;
   ```

4. **TCP/UDP Port Extraction**:

   ```c
   if (iph->protocol == IPPROTO_TCP) {
       struct tcphdr *tcph = (struct tcphdr *)(iph + 1);
       if ((void *)(tcph + 1) > data_end)
           return XDP_ACT_PASS;
       key.sport = tcph->source;
       key.dport = tcph->dest;
   }
   ```

   - Extract layer 4 information for connection tracking

5. **UID Lookup and Statistics Update**:

   ```c
   __u32 *uid_ptr = bpf_map_lookup_elem(&conn_uid_map, &key);
   if (uid_ptr) {
       __u32 uid = *uid_ptr;
       struct user_data_stats *stats =
           bpf_map_lookup_elem(&user_stats_map, &uid);
       if (stats) {
           __sync_fetch_and_add(&stats->rx_bytes, bytes);
           __sync_fetch_and_add(&stats->rx_packets, 1);
       }
   }
   ```

   - Atomic operations prevent race conditions
   - `__sync_fetch_and_add` ensures thread-safe updates

**Limitations**:

- XDP programs cannot directly access socket information
- Rely on `conn_uid_map` populated by other programs
- Only track ingress (received) packets

#### Cgroup Programs (cgroup_skb_ingress/egress)

```c
SEC("cgroup_skb/ingress")
int cgroup_skb_ingress(struct __sk_buff *skb)

SEC("cgroup_skb/egress")
int cgroup_skb_egress(struct __sk_buff *skb)
```

**Key Features**:

1. **UID Extraction**:

   ```c
   __u64 uid_gid = bpf_get_socket_cookie(skb);
   __u32 uid = (uid_gid >> 32) & 0xFFFFFFFF;
   
   if (!uid)
       uid = bpf_get_socket_uid(skb);
   ```

   - Two methods to get UID for reliability
   - Socket cookie embeds UID in upper 32 bits

2. **Direction-Aware Key Construction**:

   ```c
   // Ingress: swap source/dest since packet is incoming
   struct sock_key key = {
       .saddr = iph->daddr,  // Local address
       .daddr = iph->saddr,  // Remote address
       .sport = tcph->dest,  // Local port
       .dport = tcph->source // Remote port
   };
   ```

   - Ensures consistent connection keys for bidirectional traffic

3. **Atomic Statistics Updates**:

   ```c
   __sync_fetch_and_add(&stats->rx_bytes, bytes);
   __sync_fetch_and_add(&stats->rx_packets, 1);
   ```

   - Thread-safe counters for multi-CPU systems

#### Sockops Program (sockops_tracker)

```c
SEC("sockops")
int sockops_tracker(struct bpf_sock_ops *skops)
```

**Purpose**: Create UID→connection mapping when sockets connect

**Operation Types Handled**:

- `BPF_SOCK_OPS_ACTIVE_ESTABLISHED_CB`: Outgoing connection
  established
- `BPF_SOCK_OPS_PASSIVE_ESTABLISHED_CB`: Incoming connection
  accepted

**What It Does**:

1. Gets UID of process creating connection
2. Creates connection key from socket 4-tuple
3. Stores UID in `conn_uid_map`
4. Initializes entries in `conn_stats_map` and `user_stats_map`

**Port Number Handling**:

```c
.dport = bpf_htonl(skops->remote_port) >> 16
```

- Remote port is in host byte order
- Convert to network byte order for consistency
- Shift right 16 bits because `bpf_htonl` returns 32-bit value

#### Kprobes (tcp_sendmsg, tcp_cleanup_rbuf, udp_sendmsg, etc.)

These programs instrument kernel network functions to track data
transfer:

1. **tcp_sendmsg**: TCP transmission

   ```c
   SEC("kprobe/tcp_sendmsg")
   int kprobe_tcp_sendmsg(struct pt_regs *ctx)
   {
       __u32 uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
       __u64 size = PT_REGS_PARM3(ctx);  // Third arg = size
       // Update stats...
   }
   ```

2. **tcp_cleanup_rbuf**: TCP receive buffer cleanup (indicates data
   read)

   ```c
   __u64 copied = PT_REGS_PARM2(ctx);  // Bytes copied
   ```

3. **udp_sendmsg / udp_recvmsg**: UDP send/receive

**Why These Functions?**:

- Called for every send/receive operation
- Have size parameter easily accessible
- Stable across kernel versions (mostly)

### User Space (pdtt_xdp_user.c)

#### BPF Skeleton

Modern eBPF development uses libbpf and bpftool to generate
"skeletons":

```c
#include "pdtt_xdp_kern.skel.h"

struct pdtt_xdp_kern *skel;
skel = pdtt_xdp_kern__open();
pdtt_xdp_kern__load(skel);
```

**Skeleton Advantages**:

- Type-safe access to maps and programs
- Automatic resource management
- Cleaner code vs. raw libbpf API

#### Loading and Attaching

```c
// Load BPF program
skel = pdtt_xdp_kern__open();
err = pdtt_xdp_kern__load(skel);

// Attach to cgroup
cgroup_fd = open("/sys/fs/cgroup", O_RDONLY);
int prog_fd = bpf_program__fd(skel->progs.cgroup_skb_ingress);
bpf_prog_attach(prog_fd, cgroup_fd,
                BPF_CGROUP_INET_INGRESS, BPF_F_ALLOW_MULTI);
```

**BPF_F_ALLOW_MULTI**: Allows multiple programs to attach to same
hook

#### Map Iteration

```c
void log_user_stats(int map_fd)
{
    __u32 key = 0, next_key;
    struct user_data_stats stats;
    
    while (bpf_map_get_next_key(map_fd, &key, &next_key) == 0) {
        if (bpf_map_lookup_elem(map_fd, &next_key, &stats) == 0)
        {
            // Process stats...
        }
        key = next_key;
    }
}
```

**Iteration Pattern**:

- `bpf_map_get_next_key()`: Get next key in map
- Returns -1 when no more keys
- Two-step lookup to handle concurrent modifications

#### Username Resolution

```c
const char* get_username(uid_t uid)
{
    struct passwd *pw = getpwuid(uid);
    if (pw) {
        return pw->pw_name;
    }
    return "unknown";
}
```

- Converts numeric UID to human-readable username
- Uses standard POSIX APIs

#### Per-User Logging

```c
snprintf(user_log_path, sizeof(user_log_path),
         "%s-%s.log", log_prefix, username);
log_file = fopen(user_log_path, "a");
```

- Creates separate log file per user
- Append mode for continuous logging
- Configurable prefix via `-p` option

## Data Structures

### sock_key

```c
struct sock_key {
    __u32 saddr;     // Source IP (network byte order)
    __u32 daddr;     // Destination IP
    __u16 sport;     // Source port (network byte order)
    __u16 dport;     // Destination port
};
```

**Purpose**: Uniquely identifies a network connection (4-tuple)

**Why This Design?**:

- Fixed size for efficient hashing
- Network byte order for consistency across programs
- Covers both TCP and UDP connections

### user_data_stats

```c
struct user_data_stats {
    __u32 uid;              // User ID
    __u64 tx_bytes;         // Bytes transmitted
    __u64 rx_bytes;         // Bytes received
    __u64 tx_packets;       // Packets transmitted
    __u64 rx_packets;       // Packets received
    char username[16];      // Username (for convenience)
};
```

**Purpose**: Aggregate per-user network statistics

**Fields**:

- 64-bit counters to prevent overflow
- Username cached to avoid repeated lookups
- Separate TX/RX for bidirectional tracking

### conn_stats

```c
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
```

**Purpose**: Per-connection statistics with UID association

**Design**: Combines connection identity with statistics for detailed
tracking

## Program Flow

### Initialization Phase

```
User runs: sudo ./pdtt_xdp_user -i eth0 -p /var/log/pdtt -t 10

1. Parse command-line arguments
2. Validate interface exists
3. Load BPF skeleton (pdtt_xdp_kern__open)
4. Load BPF programs into kernel (pdtt_xdp_kern__load)
   - Kernel verifies all programs
   - JIT compiles to native code
5. Open cgroup directory
6. Attach cgroup programs:
   - cgroup_skb_ingress → BPF_CGROUP_INET_INGRESS
   - cgroup_skb_egress → BPF_CGROUP_INET_EGRESS
7. Get file descriptors for maps
8. Enter main loop
```

### Runtime Phase - New Connection

```
Application calls: connect(sockfd, ...)

1. sockops_tracker() fires (BPF_SOCK_OPS_ACTIVE_ESTABLISHED_CB)
   - Extracts UID via bpf_get_current_uid_gid()
   - Creates sock_key from connection 4-tuple
   - Stores UID in conn_uid_map[sock_key] = uid
   - Initializes conn_stats_map[sock_key]
   - Creates/updates user_stats_map[uid]

Connection now tracked and mapped to UID
```

### Runtime Phase - Packet Transmission

```
Application calls: send(sockfd, buffer, size, ...)

Path 1: Kprobe
   kprobe_tcp_sendmsg() fires
   - Gets UID: bpf_get_current_uid_gid()
   - Gets size: PT_REGS_PARM3(ctx)
   - Updates user_stats_map[uid].tx_bytes += size

Path 2: Cgroup (parallel)
   cgroup_skb_egress() fires
   - Gets UID: bpf_get_socket_uid(skb)
   - Parses packet headers
   - Creates sock_key
   - Updates user_stats_map[uid].tx_bytes += skb->len
   - Updates conn_stats_map[key].tx_bytes += skb->len

Both paths track the same data for redundancy
```

### Runtime Phase - Packet Reception

```
Packet arrives from network → NIC → Driver

Path 1: XDP (earliest)
   xdp_tracker_func() fires
   - Parses Ethernet → IP → TCP/UDP headers
   - Creates sock_key
   - Looks up UID from conn_uid_map[key]
   - If found, updates user_stats_map[uid].rx_bytes
   - Returns XDP_ACT_PASS

Path 2: Cgroup
   cgroup_skb_ingress() fires
   - Gets UID from socket context
   - Parses headers (note: source/dest swapped for key)
   - Updates user_stats_map[uid].rx_bytes
   - Updates conn_stats_map[key].rx_bytes

Path 3: Kprobe (when app reads data)
   Application calls: recv(sockfd, buffer, size, ...)
   kprobe_tcp_cleanup_rbuf() fires
   - Gets UID and bytes copied
   - Updates user_stats_map[uid].rx_bytes

Multiple capture points ensure comprehensive tracking
```

### Runtime Phase - Statistics Logging

```
Every <interval> seconds (default 10):

1. log_user_stats(map_fd)
   - Iterate user_stats_map
   - For each UID:
     * Resolve username via getpwuid()
     * Open <prefix>-<username>.log
     * Write timestamp and total bytes
     * Close file

2. log_connection_stats(conn_map_fd)
   - Iterate conn_stats_map
   - For each connection:
     * Resolve username from UID
     * Convert IPs to dotted notation (inet_ntop)
     * Open <prefix>-<username>.log
     * Write connection details (src, dst, TX, RX)
     * Close file

3. Print summary to console

Stats remain in maps (cumulative)
```

### Shutdown Phase

```
User presses Ctrl+C → SIGINT

1. sig_handler() sets running = false
2. Main loop exits
3. Final statistics dump:
   - log_user_stats()
   - log_connection_stats()
4. Detach cgroup programs:
   - bpf_prog_detach2(..., BPF_CGROUP_INET_INGRESS)
   - bpf_prog_detach2(..., BPF_CGROUP_INET_EGRESS)
5. Close cgroup file descriptor
6. Destroy skeleton (pdtt_xdp_kern__destroy)
   - Automatically unloads all programs
   - Closes all map fds
   - Frees memory

Clean shutdown, all resources released
```

## Security and Performance Considerations

### Security

1. **Privilege Requirements**:
   - Requires CAP_BPF and CAP_NET_ADMIN capabilities
   - Typically run as root
   - cgroup access requires appropriate permissions

2. **Data Privacy**:
   - Only tracks metadata (IPs, ports, byte counts)
   - Does NOT inspect packet payloads
   - Respects kernel security boundaries

3. **eBPF Verifier**:
   - All programs verified before loading
   - Prevents:
     - Invalid memory access
     - Kernel crashes
     - Infinite loops
     - Privilege escalation

4. **Resource Limits**:
   - Map sizes bounded (1024 users, 65536 connections)
   - LRU eviction prevents unbounded growth
   - Stack usage limited by verifier

### Performance

1. **XDP Advantages**:
   - Processes packets before expensive skb allocation
   - Zero-copy packet access
   - Per-CPU execution (no locking)
   - JIT compilation to native code

2. **Atomic Operations**:

   ```c
   __sync_fetch_and_add(&stats->tx_bytes, size);
   ```

   - Thread-safe without locks
   - CPU-level atomicity
   - Minimal overhead

3. **Map Types**:
   - Hash maps: O(1) lookup average case
   - LRU maps: Automatic memory management
   - Per-CPU maps could further improve performance (not used)

4. **Overhead Estimates**:
   - XDP: ~10-50 nanoseconds per packet
   - Cgroup: ~100-200 nanoseconds per packet
   - Kprobe: ~500-1000 nanoseconds per call
   - Total: <1% CPU on most workloads

5. **Scalability**:
   - Handles millions of packets per second
   - Scales with number of CPUs
   - No centralized bottlenecks

6. **Optimization Techniques**:
   - Early returns on invalid packets
   - Minimal logging (bpf_printk only for debugging)
   - Efficient data structures
   - Bounded complexity (verifier enforced)

### Trade-offs

1. **Accuracy vs. Performance**:
   - Multiple programs ensure accuracy
   - Some redundancy in tracking
   - Could disable some programs for lower overhead

2. **Memory vs. Connection Count**:
   - 65536 max connections
   - Each connection ~64 bytes in maps
   - ~4MB total for connection maps
   - Can tune max_entries if needed

3. **Kernel Version Dependencies**:
   - Kprobes depend on kernel function signatures
   - May break on kernel updates
   - XDP and cgroup programs more stable

## Conclusion

PDTT demonstrates advanced eBPF capabilities by combining multiple
program types (XDP, cgroup, sockops, kprobes) to achieve
comprehensive per-user network traffic tracking. The multi-layered
approach ensures accuracy while maintaining high performance through
eBPF's zero-overhead abstractions.

Key takeaways:

- **eBPF provides safe, efficient kernel programmability** without
  modules
- **XDP enables line-rate packet processing** at the NIC driver
  level
- **Kprobes allow dynamic instrumentation** of kernel functions
- **Multiple program types complement each other** for complete
  visibility
- **Atomic operations and careful design** ensure thread safety and
  scalability

The system architecture showcases modern Linux kernel observability
patterns applicable to security monitoring, performance analysis, and
network accounting use cases.

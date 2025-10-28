# eBPF Architecture - Pawsey Data Transfer Tracker

## Overview

This document explains how the eBPF programs in PDTT work together to
track network traffic on a per-user basis. The system uses a
**multi-layered eBPF architecture** that monitors network traffic at
different points in the Linux networking stack.

---

## 🗺️ The Three Shared Maps (Data Storage)

All eBPF programs share data through three hash maps:

### 1. `user_stats_map` - Per-User Aggregates

```c
Type: BPF_MAP_TYPE_HASH
Key: UID (32-bit user ID)
Value: user_data_stats {
  uid,           // User ID
  tx_bytes,      // Total bytes transmitted
  rx_bytes,      // Total bytes received
  tx_packets,    // Total packets transmitted
  rx_packets,    // Total packets received
  pid,           // Process ID (from last connection)
  username[16]   // Process name (cached)
}
Max entries: 1,024 users
```

**Purpose:** Stores cumulative totals for each user across all their
connections.

### 2. `conn_uid_map` - Connection → User Mapping

```c
Type: BPF_MAP_TYPE_LRU_HASH
Key: sock_key {
  saddr,  // Source IP address (network byte order)
  daddr,  // Destination IP address (network byte order)
  sport,  // Source port (network byte order)
  dport   // Destination port (network byte order)
}
Value: UID (32-bit user ID)
Max entries: 65,536 connections (LRU eviction)
```

**Purpose:** This is the **critical bridge** that allows other programs
to attribute packets to users. Without this mapping, programs like XDP
cannot determine which user owns a packet.

### 3. `conn_stats_map` - Per-Connection Details

```c
Type: BPF_MAP_TYPE_LRU_HASH
Key: sock_key (same 4-tuple as above)
Value: conn_stats {
  uid,           // User ID owning connection
  saddr, daddr,  // IP addresses
  sport, dport,  // Port numbers
  tx_bytes, rx_bytes,
  tx_packets, rx_packets,
  pid,           // Process ID
  username[16]   // Process name
}
Max entries: 65,536 connections (LRU eviction)
```

**Purpose:** Tracks individual connection statistics with full details.

---

## 🔧 The Seven eBPF Programs

### Layer 1: XDP (Earliest Packet Processing)

#### `xdp_tracker_func` - Attached at NIC Driver Level

```
Program Type: SEC("xdp")
Trigger: Every packet received by network interface
Location: Immediately after NIC driver, before network stack
Access: Raw packet data only (no socket context)
```

**What it does:**

1. Parses packet headers: Ethernet → IP → TCP/UDP
2. Extracts connection 4-tuple (src IP:port → dst IP:port)
3. **Looks up UID** from `conn_uid_map`
4. If found, updates **RX statistics** atomically:

   ```c
   __sync_fetch_and_add(&stats->rx_bytes, bytes);
   __sync_fetch_and_add(&stats->rx_packets, 1);
   ```

5. Returns `XDP_PASS` to continue packet processing

**Key Points:**
- Runs at the **fastest point** in the network stack
- Can only track packets for connections already in `conn_uid_map`
  (populated by sockops)
- Uses atomic operations to prevent race conditions
- Handles both TCP and UDP protocols

**Limitations:**
- No UID context available at this layer
- Depends on sockops program to populate `conn_uid_map` first

---

### Layer 2: Sockops (Connection Establishment)

#### `sockops_tracker` - Attached to Socket Operations

```
Program Type: SEC("sockops")
Trigger: Socket state transitions (connection established)
Events: 
  - BPF_SOCK_OPS_ACTIVE_ESTABLISHED_CB (outgoing connections)
  - BPF_SOCK_OPS_PASSIVE_ESTABLISHED_CB (incoming connections)
Location: When TCP handshake completes
Access: Full socket context with UID
```

**What it does (THE MOST CRITICAL PROGRAM):**

1. Extracts **UID** from current process:

   ```c
   __u32 uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
   ```

2. Filters for IPv4 connections only (`family == 2`)

3. Builds connection key from socket 4-tuple:

   ```c
   struct sock_key key = {
       .saddr = skops->local_ip4,
       .daddr = skops->remote_ip4,
       .sport = skops->local_port,
       .dport = bpf_htonl(skops->remote_port) >> 16
   };
   ```

4. **Creates the UID→connection mapping** (CRITICAL):

   ```c
   bpf_map_update_elem(&conn_uid_map, &key, &uid, BPF_ANY);
   ```

   This enables XDP and other programs to track packets for this connection!

5. Initializes `conn_stats_map[key]` with zero counters

6. Initializes `user_stats_map[uid]` if this is user's first connection

7. Captures process name and PID for logging:

   ```c
   new_conn_stats.pid = bpf_get_current_pid_tgid() >> 32;
   bpf_get_current_comm(&new_conn_stats.username, ...);
   ```

**Why This is Critical:**

This is the **only place** where the connection→user association is
created. Without this program:
- XDP cannot attribute packets to users
- Per-connection tracking is impossible
- Only aggregate user stats (via cgroup) would be available

---

### Layer 3: Cgroup Programs (Socket-Level Tracking)

#### `sock_create_tracker` - Socket Creation Hook

```
Program Type: SEC("cgroup/sock_create")
Trigger: Any process creates a socket
Location: Before socket is fully initialized
Access: Process context with UID
Return: 1 to allow socket creation
```

**What it does:**
- Ensures `user_stats_map[uid]` exists for every user who creates sockets
- Acts as early initialization before connections establish
- Captures process name for display

**Purpose:** Proactive initialization so user entries exist before any
traffic flows.

---

#### `cgroup_skb_ingress` - Incoming Packets at Socket Level

```
Program Type: SEC("cgroup_skb/ingress")
Trigger: Every packet received and associated with a socket
Location: After routing, when packet reaches socket
Access: Socket context with UID available
Return: 1 to accept packet
```

**What it does:**

1. Extracts UID directly from socket context (two methods for reliability):

   ```c
   __u64 uid_gid = bpf_get_socket_cookie(skb);
   __u32 uid = (uid_gid >> 32) & 0xFFFFFFFF;
   
   if (!uid)
       uid = bpf_get_socket_uid(skb);
   ```

2. Skips root (UID 0) and invalid UIDs (`0xFFFFFFFF`)

3. Parses IP header from socket buffer

4. Builds connection key with **swapped addresses**:

   ```c
   struct sock_key key = {
       .saddr = iph->daddr,  // Local address (packet destination)
       .daddr = iph->saddr,  // Remote address (packet source)
       .sport = tcph->dest,   // Local port
       .dport = tcph->source  // Remote port
   };
   ```

   ⚠️ **Address swapping is critical!** Incoming packets have
   remote→local direction, but we need local→remote keys to match
   sockops.

5. Updates both maps atomically (creates entries if needed)

**Key Advantages:**
- Has UID context directly from socket
- Can track packets even before sockops fires (for some edge cases)
- Comprehensive coverage of all socket traffic

---

#### `cgroup_skb_egress` - Outgoing Packets at Socket Level

```
Program Type: SEC("cgroup_skb/egress")
Trigger: Every packet being transmitted from a socket
Location: Before packet leaves socket layer
Access: Socket context with UID available
Return: 1 to allow packet transmission
```

**What it does:**

1. Similar to ingress but for **TX direction**
2. **No address swapping** needed (packet already in local→remote direction):

   ```c
   struct sock_key key = {
       .saddr = iph->saddr,  // Local (source in packet)
       .daddr = iph->daddr,  // Remote (destination in packet)
       .sport = tcph->source,
       .dport = tcph->dest
   };
   ```

3. Updates TX counters in both maps

**Why Both Ingress and Egress?**
- Separate hooks for receive and transmit paths
- Allows accurate bidirectional tracking
- Essential for detailed per-connection statistics

---

### Layer 4: Kprobes (Kernel Function Instrumentation)

These provide **backup/additional tracking** at the syscall level:

#### `kprobe_tcp_sendmsg` - TCP Send

```
Program Type: SEC("kprobe/tcp_sendmsg")
Trigger: tcp_sendmsg() kernel function called
Function Signature: int tcp_sendmsg(struct sock *sk, 
                                     struct msghdr *msg, 
                                     size_t size)
```

**What it does:**
1. Extracts UID from current process
2. Extracts `size` parameter via `PT_REGS_PARM3(ctx)` (third argument)
3. Updates `user_stats_map[uid].tx_bytes` and `.tx_packets`

---

#### `kprobe_tcp_cleanup_rbuf` - TCP Receive

```
Program Type: SEC("kprobe/tcp_cleanup_rbuf")
Trigger: tcp_cleanup_rbuf() called (data read from receive buffer)
Function Signature: void tcp_cleanup_rbuf(struct sock *sk, 
                                           int copied)
```

**What it does:**
1. Extracts UID from current process
2. Extracts `copied` parameter via `PT_REGS_PARM2(ctx)` (bytes delivered
   to userspace)
3. Updates `user_stats_map[uid].rx_bytes` and `.rx_packets`

**Why tcp_cleanup_rbuf?**
- Called when application actually reads data
- Indicates data successfully delivered to userspace
- More accurate than just counting received packets

---

#### `kprobe_udp_sendmsg` - UDP Send

```
Program Type: SEC("kprobe/udp_sendmsg")
Trigger: udp_sendmsg() kernel function called
Function Signature: int udp_sendmsg(struct sock *sk, 
                                     struct msghdr *msg, 
                                     size_t len)
```

---

#### `kprobe_udp_recvmsg` - UDP Receive

```
Program Type: SEC("kprobe/udp_recvmsg")
Trigger: udp_recvmsg() kernel function called
Function Signature: int udp_recvmsg(struct sock *sk, 
                                     struct msghdr *msg, 
                                     size_t len, ...)
```

**Kprobe Characteristics:**
- Update `user_stats_map` only (no per-connection tracking at this level)
- Skip root UID
- Provide syscall-level verification/backup
- Use CPU register access via `PT_REGS_PARM*` macros

---

## 🔄 The Complete Flow

### When a Connection is Established

1. **Process creates socket** → `sock_create_tracker` runs
   - Creates entry in `user_stats_map[uid]` with zero counters
   - Captures process name

2. **TCP handshake completes** → `sockops_tracker` runs
   - **Creates mapping**: `conn_uid_map[key] = uid`
   - Initializes `conn_stats_map[key]` with connection details
   - Now XDP can track this connection!

### When Data is Transmitted (Outgoing)

**Multiple programs fire in parallel:**

1. **`cgroup_skb_egress`** (socket layer) - **PRIMARY**
   - Updates `user_stats_map[uid].tx_bytes += packet_size`
   - Updates `conn_stats_map[key].tx_bytes += packet_size`
   - Has full context and connection details

2. **`kprobe_tcp_sendmsg`** (syscall layer) - **BACKUP**
   - Updates `user_stats_map[uid].tx_bytes += size`
   - Provides redundancy and verification
   - Sees exact syscall parameters

### When Data is Received (Incoming)

**Multiple tracking points:**

1. **`xdp_tracker_func`** (NIC driver, earliest) - **FAST PATH**
   - Looks up UID from `conn_uid_map[key]`
   - Updates RX stats **if connection is known**
   - Fastest possible tracking

2. **`cgroup_skb_ingress`** (socket layer) - **PRIMARY**
   - Gets UID directly from socket
   - Updates RX stats (even for new connections)
   - Most comprehensive coverage

3. **`kprobe_tcp_cleanup_rbuf`** (syscall layer) - **BACKUP**
   - Updates when data is actually read by application
   - Provides verification layer
   - Tracks successful data delivery

---

## ⚛️ Key Design Principles

### 1. Atomic Operations

All counter updates use atomic operations to prevent race conditions in
concurrent execution:

```c
__sync_fetch_and_add(&stats->rx_bytes, bytes);
__sync_fetch_and_add(&stats->rx_packets, 1);
```

**Why needed:**
- Multiple programs can update the same counters simultaneously
- Multiple CPUs may process packets concurrently
- Without atomics, counter values would be corrupted

### 2. Layered Redundancy

Multiple programs track the same events for robustness:

**XDP Layer:**
- Program: `xdp_tracker_func`
- Advantage: Fastest (driver level)
- Limitation: No UID context, depends on conn_uid_map

**Sockops Layer:**
- Program: `sockops_tracker`
- Advantage: Creates UID mapping
- Limitation: Only fires on connection establishment

**Cgroup Layer:**
- Program: `cgroup_skb_*`
- Advantage: Has UID context, comprehensive
- Limitation: Slightly slower than XDP

**Kprobes Layer:**
- Program: `kprobe_*`
- Advantage: Sees exact syscall data
- Limitation: Only per-user tracking

**Result:** If one layer misses a packet, others provide backup
tracking.

### 3. Address Direction Handling

Critical difference between ingress/egress in cgroup programs:

**Ingress (Incoming Packets):**

```c
// Packet headers show: remote_ip:remote_port → local_ip:local_port
// But we need key as: local → remote (to match sockops)
key.saddr = iph->daddr;  // Swap: use packet destination as key
                         // source
key.daddr = iph->saddr;  // Swap: use packet source as key
                         // destination
```

**Egress (Outgoing Packets):**

```c
// Packet headers already show: local_ip:local_port →
// remote_ip:remote_port
// No swapping needed
key.saddr = iph->saddr;  // Use packet source as-is
key.daddr = iph->daddr;  // Use packet destination as-is
```

**Why This Matters:**
- All programs must use the **same connection key** to reference the
  same connection
- Sockops creates keys in local→remote direction
- Ingress packets arrive in remote→local direction
- Without swapping, ingress would create different keys and statistics
  would be split

### 4. LRU Eviction

Connection maps use LRU (Least Recently Used) eviction:

```c
__uint(type, BPF_MAP_TYPE_LRU_HASH);
__uint(max_entries, 65536);
```

**Benefits:**
- Automatically removes old/inactive connections
- Prevents memory exhaustion
- Max 65,536 concurrent connections tracked
- No manual cleanup required

**How it works:**
- When map is full and new entry is added
- Kernel automatically evicts least recently accessed entry
- Ensures most active connections are always tracked

### 5. eBPF Verifier Compliance

All programs must pass the eBPF verifier's strict safety checks:

```c
// Bounds checking required before accessing packet data
if ((void *)(eth + 1) > data_end)
    return XDP_ACT_PASS;

if ((void *)(iph + 1) > data_end)
    return XDP_ACT_PASS;
```

**Safety guarantees:**
- No out-of-bounds memory access
- No infinite loops (must be provably terminating)
- No kernel crashes possible
- Limited stack size (512 bytes)
- No arbitrary function calls

---

## 🖥️ Userspace Program Role

The userspace program (`pdtt_xdp_user.c`) orchestrates the entire system:

### Initialization Phase

1. **Parse command-line arguments**
   - Network interface to monitor
   - Log file prefix
   - Statistics interval

2. **Load BPF skeleton**

   ```c
   skel = pdtt_xdp_kern__open();
   err = pdtt_xdp_kern__load(skel);
   ```

   - Loads compiled eBPF programs into kernel
   - Programs undergo eBPF verifier checks

3. **Attach cgroup programs**

   ```c
   cgroup_fd = open("/sys/fs/cgroup", O_RDONLY);
   bpf_prog_attach(prog_fd, cgroup_fd, BPF_CGROUP_INET_INGRESS, ...);
   bpf_prog_attach(prog_fd, cgroup_fd, BPF_CGROUP_INET_EGRESS, ...);
   ```

   - Attaches to system-wide cgroup (tracks all processes)

4. **Get map file descriptors**

   ```c
   map_fd = bpf_map__fd(skel->maps.user_stats_map);
   conn_map_fd = bpf_map__fd(skel->maps.conn_stats_map);
   ```

   - Used to read statistics from kernel

### Main Loop

```c
while (running) {
    sleep(stats_interval);
    log_user_stats(map_fd);
    log_connection_stats(conn_map_fd);
}
```

**Per interval:**
1. **Read user statistics** via `bpf_map_get_next_key()` and
   `bpf_map_lookup_elem()`
2. **Resolve UIDs** to usernames via `getpwuid()`
3. **Generate logs** with timestamps:
   - Aggregate per-user: `<prefix>-<username>.log`
   - Detailed per-connection statistics
4. **Print to console** for real-time monitoring

### Cleanup Phase

```c
bpf_prog_detach2(..., BPF_CGROUP_INET_INGRESS);
bpf_prog_detach2(..., BPF_CGROUP_INET_EGRESS);
pdtt_xdp_kern__destroy(skel);
```

- Dumps final statistics
- Detaches all programs
- Releases all resources

---

## 🎯 Why This Architecture?

### Multi-Layer Approach Needed Because:

#### Problem 1: XDP Has No UID Context

**XDP programs:**
- Run at NIC driver level (earliest possible point)
- Have access only to raw packet data
- Cannot determine which user/process owns a packet
- Fastest possible packet processing

**Solution:**
- Sockops program creates `conn_uid_map` during connection establishment
- XDP looks up UID from this pre-populated map
- Combines XDP speed with user attribution

#### Problem 2: Sockops Only Fires Once

**Sockops programs:**
- Only trigger on connection state transitions
- Don't see individual packets after establishment
- Cannot track actual data transfer

**Solution:**
- Sockops creates the mapping
- XDP and cgroup programs track packets
- Kprobes verify at syscall level

#### Problem 3: Need Both Speed and Completeness

**Trade-offs:**
- XDP = Fast but limited context
- Cgroup = Complete but slightly slower
- Kprobes = Verification but only aggregate stats

**Solution:**
- Use all layers together
- XDP handles fast path for known connections
- Cgroup provides comprehensive coverage
- Kprobes offer verification/backup

### Architecture Benefits

✅ **Comprehensive Coverage**
- Tracks packets at multiple layers
- Minimal packet loss
- Handles edge cases

✅ **Performance**
- XDP fast path for most traffic
- Atomic operations prevent contention
- LRU eviction prevents memory issues

✅ **Robustness**
- Redundant tracking layers
- Fallback mechanisms
- Safe eBPF verification

✅ **Detailed Insights**
- Per-user aggregates
- Per-connection details
- Process name and PID tracking

---

## 📊 Data Flow Diagram

```
┌─────────────────────────────────────────────────────────────┐
│                     Network Packet Arrives                   │
└──────────────────────┬──────────────────────────────────────┘
                       │
                       ▼
┌─────────────────────────────────────────────────────────────┐
│  Layer 1: XDP (xdp_tracker_func)                            │
│  • Parses packet headers                                     │
│  • Looks up UID from conn_uid_map                           │
│  • Updates RX stats if connection known                     │
└──────────────────────┬──────────────────────────────────────┘
                       │
                       ▼
┌─────────────────────────────────────────────────────────────┐
│  Linux Network Stack Processing                             │
│  • Routing, firewalling, etc.                               │
└──────────────────────┬──────────────────────────────────────┘
                       │
                       ▼
┌─────────────────────────────────────────────────────────────┐
│  Layer 3: Cgroup (cgroup_skb_ingress)                       │
│  • Has socket context with UID                              │
│  • Updates RX stats (backup/comprehensive)                  │
└──────────────────────┬──────────────────────────────────────┘
                       │
                       ▼
┌─────────────────────────────────────────────────────────────┐
│  Application Socket Layer                                    │
│  • Data delivered to application                            │
└──────────────────────┬──────────────────────────────────────┘
                       │
                       ▼
┌─────────────────────────────────────────────────────────────┐
│  Layer 4: Kprobe (kprobe_tcp_cleanup_rbuf)                  │
│  • Tracks actual data read by application                   │
│  • Updates RX stats (verification)                          │
└─────────────────────────────────────────────────────────────┘


┌─────────────────────────────────────────────────────────────┐
│  Connection Establishment (TCP Handshake)                   │
└──────────────────────┬──────────────────────────────────────┘
                       │
                       ▼
┌─────────────────────────────────────────────────────────────┐
│  Layer 2: Sockops (sockops_tracker)                         │
│  • Extracts UID from process                                │
│  • Creates conn_uid_map[key] = uid                          │
│  • Initializes conn_stats_map[key]                          │
│  • Initializes user_stats_map[uid]                          │
└─────────────────────────────────────────────────────────────┘


          ┌────────────────────────────────────┐
          │     Shared eBPF Maps in Kernel     │
          ├────────────────────────────────────┤
          │  user_stats_map                    │
          │  • UID → aggregate stats           │
          ├────────────────────────────────────┤
          │  conn_uid_map                      │
          │  • 4-tuple → UID (THE BRIDGE)      │
          ├────────────────────────────────────┤
          │  conn_stats_map                    │
          │  • 4-tuple → detailed stats        │
          └──────────────┬─────────────────────┘
                         │
                         │ Read every N seconds
                         │
                         ▼
          ┌────────────────────────────────────┐
          │   Userspace Program                │
          │   (pdtt_xdp_user)                  │
          │  • Reads maps                      │
          │  • Resolves UIDs to usernames      │
          │  • Generates log files             │
          │  • Prints to console               │
          └────────────────────────────────────┘
```

---

## 🔍 Example Scenario

### Scenario: User downloads a file via curl

```bash
$ curl https://example.com/file.zip > /tmp/file.zip
```

### Step-by-Step Execution:

#### 1. **Socket Creation**

```
Process: curl (PID 12345, UID 1000)
→ sock_create_tracker fires
  ✓ Creates user_stats_map[1000] = {uid=1000, tx=0, rx=0, ...}
```

#### 2. **TCP Connection Established**

```
Connection: 192.168.1.100:54321 → 93.184.216.34:443
→ sockops_tracker fires
  ✓ Creates conn_uid_map[192.168.1.100:54321→93.184.216.34:443] = 1000
  ✓ Initializes conn_stats_map[key] with connection details
```

#### 3. **TLS Handshake Packets (Outgoing)**

```
Packets sent: 192.168.1.100:54321 → 93.184.216.34:443
→ cgroup_skb_egress fires for each packet
  ✓ user_stats_map[1000].tx_bytes += packet_size
  ✓ conn_stats_map[key].tx_bytes += packet_size
→ kprobe_tcp_sendmsg fires
  ✓ Backup tracking of TX bytes
```

#### 4. **File Download (Incoming Data)**

```
Packets received: 93.184.216.34:443 → 192.168.1.100:54321
→ xdp_tracker_func fires FIRST (at NIC driver)
  ✓ Looks up conn_uid_map with swapped addresses
  ✓ Finds UID 1000
  ✓ Updates RX stats (FAST PATH)

→ cgroup_skb_ingress fires (at socket layer)
  ✓ Gets UID from socket directly
  ✓ Updates RX stats (COMPREHENSIVE)

→ kprobe_tcp_cleanup_rbuf fires (when curl reads data)
  ✓ Tracks actual data delivered to application
  ✓ Updates RX stats (VERIFICATION)
```

#### 5. **Userspace Logging**

```
Every 10 seconds:
→ pdtt_xdp_user reads maps
→ Writes to /var/log/pdtt-john.log:
  
  === Network Statistics Report [2025-01-15 10:30:00] ===
  UID: 1000 | Username: john
  Process: curl (PID: 12345)
    Total: 5242880 bytes
  ---
  
  === Per-Connection Statistics [2025-01-15 10:30:00] ===
  UID: 1000 | Username: john
  Process: curl (PID: 12345)
    Source: 192.168.1.100:54321
    Destination: 93.184.216.34:443
    TX: 2048 bytes (20 packets)
    RX: 5240832 bytes (3600 packets)
    Total: 5242880 bytes
  ---
```

---

## 🚀 Performance Considerations

### XDP Performance
- **Throughput**: Can handle millions of packets per second
- **Latency**: <1 microsecond per packet
- **CPU**: Minimal overhead due to early processing

### Atomic Operations
- **Cost**: Small synchronization overhead
- **Benefit**: Prevents data corruption
- **Alternative**: Lock-free per-CPU maps (not used here for simplicity)

### Map Lookups
- **Hash maps**: O(1) average case
- **LRU overhead**: Minimal, kernel-managed
- **65,536 connections**: ~1MB memory footprint

### Recommended Settings
- **High traffic servers**: Consider larger map sizes
- **Memory constrained**: Use smaller intervals to reduce map entries
- **Low latency**: XDP offload to NIC (if hardware supports)

---

## 🔧 Extending the System

### Adding IPv6 Support

Modify all programs to handle `family == 10` (AF_INET6):

```c
if (skops->family == 10) {  // IPv6
    // Use ipv6 fields instead
}
```

Add new maps with IPv6 keys or use larger address fields.

### Adding Protocol Details

Extend `conn_stats` to include:

```c
__u8 protocol;  // IPPROTO_TCP, IPPROTO_UDP, etc.
__u32 flags;    // TCP flags for connection state
```

### Adding Application-Layer Tracking

Use `bpf_probe_read()` to examine payload data (carefully, with
verifier constraints).

### Optimizing for Specific Workloads

- **High connection churn**: Increase LRU map size
- **Few users, many connections**: Optimize `conn_stats_map` size
- **Real-time monitoring**: Reduce logging interval, add perf events

---

## 📚 Additional Resources

### eBPF Documentation
- [Linux BPF Documentation](https://www.kernel.org/doc/html/latest/bpf/)
- [libbpf API Reference](https://libbpf.readthedocs.io/)
- [BPF Helpers](https://man7.org/linux/man-pages/man7/bpf-helpers.7.html)

### Program Types
- [XDP Documentation](https://prototype-kernel.readthedocs.io/en/latest/
  networking/XDP/)
- [Sockops Programs](https://cilium.io/blog/2018/08/07/
  bpf-socket-options/)
- [Cgroup BPF](https://docs.kernel.org/admin-guide/cgroup-v2.html)

### Tools
- `bpftool`: Inspect loaded programs and maps
- `bpftrace`: Dynamic tracing
- `/sys/kernel/debug/tracing/trace_pipe`: eBPF debug logs

---

## 🎓 Summary

The PDTT eBPF architecture demonstrates:

1. **Multi-layer observability** - Tracking at driver, socket, and
   syscall levels
2. **Intelligent data sharing** - Sockops creates mappings that XDP consumes
3. **Redundancy for reliability** - Multiple programs track the same events
4. **Performance optimization** - XDP fast path with cgroup backup
5. **Safety and verifiability** - All programs pass eBPF verifier
   checks

This architecture achieves comprehensive per-user network traffic
tracking with minimal performance overhead, making it suitable for
production environments like HPC clusters and multi-user systems.

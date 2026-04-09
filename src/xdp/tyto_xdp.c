#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/in.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>


//Tunables
#define WINDOW_NS   1000000000ULL // 1 second
#define UDP_RATE_LIMIT  800
#define SYN_RATE_LIMIT  100
#define ICMP_RATE_LIMIT  500
#define MAX_ENTRIES  65536



//shared event struct
struct tyto_event {
    __u64 timestamp;
    __u32 src_ip;
    __u32 pkt_count;
    __u8 protocol; // TCP, UDP, ICMP
    __u8 pad[3];
};

//Per-IP state struct
struct ip_entry {
    __u64 window_start;
    __u32 pkt_count;
    __u32 blocked; // 0 = not blocked, 1 = blocked
};

//BPF maps
struct {
__uint(type, BPF_MAP_TYPE_LRU_HASH);
__uint(max_entries, MAX_ENTRIES);
__type(key, __u32);
__type(value, struct ip_entry);
}udp_track_map SEC(".maps");

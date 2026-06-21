#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/in.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <linux/icmp.h>

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

struct tyto_stats {
    __u64 total_packets;
    __u64 passed_packets;
    __u64 dropped_packets;
    __u64 udp_packets;
    __u64 syn_packets;
    __u64 icmp_packets;
    __u64 udp_dropped;
    __u64 syn_dropped;
    __u64 icmp_dropped;
};

//BPF maps
struct {
__uint(type, BPF_MAP_TYPE_LRU_HASH);
__uint(max_entries, MAX_ENTRIES);
__type(key, __u32);
__type(value, struct ip_entry);
}udp_track_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, MAX_ENTRIES);
    __type(key, __u32);
    __type(value, struct ip_entry);
}syn_track_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, MAX_ENTRIES);
    __type(key, __u32);
    __type(value, struct ip_entry);
}icmp_track_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, MAX_ENTRIES);
    __type(key, __u32);
    __type(value, __u8);
} blocklist_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, __u32);
    __type(value, __u8);
} allowlist_map SEC(".maps");

//PER CPU ARRY
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct tyto_stats);
}stats_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 24); // 16MB ring buffer
} events SEC(".maps");

static __always_inline void update_stats(__u64 total_delta, __u64 drop_delta,
                                          __u64 udp_drop_delta, __u64 syn_drop_delta,
                                          __u64 icmp_drop_delta)
{
    __u32 key = 0;
    struct tyto_stats *stats = bpf_map_lookup_elem(&stats_map, &key);
    if (!stats)
        return;

    if (total_delta)
        __sync_fetch_and_add(&stats->total_packets, total_delta);
    if (drop_delta)
        __sync_fetch_and_add(&stats->dropped_packets, drop_delta);
    if (udp_drop_delta)
        __sync_fetch_and_add(&stats->udp_dropped, udp_drop_delta);
    if (syn_drop_delta)
        __sync_fetch_and_add(&stats->syn_dropped, syn_drop_delta);
    if (icmp_drop_delta)
        __sync_fetch_and_add(&stats->icmp_dropped, icmp_drop_delta);
}

static __always_inline int emit_event(__u32 src_ip , __u8 protocol,__u32 pkt_count){
   //reserve space in the ring buffer for the event
    struct tyto_event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e)
        return -1;
    e->timestamp = bpf_ktime_get_ns();
    e->src_ip = src_ip;
    e->pkt_count = pkt_count;
    e->protocol = protocol;
    e->pad[0] = 0;
    e->pad[1] = 0;
    e->pad[2] = 0;

    bpf_ringbuf_submit(e, 0);
    return 0;
}

//check rate
static __always_inline int check_rate(void *track_map, __u32 src_ip, __u32 threshold, __u8 protocol){
    struct ip_entry *entry = bpf_map_lookup_elem(track_map, &src_ip);
    __u64 now = bpf_ktime_get_ns();

    if (entry) {
        if (entry->blocked) {
            return 1; // blocked
        }
        if (now - entry->window_start > WINDOW_NS) {
            // reset window
            entry->window_start = now;
            entry->pkt_count = 1;
        } else {
            entry->pkt_count++;
            if (entry->pkt_count > threshold) {
                entry->blocked = 1;
                __u8 block_val = 1;
                bpf_map_update_elem(&blocklist_map, &src_ip, &block_val, BPF_ANY);
                emit_event(src_ip, protocol, entry->pkt_count);
                return 1; // blocked
            }
        }

    } else {
        struct ip_entry new_entry = {
            .window_start = now,
            .pkt_count = 1,
            .blocked = 0
        };
        bpf_map_update_elem(track_map, &src_ip, &new_entry, BPF_ANY);
    }
    return 0; // not blocked
}


SEC("xdp")
int xdp_prog(struct xdp_md *ctx) {
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;
    struct ethhdr *eth = data;
    if (data + sizeof(*eth) > data_end)
        return XDP_PASS;
    if(bpf_ntohs(eth->h_proto)!= ETH_P_IP)
        return XDP_PASS;
    struct iphdr *ip = (void *)(eth + 1);
    if ((void *)(ip + 1) > data_end)
        return XDP_PASS;
    __u32 src_ip = ip->saddr;
    __u8 protocol = ip->protocol;

    update_stats(1, 0, 0, 0, 0);

    __u8 *blocked = bpf_map_lookup_elem(&blocklist_map, &src_ip);
    if (blocked && *blocked) {
        update_stats(0, 1, 0, 0, 0);
        emit_event(src_ip, protocol, 1);
        return XDP_DROP;
    }
    __u8 *allowed = bpf_map_lookup_elem(&allowlist_map,&src_ip);
    if (allowed&& *allowed) {
      return XDP_PASS;
    }

    void *trans_hdr = (void *)ip + (ip->ihl * 4);

    if (protocol == IPPROTO_UDP) {
        struct udphdr *udp = trans_hdr;

        // BOUNDS CHECK
        if ((void *)(udp + 1) > data_end)
            return XDP_PASS;

        // RATE CHECK
        if (check_rate(&udp_track_map, src_ip, UDP_RATE_LIMIT, IPPROTO_UDP)) {
            update_stats(0, 1, 1, 0, 0);
            return XDP_DROP;
        }
    }
    else if (protocol == IPPROTO_TCP) {
        struct tcphdr *tcp = trans_hdr;

        // BOUNDS CHECK
        if ((void *)(tcp + 1) > data_end)
            return XDP_PASS;

        // only check rate for new connections (SYN without ACK)
        if (tcp->syn && !tcp->ack) {
            if (check_rate(&syn_track_map, src_ip, SYN_RATE_LIMIT, IPPROTO_TCP)) {
                update_stats(0, 1, 0, 1, 0);
                return XDP_DROP;
            }
        }
    }
    else if (protocol == IPPROTO_ICMP) {
        struct icmphdr *icmp = trans_hdr;

        // BOUNDS CHECK
        if ((void *)(icmp + 1) > data_end)
            return XDP_PASS;

        // RATE CHECK
        if (check_rate(&icmp_track_map, src_ip, ICMP_RATE_LIMIT, IPPROTO_ICMP)) {
            update_stats(0, 1, 0, 0, 1);
            return XDP_DROP;
        }
    }

    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";

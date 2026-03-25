#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ipv6.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/in.h>
#include <linux/in.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>


//Tunables
#define WINDOW_NS   1000000000ULL // 1 second
#define UDP_RATE_LIMIT  800
#define SYN_RATE_LIMIT  100
#define ICMP_RATE_LIMIT  500



//shared event struct
struct tyto_event {
    __u64 timestamp;
    __u32 src_ip;
    __u32 pkt_count;
    __u8 protocol; // TCP, UDP, ICMP
    __u8 pad[3];
};

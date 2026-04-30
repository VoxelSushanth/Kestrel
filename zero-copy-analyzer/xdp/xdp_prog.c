/*
 * XDP BPF program for zero-copy packet analyzer
 *
 * This program is loaded into the kernel via AF_XDP and passes all packets
 * to userspace for analysis. In production, you might add filtering logic
 * here to only capture relevant traffic.
 *
 * Build with:
 *   clang -O2 -target bpf -c xdp_prog.c -o xdp_prog.o
 */

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/icmp.h>

/* XDP action return codes */
#define XDP_ABORTED 0
#define XDP_DROP 1
#define XDP_PASS 2
#define XDP_TX 3
#define XDP_REDIRECT 4

/* Map for statistics (optional - for in-kernel accounting) */
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u64);
} xdp_stats SEC(".maps");

/* Configuration map for runtime tuning */
struct config {
    __u32 drop_all;      /* Drop all packets if non-zero */
    __u32 filter_port;   /* Port to filter on (host byte order) */
    __u32 filter_proto;  /* Protocol to filter (IPPROTO_TCP, etc.) */
    __u32 reserved;
};

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct config);
} config_map SEC(".maps");

/* Simple packet counter */
static __always_inline void increment_counter(__u32 index) {
    __u64 *counter = bpf_map_lookup_elem(&xdp_stats, &index);
    if (counter) {
        __sync_fetch_and_add(counter, 1);
    }
}

/* Parse Ethernet header and return offset to next header */
static __always_inline int parse_ethernet(void *data, __u64 data_len, __u16 *ether_type, __u64 *offset) {
    struct ethhdr *eth = data;
    
    if (*offset + sizeof(*eth) > data_len) {
        return -1;
    }
    
    *ether_type = bpf_ntohs(eth->h_proto);
    *offset += sizeof(*eth);
    
    return 0;
}

/* Parse IPv4 header */
static __always_inline int parse_ipv4(void *data, __u64 data_len, __u64 offset, 
                                       __u8 *proto, __u64 *payload_offset) {
    struct iphdr *iph = data + offset;
    
    if (offset + sizeof(*iph) > data_len) {
        return -1;
    }
    
    /* Verify IP version */
    if (iph->version != 4) {
        return -1;
    }
    
    *proto = iph->protocol;
    *payload_offset = offset + (iph->ihl * 4);
    
    return 0;
}

/* Parse IPv6 header */
static __always_inline int parse_ipv6(void *data, __u64 data_len, __u64 offset,
                                       __u8 *proto, __u64 *payload_offset) {
    struct ipv6hdr *ip6h = data + offset;
    
    if (offset + sizeof(*ip6h) > data_len) {
        return -1;
    }
    
    *proto = ip6h->nexthdr;
    *payload_offset = offset + sizeof(*ip6h);
    
    return 0;
}

/* Main XDP program entry point */
SEC("xdp")
int xdp_pass_all(struct xdp_md *ctx) {
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;
    __u64 data_len = data_end - data;
    
    __u16 ether_type;
    __u64 offset = 0;
    __u8 proto = 0;
    __u64 payload_offset;
    
    /* Get configuration */
    __u32 config_key = 0;
    struct config *cfg = bpf_map_lookup_elem(&config_map, &config_key);
    
    /* Check if we should drop all packets */
    if (cfg && cfg->drop_all) {
        increment_counter(0);
        return XDP_DROP;
    }
    
    /* Parse Ethernet header */
    if (parse_ethernet(data, data_len, &ether_type, &offset) < 0) {
        return XDP_PASS;
    }
    
    /* Handle VLAN tags (802.1Q) */
    while (ether_type == ETH_P_8021Q) {
        __u16 *vlan_hdr = data + offset;
        if (offset + 4 > data_len) {
            return XDP_PASS;
        }
        ether_type = bpf_ntohs(vlan_hdr[1]);
        offset += 4;
    }
    
    /* Parse based on EtherType */
    switch (ether_type) {
    case ETH_P_IP:
        if (parse_ipv4(data, data_len, offset, &proto, &payload_offset) < 0) {
            return XDP_PASS;
        }
        
        /* Optional: filter by protocol/port */
        if (cfg && cfg->filter_proto && proto != cfg->filter_proto) {
            return XDP_PASS;
        }
        
        /* Could add TCP/UDP port filtering here */
        break;
        
    case ETH_P_IPV6:
        if (parse_ipv6(data, data_len, offset, &proto, &payload_offset) < 0) {
            return XDP_PASS;
        }
        break;
        
    case ETH_P_ARP:
        /* Pass ARP packets */
        break;
        
    default:
        /* Pass unknown protocols */
        break;
    }
    
    /* Count packets by type */
    switch (ether_type) {
    case ETH_P_IP:
        increment_counter(0);
        break;
    case ETH_P_IPV6:
        increment_counter(0);
        break;
    }
    
    /* Pass all packets to userspace via AF_XDP */
    return XDP_PASS;
}

/* Alternative: Drop all non-matching packets */
SEC("xdp")
int xdp_filter(struct xdp_md *ctx) {
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;
    __u64 data_len = data_end - data;
    
    __u16 ether_type;
    __u64 offset = 0;
    __u8 proto;
    __u64 payload_offset;
    
    /* Get configuration */
    __u32 config_key = 0;
    struct config *cfg = bpf_map_lookup_elem(&config_map, &config_key);
    
    if (!cfg) {
        return XDP_PASS;
    }
    
    /* Parse Ethernet */
    if (parse_ethernet(data, data_len, &ether_type, &offset) < 0) {
        return XDP_DROP;
    }
    
    /* Only process IPv4 for now */
    if (ether_type != ETH_P_IP) {
        return XDP_PASS;
    }
    
    if (parse_ipv4(data, data_len, offset, &proto, &payload_offset) < 0) {
        return XDP_DROP;
    }
    
    /* Filter by protocol if configured */
    if (cfg->filter_proto && proto != cfg->filter_proto) {
        return XDP_PASS;
    }
    
    /* Could add port filtering here by parsing TCP/UDP headers */
    
    return XDP_PASS;
}

/* License for BPF program */
char _license[] SEC("license") = "GPL";

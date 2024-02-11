// +build ignore

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

char __license[] SEC("license") = "Dual MIT/GPL";

#define MAX_MAP_ENTRIES 100
#define ETH_P_IP		0x0800	/* Internet Protocol packet	*/

#define PARSE_SKIP 			0
#define PARSED_TCP_PACKET	1
#define PARSED_UDP_PACKET	2

/* Define an LRU hash map for storing packet count by source IP and port */
struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(max_entries, MAX_MAP_ENTRIES);
	__type(key, u64); // source IPv4 addresses and port tuple
	__type(value, u32); // packet count
} xdp_stats_map SEC(".maps");

static __always_inline int parse_ip_packet(struct xdp_md *ctx, u64 *ip_metadata) {
	void *data_end = (void *)(long)ctx->data_end;
	void *data     = (void *)(long)ctx->data;

	// First, parse the ethernet header.
	struct ethhdr *eth = data;
	if ((void *)(eth + 1) > data_end) {
		return PARSE_SKIP;
	}

	if (eth->h_proto != bpf_htons(ETH_P_IP)) {
		// The protocol is not IPv4, so we can't parse an IPv4 source address.
		return PARSE_SKIP;
	}

	// Then parse the IP header.
	struct iphdr *ip = (void *)(eth + 1);
	if ((void *)(ip + 1) > data_end) {
		return PARSE_SKIP;
	}

	u16 src_port, dest_port;
	int retval;

	if (ip->protocol == IPPROTO_TCP) {
		struct tcphdr *tcp = (void*)ip + sizeof(*ip);
		if ((void*)(tcp+1) > data_end) {
			return PARSE_SKIP;
		}
		src_port = bpf_ntohs(tcp->source);
		dest_port = bpf_ntohs(tcp->dest);
		retval = PARSED_TCP_PACKET;
	} else if (ip->protocol == IPPROTO_UDP) {
		struct udphdr *udp = (void*)ip + sizeof(*ip);
		if ((void*)(udp+1) > data_end) {
			return PARSE_SKIP;
		}
		src_port = bpf_ntohs(udp->source);
		dest_port = bpf_ntohs(udp->dest);
		retval = PARSED_UDP_PACKET;
	} else {
		// The protocol is not TCP or UDP, so we can't parse a source port.
		return PARSE_SKIP;
	}

	// Return the (source IP, destination IP) tuple in network byte order.
	// |<-- Source IP: 32 bits -->|<-- Source Port: 16 bits --><-- Dest Port: 16 bits -->|
	*ip_metadata = ((u64)(ip->saddr) << 32) | ((u64)src_port << 16) | (u64)dest_port;
	return retval;
}

SEC("xdp")
int xdp_prog_func(struct xdp_md *ctx) {
	u64 ip_meta;
	if (!parse_ip_packet(ctx, &ip_meta)) {
		// Not an IPv4 packet or not TCP/UDP, so don't count it.
		return XDP_PASS;
	}

	u32 *pkt_count = bpf_map_lookup_elem(&xdp_stats_map, &ip_meta);
	if (!pkt_count) {
		// No entry in the map for this IP tuple yet, so set the initial value to 1.
		u32 init_pkt_count = 1;
		bpf_map_update_elem(&xdp_stats_map, &ip_meta, &init_pkt_count, BPF_ANY);
	} else {
		// Entry already exists for this IP tuple,
		// so increment it atomically using an LLVM built-in.
		__sync_fetch_and_add(pkt_count, 1);
	}

	return XDP_PASS;
}

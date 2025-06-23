#define ETH_P_IP	0x0800		
#define ICMP_PING 8

#define ETH_ALEN 6
#define ETH_HLEN 14


#ifndef __XDP_PROG_H
#define __XDP_PROG_H

// map key
struct flow_id {
    __u32 src_ip;
    __u32 dst_ip;
    __u16 src_port;
    __u16 dst_port;
    __u8  proto;
};

struct flow_stat {
    __u64 syn_count;
    __u64 tcp_count;
    __u64 udp_count;
    __u64 last_ts;
};


#endif // __XDP_FLOW_COLLECTOR_H
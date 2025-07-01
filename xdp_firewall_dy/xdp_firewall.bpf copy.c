// This page is useless and can be deleted


#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#include "xdp_firewall.h"

char LICENSE[] SEC("license") = "Dual BSD/GPL";

// 协议统计 map（全局）维护各协议的全局动态阈值
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, __u8);               // 协议ID
    __type(value, struct proto_stat);
    __uint(max_entries, 4);
} proto_stat_map SEC(".maps");

// 黑名单 map（按 IP）
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, __u32);  // IP
    __type(value, struct blacklist_val);
    __uint(max_entries, 1024);
} blacklist SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, __u32); // 源 IP
    __type(value, struct tcp_counter);
    __uint(max_entries, 10240);
} tcp_flood_map SEC(".maps");


SEC("xdp")
int xdp_dynamic_throttle(struct xdp_md *ctx) {

    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end) return XDP_PASS;
    if (eth->h_proto != bpf_htons(ETH_P_IP)) return XDP_PASS;

    struct iphdr *iph = data + sizeof(*eth);
    if ((void *)(iph + 1) > data_end) return XDP_PASS;

    __u32 src_ip = iph->saddr;
    __u8 proto = iph->protocol;
    __u64 now = bpf_ktime_get_ns(); // 当前时间（纳秒）
    __u64 pkt_len = data_end - data;

    // 协议分类
    __u8 ptype = 0;

    // // 检查黑名单
    struct blacklist_val *bl= bpf_map_lookup_elem(&blacklist, &src_ip);
    if (bl) {
        if (now - bl->ts_ns < BLACKLIST_DURATION_NS) {
            return XDP_DROP;
        } else {
            // 黑名单已过期，移除 IP
            bpf_map_delete_elem(&blacklist, &src_ip);
        }
    }

    if (proto != IPPROTO_TCP && proto != IPPROTO_UDP && proto != IPPROTO_ICMP) {
        return XDP_PASS;
    }

    // 协议分类
    if (proto == IPPROTO_TCP) {
        struct tcphdr *tcph = (void *)iph + iph->ihl * 4;
        if ((void *)(tcph + 1) > data_end) return XDP_PASS;
        if (tcph->syn && !tcph->ack) ptype = PROTO_SYN;
        else {
            // 处理非 SYN TCP，检测 TCP Flood
            struct tcp_counter *tcp = bpf_map_lookup_elem(&tcp_flood_map, &src_ip);
            struct tcp_counter new_tcp = {};
            if (!tcp) { //新TCP
                new_tcp.count = 1;
                new_tcp.last_time = now;
                bpf_map_update_elem(&tcp_flood_map, &src_ip, &new_tcp, BPF_ANY);
                return XDP_PASS;
            }
            if (now - tcp->last_time > WINDOW_NS) { //时间窗口计数
                tcp->count = 1;
                tcp->last_time = now;
            }else{
                tcp->count ++;
                if (tcp->count > TCP_FLOOD_THRESHOLD){ // TCP_FLOOD_THRESHOLD
                    struct blacklist_val new_bl = {.ts_ns = bpf_ktime_get_ns()};
                    bpf_map_update_elem(&blacklist, &src_ip, &new_bl, BPF_ANY);
                    return XDP_DROP;
                }
            } 
            return XDP_PASS;
        }
    } else if (proto == IPPROTO_UDP) {
        ptype = PROTO_UDP;
    } else if (proto == IPPROTO_ICMP) {
        ptype = PROTO_ICMP;
    } else {
        return XDP_PASS;
    }

    // // 协议统计项获取与初始化
    struct proto_stat *stat = bpf_map_lookup_elem(&proto_stat_map, &ptype);
    struct proto_stat new_stat = {};

    if (!stat) { //新类型协议
        new_stat.dyn_threshold = THRESHOLD_BASE; // 初始阈值
        new_stat.last_ts = now;  //上次更新时间->现在
        new_stat.exceed_duration = now;
        bpf_map_update_elem(&proto_stat_map, &ptype, &new_stat, BPF_ANY);
        
        stat = bpf_map_lookup_elem(&proto_stat_map, &ptype);
        if (!stat) return XDP_PASS;  //并非要预防的直接pass
    }

    // 检查黑名单
    // struct blacklist_val *bl= bpf_map_lookup_elem(&blacklist, &src_ip);
    // if (bl) {
    //     if (now - bl->ts_ns < BLACKLIST_DURATION_NS) {
    //         // 黑名单尚未过期，记录统计后丢弃
    //         stat->byte_count += pkt_len;
    //         return XDP_DROP;
    //     } else {
    //         // 黑名单已过期，移除 IP
    //         bpf_map_delete_elem(&blacklist, &src_ip);
    //     }
    // }

    // 时间窗口处理  每秒更新动态阈值
    //  上升快、下降慢
    if (now - stat->last_ts > WINDOW_NS) {  //该协议上次进入时间串口已1s，则更新动态阈值
        // 指数加权平均更新阈值
        __u64 new_threshold;
        if (stat->byte_count > stat->dyn_threshold) {
            // 流量高，阈值上升（快速）
            new_threshold = ((SCALE - ALPHA) * stat->dyn_threshold + ALPHA * stat->byte_count) / SCALE;
        } else {
            // 流量低，阈值下降（慢速）
            new_threshold = ((SCALE - BETA) * stat->dyn_threshold + BETA * stat->byte_count) / SCALE;
        }
        // 加个上下限保护
        if (new_threshold < THRESHOLD_MIN)
            new_threshold = THRESHOLD_MIN;
        else if (new_threshold > THRESHOLD_MAX)
            new_threshold = THRESHOLD_MAX;

        stat->dyn_threshold = new_threshold;  //更新阈值
        stat->byte_count = 0;   
        stat->exceed_count = 0;
        // stat->exceed_dduration = bpf_ktime_get_ns();
        stat->last_ts = now;
    }

    // 字节计数 + 检查阈值
    // 黑名单未命中或已被清除，继续正常处理
    stat->byte_count += pkt_len;

    if (stat->byte_count > stat->dyn_threshold) {
        //超过阈值了，再判断持续的时间窗口
        if (now - stat->exceed_dduration > EXCEED_DURATION){
            // 每超过一个5s就容忍一次
            stat->exceed_count += 1;
            stat->exceed_dduration = bpf_ktime_get_ns();
        }
        //超过了三次无法容忍，拉黑
        if (stat->exceed_count >= BLOCK_THRESHOLD) {
            struct blacklist_val bl_val = {.ts_ns = bpf_ktime_get_ns()};
            bpf_map_update_elem(&blacklist, &src_ip, &bl_val, BPF_ANY);
            return XDP_DROP;
        }
    }

// 封锁条件（关键）：
// 短期异常 spike：动态阈值上浮容忍。
// 持续性偏离 + 超出安全容忍区间：判定为攻击 → 加入黑名单 or 丢弃包。

    return XDP_PASS;
}

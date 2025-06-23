// SPDX-License-Identifier: GPL-2.0
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include "xdp_firewall.h"

char LICENSE[] SEC("license") = "Dual BSD/GPL";

// 协议统计 map（全局）维护各协议的全局动态阈值
struct
{
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, __u8); // 协议ID
    __type(value, struct proto_stat);
    __uint(max_entries, 4);
} proto_stat_map SEC(".maps");

// 黑名单 map（按 IP）
struct
{
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, __u32); // IP
    __type(value, struct blacklist_val);
    __uint(max_entries, 1024);
} blacklist SEC(".maps");


SEC("xdp")
int xdp_dynamic_throttle(struct xdp_md *ctx)
{

    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;
    if (eth->h_proto != bpf_htons(ETH_P_IP))
        return XDP_PASS;

    struct iphdr *iph = data + sizeof(*eth);
    if ((void *)(iph + 1) > data_end)
        return XDP_PASS;

    __u32 src_ip = iph->saddr;
    __u8 proto = iph->protocol;
    __u64 now = bpf_ktime_get_ns(); // 当前时间（纳秒）
    __u64 pkt_len = data_end - data;

    // 协议分类
    __u8 ptype = 0;

    // // 检查黑名单
    struct blacklist_val *bl = bpf_map_lookup_elem(&blacklist, &src_ip);
    if (bl)
    {
        if (now - bl->ts_ns < BLACKLIST_DURATION_NS)
        {
            return XDP_DROP;
        }
        else
        {
            // 黑名单已过期，移除 IP
            bpf_map_delete_elem(&blacklist, &src_ip);
        }
    }

    if (proto != IPPROTO_TCP && proto != IPPROTO_UDP && proto != IPPROTO_ICMP)
    {
        return XDP_PASS;
    }

    // 协议分类
    if (proto == IPPROTO_TCP)
    {
        struct tcphdr *tcph = (void *)iph + iph->ihl * 4;
        if ((void *)(tcph + 1) > data_end)
            return XDP_PASS;
        if (tcph->syn && !tcph->ack)
            ptype = PROTO_SYN;
        // else
        // {
        //     // 处理非 SYN TCP，检测 TCP Flood
        //     struct tcp_counter *tcp = bpf_map_lookup_elem(&tcp_flood_map, &src_ip);
        //     struct tcp_counter new_tcp = {};
        //     if (!tcp)
        //     { // 新TCP
        //         new_tcp.count = 1;
        //         new_tcp.last_time = now;
        //         bpf_map_update_elem(&tcp_flood_map, &src_ip, &new_tcp, BPF_ANY);
        //         return XDP_PASS;
        //     }
        //     if (now - tcp->last_time > WINDOW_NS)
        //     { // 时间窗口计数
        //         tcp->count = 1;
        //         tcp->last_time = now;
        //     }
        //     else
        //     {
        //         tcp->count++;
        //         if (tcp->count > TCP_FLOOD_THRESHOLD)
        //         { // TCP_FLOOD_THRESHOLD
        //             struct blacklist_val new_bl = {.ts_ns = now};
        //             bpf_map_update_elem(&blacklist, &src_ip, &new_bl, BPF_ANY);
        //             return XDP_DROP;
        //         }
        //     }
        //     return XDP_PASS;
        // }
    }
    else if (proto == IPPROTO_UDP)
    {
        ptype = PROTO_UDP;
    }
    else if (proto == IPPROTO_ICMP)
    {
        ptype = PROTO_ICMP;
    }
    else
    {
        return XDP_PASS;
    }

    // // 协议统计项获取与初始化
    struct proto_stat *stat = bpf_map_lookup_elem(&proto_stat_map, &ptype);
    struct proto_stat new_stat = {};

    if (!stat)                                   // 仅当 stat == NULL（map 中没有该协议的记录）时，才写入初始值，确保不会意外清零已有的统计数据。
    {                                            // 新类型协议
        new_stat.dyn_threshold = THRESHOLD_BASE; // 初始阈值
        new_stat.last_ts = now;                  // 上次更新时间->现在
        // new_stat.exceed_count = 0;
        // new_stat.exceed_duration = 0;
        // new_stat.exceed_duration_count = 0 ;
        // new_stat.exceed_duration = bpf_ktime_get_ns();  //新协议先给一个持续时间窗口开始
        bpf_map_update_elem(&proto_stat_map, &ptype, &new_stat, BPF_ANY);

        stat = bpf_map_lookup_elem(&proto_stat_map, &ptype);
        if (!stat)
            return XDP_PASS; // 并非要预防的直接pass
    }

    stat->byte_count += pkt_len; // 字节计数便于阈值更新

   
    //  上升快、下降慢
    if (now - stat->last_ts > WINDOW_NS)   
    { 
        // ⚠️ 先判断是否超阈
        if (stat->byte_count > stat->dyn_threshold)
        {
            // bpf_printk("exceed\n");
            stat->exceed_duration++;
            // 如果是超出阈值且在时间窗口内，记1次，5000000个微妙是5s
            // bpf_printk("window exceed_duration: %u\n", stat->exceed_duration);
            if (stat->exceed_duration >= EXCEED_DURATION ) //超过5s，记一次突破滑动窗口不好的行为
            {
                stat->exceed_duration_count++; // 0->1->2..->5
                stat->exceed_duration = 0; //窗口重置再次计数
                // bpf_printk("window exceed_duration_count: %u\n", stat->exceed_duration_count);
            }
            // 注意：拉黑操作是不可重入行为，仅在滑窗机制满足后触发一次
            if(stat->exceed_duration_count >= BLOCK_THRESHOLD ){  //可以拉黑处理了
                struct blacklist_val bl_val = {.ts_ns = now};
                bpf_map_update_elem(&blacklist, &src_ip, &bl_val, BPF_ANY);
                stat->exceed_duration_count =0; //时间窗口重新计数
                return XDP_DROP;
            }
        }
        else
        {
            // 未超过阈值，重置滑动窗口
            stat->exceed_duration = 0; // 未超过阈值，时间窗口重新计数
            stat->exceed_duration_count = 0;
            // bpf_printk("not exceed\n");
        }


        // bpf_printk("BPF check: byte_count=%llu, dyn_threshold=%llu\n", stat->byte_count, stat->dyn_threshold);


        // ✅ 再更新阈值
        // 指数加权平均更新阈值
        __u64 new_threshold;
        if (stat->byte_count > stat->dyn_threshold)
        {
            // 流量高，阈值上升（快速）
            new_threshold = ((SCALE - ALPHA) * stat->dyn_threshold + ALPHA * stat->byte_count) / SCALE;
        }
        else
        {
            // 流量低，阈值下降（慢速）
            new_threshold = ((SCALE - BETA) * stat->dyn_threshold + BETA * stat->byte_count) / SCALE;
        }
        // 加个上下限保护
        if (new_threshold < THRESHOLD_MIN)
            new_threshold = THRESHOLD_MIN;
        else if (new_threshold > THRESHOLD_MAX)
            new_threshold = THRESHOLD_MAX;

        stat->dyn_threshold = new_threshold; // 更新阈值
        // bpf_printk("DynThreshold: %u\n",stat->dyn_threshold);

        // 字节数也归零，用下次新值计算
        // if (stat->byte_duration_count > BYTE_DURATION){
        //     stat->byte_count = 0; 
        // }else{
        //     stat->byte_duration_count++; //1s的总字节数
        //     // bpf_printk("byte_duration_count: %u\n",stat->byte_duration_count);
        // }   
        
        stat->byte_count = 0;
        stat->last_ts = now;
    }
    return XDP_PASS;
}

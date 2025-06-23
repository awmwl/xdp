#ifndef __XDP_FIREWALL_H
#define __XDP_FIREWALL_H


#define ETH_P_IP 0x0800		
#define ICMP_PING 8

#define ETH_ALEN 6
#define ETH_HLEN 14

#define MAX_ENTRIES 10240

#define BETA 5 // 降低速率因子（相对 ALPHA 小）
#define ALPHA 300 // 0.3 * 100
#define SCALE 1000 // 用于固定点数

#define THRESHOLD_BASE 75 * 1024 // 初始阈值  // 100 KiB/s
#define THRESHOLD_MAX 500*1024  //  1MiB/s
#define THRESHOLD_MIN 50 * 1024 // 最小动态阈值：防止阈值降到过低
#define TCP_FLOOD_THRESHOLD 100000  // 每秒最多允许 TCP 数据包数

#define BLOCK_THRESHOLD 1  // 连续超过3次滑动时间窗口触发黑名单
// #define EXCEED_DURATION (5ULL * 1000000000ULL)  //持续性时间窗口
#define EXCEED_DURATION 1 //滑动时间窗口，1000个ms是1S
#define BYTE_DURATION 1000 // 1000个ms是1S

#define WINDOW_NS (1ULL * 1000000000ULL)
// #define WINDOW_NS (1ULL * 1000000ULL)  // 1ms = 1,000,000ns
#define BLACKLIST_DURATION_NS (120ULL * 1000000000ULL) // 60秒


enum proto_type {
    PROTO_SYN = 1,
    PROTO_UDP = 2,
    PROTO_ICMP = 3,

};

// 动态统计结构体
struct proto_stat {
    __u64 last_ts;          // 上次更新时间
    __u32 byte_count;        // 当前时间窗口内的字节数
    __u32 dyn_threshold;    // 动态阈值
    __u32 exceed_duration;  // 持续性时间超窗口
    __u8 exceed_duration_count;
};


// 黑名单项
struct blacklist_val {
    __u64 ts_ns;  // 纳秒时间戳，到期解除
};

#endif /* __XDP_FIREWALL_H */
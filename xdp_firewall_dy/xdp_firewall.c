#include <stdio.h>
#include <stdio.h>
#include <stdint.h>

#include "bpf/bpf.h"
#include "bpf/libbpf.h"

#include <unistd.h>
#include <signal.h> // <-- 关键：用于 信号处理
#include <stdbool.h>
#include <net/if.h>    // <-- 关键：用于 if_nametoindex
#include <arpa/inet.h> // <-- 关键：用于IP地址转换
#include <time.h>      // <-- 关键：用于时间格式转换
// #include <sys/sysinfo.h>// <-- 新增，用于获取系统启动时间

#include "xdp_firewall.skel.h"
#include "xdp_firewall.h"

static volatile bool exiting = false;
void print_ip(__u32 ip)
{
    struct in_addr addr = {.s_addr = ip};
    printf("%s", inet_ntoa(addr));
}

// 将纳秒时间戳转换为本地时间字符串
void print_timestamp(__u64 ns_time)
{
    time_t sec = ns_time / 1000000000ULL; // 纳秒 -> 秒
    struct tm *tm = localtime(&sec);
    char time_str[64];
    strftime(time_str, sizeof(time_str), "%F %T", tm);
    printf("%s\n", time_str);
}

int main(int argc, char **argv)
{
    struct xdp_firewall_bpf *skel;
    // int map_fd;
    const char *ifname = "ens33";

    // 加载 BPF skeleton
    skel = xdp_firewall_bpf__open_and_load();
    if (!skel)
    {
        fprintf(stderr, "Failed to open/load skeleton\n");
        return 1;
    }

    int ifindex = if_nametoindex(ifname); // 定义网络接口，程序ID
    if (ifindex == 0)
    {
        perror("if_nametoindex");
        return -1;
    }

    struct bpf_link *link = bpf_program__attach_xdp(skel->progs.xdp_dynamic_throttle, ifindex);
    if (!link)
    {
        fprintf(stderr, "Failed to attach XDP to %s (index %d)\n", ifname, ifindex);
        goto cleanup;
    }
    printf("XDP program successfully attached on %s (ifindex: %d)\n", ifname, ifindex);

    // 等待用户中断
    printf("Press Ctrl+C to exit...\n");
    pause();

    int map_fd = bpf_map__fd(skel->maps.blacklist);
    int proto_map_fd = bpf_map__fd(skel->maps.proto_stat_map);

    生成带时间戳的唯一文件名
    char filename[128];
    time_t now = time(NULL);
    struct tm *tm_info = localtime(&now);
    strftime(filename, sizeof(filename), "proto_stat_%Y%m%d_%H%M%S.csv", tm_info);

    FILE *fp = fopen(filename, "w");  // 用 "w" 模式写入新的文件
    if (!fp) {
        perror("Failed to open CSV");
        return 1;
    }
    // 写入表头
    fprintf(fp, "timestamp,protocol,dyn_threshold,byte_count,exceed_duration,exceed_duration_count\n");


    周期性读取黑名单 map
    while (!exiting)
    {
        __u32 key = 0, next_key;
        struct blacklist_val val;

        printf("=== Current Blacklisted IPs ===\n");
        while (bpf_map_get_next_key(map_fd, &key, &next_key) == 0)
        {
            if (bpf_map_lookup_elem(map_fd, &next_key, &val) == 0)
            {
                printf("IP: ");
                char ip_str[INET_ADDRSTRLEN];
                inet_ntop(AF_INET, &next_key, ip_str, sizeof(ip_str));
                printf("%s\n",ip_str);
            }
            key = next_key;
        }
        __u8 proto_key = 0, next_proto;
        struct proto_stat stat;
        // printf("=== Protocol Statistics ===\n");
        while (bpf_map_get_next_key(proto_map_fd, &proto_key, &next_proto) == 0)
        {
            if (bpf_map_lookup_elem(proto_map_fd, &next_proto, &stat) == 0)
            {
                const char *proto_name = (next_proto == PROTO_SYN) ? "SYN" : (next_proto == PROTO_UDP) ? "UDP"
                                                                         : (next_proto == PROTO_ICMP)  ? "ICMP"
                                                                                                       : "UNKNOWN";
                // printf("Protocol: %s | DynThreshold: %u Bps | byteCount: %u Bps | ExceedCount: %u\n",
                //     proto_name,
                //     stat.dyn_threshold,
                //     stat.byte_count,
                //     stat.exceed_count);
                // printf("EXCEED_DURATION: %u | EXCEED_DURATION_count: %u\n", stat.exceed_duration,stat.exceed_duration_count);
                time_t now = time(NULL);
                char timestr[64];
                strftime(timestr, sizeof(timestr), "%Y-%m-%d %H:%M:%S", localtime(&now));

                fprintf(fp, "%s,%s,%u,%u,%u,%u\n",
                        timestr,
                        proto_name,
                        stat.dyn_threshold,
                        stat.byte_count,
                        stat.exceed_duration,
                        stat.exceed_duration_count);
            }
            proto_key = next_proto;
        }
        fflush(fp);       // 每次手动刷新，确保立即写入磁盘   
        sleep(1);
        printf("------------1s------------\n");
    }
    fclose(fp);

cleanup:
    xdp_firewall_bpf__destroy(skel);
    return -1;
}
 

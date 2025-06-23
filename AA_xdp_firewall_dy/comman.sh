clang -O2 -target bpf -c ddos_filter.c -o ddos_filter.o

echo "==检查是否正确加载 eBPF=="
sudo bpftool prog show
# 检查 eBPF 统计信息
sudo bpftool map dump name ddos_map
# 观察 ddos_map 是否正确记录 IP 访问次数。


/opt/kafka/bin/kafka-console-producer.sh --bootstrap-server localhost:9092 --topic filteredlogs
/opt/kafka/bin/kafka-server-start.sh /opt/kafka/config/server.properties
/opt/kafka/bin/kafka-console-consumer.sh --bootstrap-server localhost:9092 --topic filteredlogs --from-beginning

# 如果你的 eBPF 代码依赖 bpf_helpers.h 但找不到正确的路径，可以手动生成：

# bash
# 复制代码
# bpftool btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h
# 然后在 ddos_filter.c 开头包含 vmlinux.h：

# c
# 复制代码
# #include "vmlinux.h"
# #include <bpf/bpf_helpers.h>
# 再尝试重新编译
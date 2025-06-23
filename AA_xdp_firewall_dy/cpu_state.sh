#!/bin/bash

NET_IF="ens33"
DURATION=1200  # 采集秒数
NET_CSV="net_stat.csv"
SYS_CSV="sys_cpu_stat.csv"

echo "timestamp,rx_bytes,tx_bytes" > $NET_CSV
echo "timestamp,total_cpu_percent" > $SYS_CSV

prev_rx=$(cat /sys/class/net/$NET_IF/statistics/rx_bytes)
prev_tx=$(cat /sys/class/net/$NET_IF/statistics/tx_bytes)

for ((i=0; i<$DURATION; i++)); do
    ts=$(date +%s)

    # 网络统计
    curr_rx=$(cat /sys/class/net/$NET_IF/statistics/rx_bytes)
    curr_tx=$(cat /sys/class/net/$NET_IF/statistics/tx_bytes)
    echo "$ts,$((curr_rx - prev_rx)),$((curr_tx - prev_tx))" >> $NET_CSV
    prev_rx=$curr_rx
    prev_tx=$curr_tx

    # 系统总 CPU 使用率
    cpu_usage=$(top -bn2 | grep "Cpu(s)" | tail -n 1 | awk '{print 100 - $8}')
    echo "$ts,$cpu_usage" >> $SYS_CSV

    sleep 1
done

echo "✅ 已完成系统资源采集"

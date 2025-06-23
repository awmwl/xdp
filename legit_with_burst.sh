!/bin/bash

TARGET_IP="192.168.254.142"
END_TIME=$((SECONDS + 900))  # 1500秒 = 25分钟

echo "[*] 开始随机合法流量模拟，目标IP: $TARGET_IP"

while [ $SECONDS -lt $END_TIME ]; do
    CHOICE=$((RANDOM % 4))
    if [ $CHOICE -eq 0 ]; then
        echo "[+] ICMP ping flood (short burst)"
        ping -c 10 -i 0.1 $TARGET_IP > /dev/null 2>&1 &
    elif [ $CHOICE -eq 1 ]; then
        echo "[+] UDP 流量"
        hping3 -2 $TARGET_IP -p 53 -d 120 -c 20 -i u10000 > /dev/null 2>&1 &
    elif [ $CHOICE -eq 2 ]; then
        echo "[+] TCP 流量 (iperf3)"
        iperf3 -c $TARGET_IP -t 5 -b 500K > /dev/null 2>&1 &
    else
        echo "[+] HTTP 请求"
        curl -s http://$TARGET_IP > /dev/null &
    fi

    # 等待 0.5 到 2 秒之间的随机时间
    sleep $(awk -v min=0.5 -v max=2 'BEGIN{srand(); print min+rand()*(max-min)}')
done

echo "[*] 流量模拟结束"

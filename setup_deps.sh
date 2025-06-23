#!/bin/bash

set -e

echo "[+] 更新 APT 软件包索引..."
sudo apt update

echo "[+] 安装 eBPF 编译和开发相关依赖..."
sudo apt install -y \
    clang llvm gcc apt-transport-https ca-certificates curl clang llvm jq \
      libelf-dev libpcap-dev libzstd-dev libbfd-dev binutils-dev build-essential make \
      linux-tools-common linux-tools-$(uname -r) python3-pip git pkg-config \
      zlib1g-dev libcap-dev libssl-dev dwarves pahole
sudo apt install -y zip bison build-essential cmake flex git libedit-dev \
  libllvm18 llvm-18-dev libclang-18-dev python3 zlib1g-dev libelf-dev libfl-dev python3-setuptools \
  liblzma-dev libdebuginfod-dev arping netperf iperf libpolly-18-dev

echo "[+] 所有依赖已安装完毕。"

# 📦 xdp\_ebpf\_ddos

An experimental framework for simulating and defending against DDoS attacks using kernel-level **eBPF/XDP**. Includes custom eBPF programs, traffic simulators, environment setup scripts, and supporting tools.

---

## 📁 Project Structure

```bash
xdp_ebpf/
├── .build/                      # Build artifacts (auto-generated, no manual edits required)
│   ├── bin/
│   │   └── bpftool              # Compiled bpftool binary
│   ├── bpftool/
│   │   └── bpftool              # Raw bpftool build output
│   └── libbpf/
│       ├── lib/
│       │   └── libbpf.a         # Static libbpf library
│       └── include/
│           └── ...              # eBPF headers (e.g., vmlinux.h, bpf_helpers.h)
├── Makefile                     # Main build entry for compiling eBPF object files
├── setup_deps.sh               # One-click script for building libbpf and bpftool
├── bcc/                         # (Optional) BCC-based tools or scripts
├── bpftool/                     # bpftool source directory
├── libbpf/                      # libbpf source directory
├── ddos_simulation_master/     # Tools for generating DDoS attacks (e.g., ICMP/UDP floods)
├── legit_with_burst.sh         # Simulates normal traffic with occasional bursts
├── AA_xdp_firewall_dy/         # Core directory containing custom eBPF firewall logic
```

---

## 🛠️ Getting Started

### 1️⃣ Install Dependencies

```bash
sudo apt update
sudo apt install -y clang llvm gcc make iproute2 libelf-dev libbpf-dev linux-headers-$(uname -r)
```

### 2️⃣ Build libbpf and bpftool

```bash
./setup_deps.sh
make
```

### 3️⃣ Compile the eBPF Defense Program (default interface: `ens33`, can be customized)

```bash
cd AA_xdp_firewall_dy
make
./xdp_firewall
```

### 4️⃣ Attach XDP Program (or run commands manually from Makefile)

```bash
sudo ip link set dev eth0 xdp obj AA_xdp_firewall_dy/xdp_firewall.bpf.o sec xdp
```

---

## 🎯 Simulation Guide

* `ddos_simulation_master/`: Simulated DDoS attack generators (e.g., UDP/ICMP floods)
* `legit_with_burst.sh`: Emulates legitimate traffic with occasional spikes
* `AA_xdp_firewall_dy/`: Core defense logic with dynamic thresholding (DEWS) and probabilistic reaction (PGDR)

---

## 📌 Notes

* This project is intended for **research and educational purposes**, demonstrating how eBPF/XDP can be used for lightweight kernel-space DDoS mitigation.
* For production use, consider integrating with a **user-space control plane**, **security policy manager**, and **logging system**.

---


## ✨ Acknowledgements

Built using:

* [libbpf](https://github.com/libbpf/libbpf)
* [bpftool](https://github.com/libbpf/bpftool)
* [ddos_simulation](https://github.com/ricardojoserf/ddos_simulation/tree/master)



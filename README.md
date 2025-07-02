xdp_ebpf/
├── .build/
│   ├── bin/
│   │   └── bpftool          # 编译完成后的可执行文件
│   ├── bpftool/
│   │   └── bpftool          # 原始 bpftool 编译输出
│   └── libbpf/
│       ├── lib/
│       │   └── libbpf.a     # 编译生成的静态库
│       └── include/
│           └── ...          # 所有 bpf 所需头文件
├── Makefile                 # 编译环境
├── setup_deps.sh            # 环境所需依赖                             
├── bcc              
├── bpftool 
├── libbpf 
├── ddos_simulation_master   # DDoS模拟工具
├── legit_with_burst.sh      # 正常通信模拟脚本  
├── AA_xdp_firewall_dy       

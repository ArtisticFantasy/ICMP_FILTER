#!/bin/bash
sudo apt install clang libbpf-dev

# Build the BPF program
PROJ_DIR = $(dirname $(realpath $0))
bpftool btf dump file vmlinux.btf format c > $PROJ_DIR/include/vmlinux.h
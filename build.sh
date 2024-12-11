#!/bin/bash
sudo apt install clang libbpf-dev

# Build the BPF program
PROJ_DIR=$(dirname $(realpath $0))
cd $PROJ_DIR && make
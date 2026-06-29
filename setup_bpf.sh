#!/bin/bash
# setup_bpf.sh - Versão com Limpeza Forçada de Interface
set -e

CONTAINER="clab-lab-ebpf-gateway"
IFACE="eth1"
BPF_DIR="/sys/fs/bpf/iot_automaton"
LAB_PATH="/lab/automato.o" 

echo "[1/4] Compilando automato.c (Host)..."
clang -O2 -g -target bpf -c automato.c -o automato.o

echo "[2/4] Forçando remoção e reinicialização da interface (Kernel)..."
# 1. Derruba a interface temporariamente para liberar o lock do driver genérico
docker exec $CONTAINER ip link set dev $IFACE down || true

# 2. Remove o vínculo antigo diretamente no driver/kernel
docker exec $CONTAINER bpftool net detach xdpgeneric dev $IFACE 2>/dev/null || true
docker exec $CONTAINER bpftool net detach xdp dev $IFACE 2>/dev/null || true
docker exec $CONTAINER rm -rf $BPF_DIR 2>/dev/null || true

# 3. Sobe a interface novamente limpa
docker exec $CONTAINER ip link set dev $IFACE up || true

echo "[3/4] Preparando BPF FS e exportando mapas..."
docker exec $CONTAINER bash -c "mkdir -p /sys/fs/bpf && mount -t bpf bpf /sys/fs/bpf/ 2>/dev/null || true"
docker exec $CONTAINER mkdir -p $BPF_DIR
docker exec $CONTAINER bpftool prog load $LAB_PATH $BPF_DIR/prog type xdp pinmaps $BPF_DIR/maps

echo "[4/4] Vinculando novo programa XDP à interface $IFACE..."
docker exec $CONTAINER bpftool net attach xdpgeneric pinned $BPF_DIR/prog dev $IFACE

echo "[✓] Sucesso! Novo programa com suporte a APPROVED/REJECTED carregado."

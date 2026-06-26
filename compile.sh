#!/bin/bash
# compile.sh - Script para compilar o código eBPF
echo "[*] Compilando xdp_monitor.c para bytecode BPF..."
clang -O2 -target bpf -c xdp_monitor.c -o xdp_monitor.o

if [ $? -eq 0 ]; then
    echo "[✓] Sucesso! xdp_monitor.o gerado."
else
    echo "[✗] Erro na compilação. Verifique os includes."
    exit 1
fi

#!/usr/bin/env python3
from bcc import BPF
import time
import sys

# 1. Definição dos mesmos IDs usados no código C
STATE_Q0 = 0
STATE_Q1 = 1
STATE_QERR = 2

EVENT_CONNECT = 1
EVENT_PUBLISH = 2
EVENT_DISCONNECT = 3
EVENT_ERROR = 4

interface = "eth0" if len(sys.argv) < 2 else sys.argv[1]

print(# Traduzindo a tabela matemática para o dicionário do Python
f"[+] Carregando o código eBPF e anexando à interface {interface}...")

# 2. Inicializa o BCC apontando para o seu arquivo de código C
b = BPF(src_file="iot_monitor.c")
fn = b.load_func("iot_automaton_monitor", BPF.XDP)
b.attach_xdp(interface, fn, 0)

# 3. Obtém a referência para o mapa de transição do Kernel
transition_table = b.get_table("map_transition_table")

# 4. Popula a Matriz Delta \delta(estado_atual, evento) = proximo_estado
# Formato: transition_table[ transition_table.Key(estado, evento) ] = proximo_estado

# Regras a partir de Q0 (Inicial)
transition_table[transition_table.Key(STATE_Q0, EVENT_CONNECT)] = STATE_Q1
transition_table[transition_table.Key(STATE_Q0, EVENT_PUBLISH)] = STATE_QERR
transition_table[transition_table.Key(STATE_Q0, EVENT_DISCONNECT)] = STATE_Q0
transition_table[transition_table.Key(STATE_Q0, EVENT_ERROR)] = STATE_QERR

# Regras a partir de Q1 (Autenticado)
transition_table[transition_table.Key(STATE_Q1, EVENT_CONNECT)] = STATE_QERR
transition_table[transition_table.Key(STATE_Q1, EVENT_PUBLISH)] = STATE_Q1
transition_table[transition_table.Key(STATE_Q1, EVENT_DISCONNECT)] = STATE_Q0
transition_table[transition_table.Key(STATE_Q1, EVENT_ERROR)] = STATE_QERR

print("[+] Matriz do Autômato (AI Safety Guardrail) injetada com sucesso no Kernel!")
print("[+] Monitoramento ativo. Pressione Ctrl+C para encerrar.")

# 5. Loop para manter o programa rodando e ler logs do bpf_printk
try:
    while True:
        # Lê as mensagens do bpf_printk enviadas pelo Kernel (ex: violações)
        (task, pid, cpu, flags, ts, msg) = b.trace_fields()
        print(f"   [KERNEL LOG] {msg.decode('utf-8')}")
except KeyboardInterrupt:
    print("\n[-] Removendo monitor eBPF...")
    b.remove_xdp(interface, 0)

#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <bpf/bpf_helpers.h>
#include "ebpf_defs.h"

SEC("xdp")
int iot_automaton_monitor(struct xdp_md *ctx) {
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;

    // 1. Camada Ethernet
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end) return XDP_PASS;
    if (eth->h_proto != __constant_htons(ETH_P_IP)) return XDP_PASS;

    // 2. Camada IP
    struct iphdr *ip = (void *)(eth + 1);
    if ((void *)(ip + 1) > data_end) return XDP_PASS;
    
    // Filtra para analisar apenas pacotes TCP (onde roda o MQTT tradicional)
    if (ip->protocol != IPPROTO_TCP) return XDP_PASS;
    __be32 src_ip = ip->saddr;

    // 3. Camada TCP
    struct tcphdr *tcp = (void *)(ip + 1);
    if ((void *)(tcp + 1) > data_end) return XDP_PASS;

    // Filtra pela porta padrão do MQTT (1883) para economizar processamento
    if (tcp->dest != __constant_htons(1883)) return XDP_PASS;

    // 4. Identificação do Evento MQTT (Simplificado para o artigo)
    // O cabeçalho fixo do MQTT começa logo após o cabeçalho TCP
    __u8 *mqtt_header = (__u8 *)tcp + (tcp->doff * 4);
    if ((void *)(mqtt_header + 1) > data_end) return XDP_PASS;

    // O tipo de pacote MQTT fica nos 4 bits mais significativos do primeiro byte
    __u8 mqtt_type = (*mqtt_header) >> 4;
    __u32 current_event = EVENT_ERROR;

    if (mqtt_type == 1)      current_event = EVENT_CONNECT;
    else if (mqtt_type == 3) current_event = EVENT_PUBLISH;
    else if (mqtt_type == 14) current_event = EVENT_DISCONNECT;
    else                     current_event = EVENT_ERROR;

    // 5. Execução do Autômato
    // Busca o estado atual do dispositivo
    __u32 *state_ptr = bpf_map_lookup_elem(&map_session_state, &src_ip);
    __u32 current_state = state_ptr ? *state_ptr : STATE_Q0; // Se não achar, assume q0

    // Se o dispositivo já estiver no estado de erro/bloqueio, dropa imediatamente
    if (current_state == STATE_QERR) {
        return XDP_DROP;
    }

    // Consulta a função de transição \delta(current_state, current_event)
    struct transition_key trans_key = {
        .current_state = current_state,
        .event = current_event
    };
    
    __u32 *next_state_ptr = bpf_map_lookup_elem(&map_transition_table, &trans_key);
    __u32 next_state = next_state_ptr ? *next_state_ptr : STATE_QERR; // Se não houver transição, vai para erro

    // Atualiza o estado do dispositivo na tabela de sessões
    bpf_map_update_elem(&map_session_state, &src_ip, &next_state, BPF_ANY);

    // Se a transição resultou em Estado de Erro, barra o pacote
    if (next_state == STATE_QERR) {
        bpf_printk("AI Safety Violation! IP %pI4 blocked.\n", &src_ip);
        return XDP_DROP;
    }

    // Comportamento seguro: permite a passagem do pacote para o Broker MQTT
    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";

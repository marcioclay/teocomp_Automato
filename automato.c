#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <bpf/bpf_endian.h>

// Estados do Autômato
#define Q0 0   // Estado Inicial / Desconectado
#define Q1 1   // Conectado
#define QERR 2 // Estado de Erro (Violação)

// Tipos MQTT (Fixed Header)
#define MQTT_CONNECT 0x10
#define MQTT_PUBLISH 0x30
#define MQTT_DISCONNECT 0xE0

struct session_state {
    __u8 current_state;
};

// Mapa de sessão: IP -> Estado
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 8192);
    __type(key, __u32);
    __type(value, struct session_state);
} map_session_state SEC(".maps");

SEC("xdp")
int xdp_monitor_prog(struct xdp_md *ctx) {
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;

    // 1. Parsing Básico (Camadas 2, 3 e 4)
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end) return XDP_PASS;
    if (eth->h_proto != bpf_htons(ETH_P_IP)) return XDP_PASS;

    struct iphdr *iph = data + sizeof(struct ethhdr);
    if ((void *)(iph + 1) > data_end) return XDP_PASS;
    if (iph->protocol != 6) return XDP_PASS; // Apenas TCP

    int ip_hdr_len = iph->ihl * 4;
    struct tcphdr *tcp = (void *)iph + ip_hdr_len;
    if ((void *)tcp + sizeof(struct tcphdr) > data_end) return XDP_PASS;

    // Filtra porta 1883 (MQTT)
    if (tcp->dest != bpf_htons(1883)) return XDP_PASS;

    // 2. Extração do Tipo de Mensagem MQTT
    void *payload = (void *)tcp + (tcp->doff * 4);
    if (payload + 1 > data_end) return XDP_PASS;
    __u8 mqtt_type = *(unsigned char *)payload & 0xF0;

    // 3. Lógica de Autômato
    __u32 src_ip = iph->saddr;
    struct session_state *state = bpf_map_lookup_elem(&map_session_state, &src_ip);
    __u8 current = state ? state->current_state : Q0;
    __u8 next_state = current;

    // Tabela de Transição (Matriz Lógica)
    if (current == Q0 && mqtt_type == MQTT_CONNECT) {
        next_state = Q1;
    } else if (current == Q1 && mqtt_type == MQTT_PUBLISH) {
        next_state = Q1;
    } else if (current == Q1 && mqtt_type == MQTT_DISCONNECT) {
        next_state = Q0;
    } else {
        // Qualquer outra combinação resulta em erro de protocolo/ataque
        next_state = QERR;
    }

    // 4. Decisão Final
    if (next_state == QERR) {
        return XDP_DROP; // Bloqueio conforme Seção 4.3
    } else {
        struct session_state new_state = { .current_state = next_state };
        bpf_map_update_elem(&map_session_state, &src_ip, &new_state, BPF_ANY);
        return XDP_PASS;
    }
}

char _license[] SEC("license") = "GPL";

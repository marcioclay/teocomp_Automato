#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <bpf/bpf_endian.h>

// Definições dos Estados e Eventos
#define STATE_Q0 0
#define STATE_Q1 1
#define STATE_QERR 2

#define EVENT_CONNECT 1
#define EVENT_PUBLISH 2
#define EVENT_DISCONNECT 3

// Estrutura para a chave do mapa de transição (Estado + Evento)
struct transition_key {
    __u32 state;
    __u32 event;
};

struct session_state {
    __u8 current_state;
};

// Mapas (Devem ser os mesmos nomes definidos no seu script Python)
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 8192);
    __type(key, __u32);
    __type(value, struct session_state);
} map_session_state SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 256);
    __type(key, struct transition_key);
    __type(value, __u32); // Próximo estado
} map_transition_table SEC(".maps");

SEC("xdp")
int iot_automaton_monitor(struct xdp_md *ctx) {
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;

    // Parsing básico para chegar ao MQTT
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end) return XDP_PASS;
    struct iphdr *iph = data + sizeof(struct ethhdr);
    if ((void *)(iph + 1) > data_end) return XDP_PASS;
    if (iph->protocol != 6) return XDP_PASS;

    struct tcphdr *tcp = (void *)iph + (iph->ihl * 4);
    if ((void *)tcp + sizeof(struct tcphdr) > data_end) return XDP_PASS;
    if (tcp->dest != bpf_htons(1883)) return XDP_PASS;

    // Identificação do Evento MQTT
    void *payload = (void *)tcp + (tcp->doff * 4);
    if (payload + 1 > data_end) return XDP_PASS;
    __u8 mqtt_type = *(unsigned char *)payload & 0xF0;

    __u32 event;
    if (mqtt_type == 0x10) event = EVENT_CONNECT;
    else if (mqtt_type == 0x30) event = EVENT_PUBLISH;
    else if (mqtt_type == 0xE0) event = EVENT_DISCONNECT;
    else return XDP_PASS;

    // Lógica do Autômato via Mapas
    __u32 src_ip = iph->saddr;
    struct session_state *st = bpf_map_lookup_elem(&map_session_state, &src_ip);
    __u32 current = st ? st->current_state : STATE_Q0;

    struct transition_key key = { .state = current, .event = event };
    __u32 *next_state = bpf_map_lookup_elem(&map_transition_table, &key);

    if (next_state) {
        if (*next_state == STATE_QERR) {
            return XDP_DROP; // Bloqueio conforme artigo
        } else {
            struct session_state new_st = { .current_state = (__u8)*next_state };
            bpf_map_update_elem(&map_session_state, &src_ip, &new_st, BPF_ANY);
            return XDP_PASS;
        }
    }

    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";

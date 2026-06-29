#include <linux/bpf.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/if_ether.h>  // OBRIGATÓRIO: Define struct ethhdr e ETH_P_IP
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>   // Recomendado para manipulação de bytes (bpf_htons)



#define MQTT_PORT 1883

// Definição dos Estados do Autómato
#define STATE_Q0   0  // Desconectado (Estado Inicial)
#define STATE_Q1   1  // Autenticado / Conectado
#define STATE_QERR 2  // Estado de Erro (Bloqueio Permanente)

// Estruturas de Chaves e Valores para os Mapas BPF
struct transition_key {
    __u32 state;
    __u32 event;
};

struct session_state {
    __u8 current_state;
};

// MAPA 1: Matriz de Transição Estática (Preenchida pelo Python)
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 64);
    __type(key, struct transition_key);
    __type(value, __u32);
} map_transition_table SEC(".maps");

// MAPA 2: Tabela Dinâmica de Estados por IP do Cliente
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, __be32); // IP de Origem
    __type(value, struct session_state);
} map_session_state SEC(".maps");

SEC("xdp")
int iot_automaton_monitor(struct xdp_md *ctx) {
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;

    // 1. Decodificação da Camada de Enlace (Ethernet)
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;

    if (eth->h_proto != __constant_htons(ETH_P_IP))
        return XDP_PASS;

    // 2. Decodificação da Camada de Rede (IPv4)
    struct iphdr *iph = data + sizeof(struct ethhdr);
    if ((void *)(iph + 1) > data_end)
        return XDP_PASS;

    if (iph->protocol != IPPROTO_TCP)
        return XDP_PASS;

    // 3. Decodificação da Camada de Transporte (TCP)
    struct tcphdr *tcph = (void *)iph + iph->ihl * 4;
    if ((void *)(tcph + 1) > data_end)
        return XDP_PASS;

    // Filtra apenas tráfego direcionado ao Broker MQTT (Porta 1883)
    if (tcph->dest != __constant_htons(MQTT_PORT))
        return XDP_PASS;

    // 4. Localização do Payload da Aplicação (MQTT)
    __u8 *payload = (__u8 *)tcph + tcph->doff * 4;
    if ((void *)(payload + 1) > data_end)
        return XDP_PASS;

    // Extrai o tipo de mensagem MQTT (4 bits mais significativos do primeiro byte)
    __u8 mqtt_type = payload[0] >> 4;
    __u32 event = (__u32)mqtt_type;

    // Ignora pacotes de controle TCP puros (como o handshake SYN/ACK sem payload)
    if (event == 0)
        return XDP_PASS;

    // 5. Motor de Inferência do Autómato de Estados
    __be32 src_ip = iph->saddr;
    struct session_state *st = bpf_map_lookup_elem(&map_session_state, &src_ip);
    __u32 current = st ? st->current_state : STATE_Q0;

    // Se o nó já estiver marcado em estado de erro, aplica o drop imediato
    if (current == STATE_QERR) {
        char msg_drop[] = "REJECTED: No imobilizado em QERR!";
        bpf_trace_printk(msg_drop, sizeof(msg_drop));
        return XDP_DROP;
    }

    // Consulta a tabela para verificar se a transição é permitida
    struct transition_key key = { .state = current, .event = event };
    __u32 *next_state = bpf_map_lookup_elem(&map_transition_table, &key);

    if (next_state) {
        if (*next_state == STATE_QERR) {
            // Emite log de violação de segurança capturado pelo Python
            char msg_err[] = "REJECTED: Transicao ilegal detectada!";
            bpf_trace_printk(msg_err, sizeof(msg_err));

            // Atualiza o estado do nó para QERR na memória RAM
            struct session_state err_st = { .current_state = STATE_QERR };
            bpf_map_update_elem(&map_session_state, &src_ip, &err_st, BPF_ANY);
            return XDP_DROP;
        } else {
            // Emite log de conformidade normativa
            char msg_ok[] = "APPROVED: Transicao valida!";
            bpf_trace_printk(msg_ok, sizeof(msg_ok));

            // Avança o estado do dispositivo na tabela
            struct session_state next_st = { .current_state = (__u8)*next_state };
            bpf_map_update_elem(&map_session_state, &src_ip, &next_st, BPF_ANY);
            return XDP_PASS;
        }
    }

    // Comportamento Padrão: Pacotes MQTT não previstos na matriz básica caem aqui (ex: SUBSCRIBE)
    char msg_default[] = "REJECTED: Comando nao mapeado no automato!";
    bpf_trace_printk(msg_default, sizeof(msg_default));
    
    struct session_state def_err = { .current_state = STATE_QERR };
    bpf_map_update_elem(&map_session_state, &src_ip, &def_err, BPF_ANY);
    return XDP_DROP;
}

char _license[] SEC("license") = "GPL";




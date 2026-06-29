## 🐝 Protótipo de topologia com XDP/eBPF orquestrado por Containerlab para mitigar conexões anômalo entre sensor e MQTT.

> Protótipo de e deteção e mitigação usando **eBPF/XDP** em ambiente de rede virtualizado com **Containerlab**.

[![Containerlab](https://img.shields.io/badge/Containerlab-v0.50+-blue?logo=linux)](https://containerlab.dev)
[![Docker](https://img.shields.io/badge/Docker-required-blue?logo=docker)](https://www.docker.com)
[![eBPF](https://img.shields.io/badge/eBPF-XDP-orange)](https://ebpf.io)
[![Licença](https://img.shields.io/badge/licença-GPL--2.0-green)](LICENSE)
[![Linguagem](https://img.shields.io/badge/linguagem-C-blue)](https://en.wikipedia.org/wiki/C_(programming_language))
[![OS](https://img.shields.io/badge/OS-Ubuntu-orange)](https://ubuntu.com/)


---

## 🚀 O que este protótipo demonstra
- **[Modelagem de Estados](ca://s?q=Modelagem_de_estados_em_automatos):** representação explícita de estados e transições.  
- **[Reconhecimento de Linguagens](ca://s?q=Reconhecimento_de_linguagens_formais):** validação de cadeias de símbolos conforme gramática.  
- **[Implementação em C](ca://s?q=Automato_em_C):** manipulação de tabelas de transição e execução eficiente.  
- **[Visualização de Fluxo](ca://s?q=Fluxograma_de_automato):** diagramas que ilustram o comportamento do autômato.  
- **[Aplicação Didática](ca://s?q=Aplicacao_didatica_de_automatos):** integração entre eBPF/xdp, automato determnisticos e containers.  
---


Guia de Execução do Protótipo
Este guia descreve os passos necessários para compilar o plano de dados eBPF/XDP, orquestrar a topologia de rede via Containerlab e validar o monitoramento do autômato de estados em tempo real.

 Pré-requisitos
Antes de iniciar, certifique-se de ter os seguintes componentes instalados na sua máquina Host (Linux ou WSL2):


- Docker

- Containerlab

- Clang e LLVM (para compilação do código BPF)

- Python 3 com a biblioteca BCC (python3-bpfcc)


   Passo 1: Inicializar a Topologia de Rede
Navegue até a raiz e inicie a topologia:

```
sudo containerlab deploy --topo topo.yaml
```

Este comando criará o switch virtual (clab-bridge), o gateway de borda (clab-gateway) e os dois nós agentes (clab-sensor e clab-atacante).

 Passo 2: Compilar e Injetar o Programa XDP
Execute o script de automação para compilar o código em C do autômato e vinculá-lo à interface de rede do gateway:
```
sudo chmod +x setup_bpf.sh
sudo ./setup_bpf.sh
```

 Passo 3: Inicializar o Dashboard de Monitoramento (Terminal 1)
Terminal host, execute o painel em Python para carregar a matriz de transições nos mapas eBPF e iniciar a coleta de traços do Kernel:

```
sudo python3 leitor.py
```
A tela será limpa e o dashboard exibirá o estado inicial estático:

[ Q0 (Desconectado) ] ───( Aguardando Tráfego )───> [ Q0 ] 

##  Passo 4: Executar os Cenários de Teste (Terminal 2)

Abra uma nova aba ou janela de terminal para interagir com os nós da rede.

###  Cenário A: Fluxo Legítimo (Handshake + Telemetria)

Dispare o script do sensor de dentro do contêiner isolado:

```
docker exec -it clab-lab-ebpf-sensor python3 /src/sensor.py
```
O que observar:

O sensor enviará o pacote CONNECT e fará uma pausa programada de 10 segundos.

No Terminal 1, o dashboard capturará o evento instantaneamente e travará na transição de handshake legítimo:

```
[ Q0 (Desconectado) ] ───( CONNECT Autorizado )───> [ ✅ Q1 (Autenticado) ]
```
Após a pausa, o sensor começará a enviar telemetrias PUBLISH contínuas, mantendo o estado estabilizado em Q1 → Q1. 

Cenário B: Mitigação de Ataque por Injeção de Estado

Abra o terminal do nó atacante e tente forçar o envio de dados sem realizar uma conexão prévia:
```
docker exec -it clab-lab-ebpf-atacante python3 /src/atacante.py
```

O que observar:

- O autômato detectará a quebra da gramática a partir do estado Q0.

- O pacote será descartado via XDP_DROP na placa de rede.

- O dashboard exibirá o bloqueio imediato:
  
```
  [ Q0 (Desconectado) ] ───( PUBLISH Sem Handshake )───> [ 🚨 QERR (DROP) ]
```

Cenário C: Mitigação de Abuso por Duplo Handshake

Mantenha o sensor legítimo do cenário A ativo e autenticado (Q!), force o envio de um novo pacote redunte em outro terminal.

```
docker exec -it clab-lab-ebpf-sensor python3 /src/sensor.py
```

O que observar:

- O Kernel interceptará o desvio comportamental de sessão duplicada.

- Todo o tráfego subsequente será dropado:
```
  [ Q1 (Autenticado) ] ───( Duplo CONNECT Detectado )───> [ 🚨 QERR (DROP) ]
```







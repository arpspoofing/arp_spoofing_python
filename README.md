# 🔴 Simulação de um ataque DoS em rede local utilizando ARP Spoofing e um algoritmo Python 


![Python](https://img.shields.io/badge/Python-3.x-blue?style=for-the-badge&logo=python&logoColor=white)
![Scapy](https://img.shields.io/badge/Scapy-ARP-red?style=for-the-badge)
![License](https://img.shields.io/badge/Uso-Educacional-yellow?style=for-the-badge)

Ferramenta educacional de ataque ARP Spoofing bidirecional em redes locais, com suporte a modo **DoS** (negação de serviço) e modo **MitM** (interceptação de tráfego). Inclui descoberta automática de hosts, monitoramento contínuo de novos dispositivos e verificador de eficácia do ataque em tempo real.

> ⚠️ **AVISO**: Esta ferramenta foi desenvolvida exclusivamente para fins educacionais e testes em ambientes controlados e autorizados. O uso em redes sem permissão explícita é ilegal.

---

## 📖 Como Funciona

O ARP Spoofing explora a ausência de autenticação no protocolo ARP: ao enviar respostas ARP falsas para a vítima e para o gateway, o atacante se posiciona no meio da comunicação (MitM) ou a interrompe completamente (DoS).

```
Vítima  <──── ARP falso (gateway = MAC atacante) ────>  Atacante
Gateway <──── ARP falso (vítima = MAC atacante)  ────>  Atacante
```

**Modo DoS** (`--no-forward`): pacotes da vítima chegam ao atacante e são descartados — conexão cai.  
**Modo MitM** (`--forward`): IP Forwarding habilitado — tráfego é repassado e pode ser inspecionado.

---

## ✨ Funcionalidades

- 🔍 **Varredura ARP inicial** — descobre todos os hosts ativos na rede
- 🔄 **Monitoramento contínuo** — detecta novos dispositivos conectados e os adiciona automaticamente como alvos
- ⚡ **Spoofing bidirecional dinâmico** — envenena vítima e gateway simultaneamente via `arpspoof`
- 🩺 **Health Check** — verifica ciclicamente se o ataque está funcionando para cada alvo
- 🔧 **Controle de IP Forwarding** — alterna entre modo DoS e modo MitM por argumento
- 🛡️ **Auto-proteção** — exclui automaticamente o próprio IP e o gateway da lista de alvos

---

## 🛠️ Requisitos

**Sistema operacional:** Linux (requer permissão root)

**Dependências do sistema:**

```bash
apt install dsniff  # fornece o comando arpspoof
```

**Dependências Python:** (instaladas via `requirements.txt` na venv)

---

## 🚀 Instalação e Uso

### 1️⃣ Criar e ativar a venv

```bash
python3 -m venv venv
source venv/bin/activate
```

### 2️⃣ Instalar dependências

```bash
pip install -r requirements.txt
```

### 3️⃣ Executar a ferramenta

```bash
sudo venv/bin/python3 main.py [OPÇÕES]
```

### Opções

| Argumento         | Descrição                                                   |
|-------------------|-------------------------------------------------------------|
| `--no-forward`    | Desabilita IP Forwarding — **modo DoS** (padrão recomendado) |
| `--forward`       | Habilita IP Forwarding — **modo MitM** (interceptação)      |

### Exemplos Completos

```bash
# Setup inicial
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt

# Ataque DoS contra todos os hosts da LAN
sudo venv/bin/python3 main.py --no-forward

# Interceptação (MitM) de tráfego
sudo venv/bin/python3 main.py --forward
```

---

## 📊 Saída Esperada

```
=== INFORMAÇÕES DA LAN ===
Interface Ativa:  eth0
Seu IP Local:     192.168.1.100
Gateway/Roteador: 192.168.1.1
==========================

[*] Realizando varredura ARP inicial na rede...
[+] 3 alvos iniciais qualificados encontrados.
 -> 192.168.1.105
 -> 192.168.1.110
 -> 192.168.1.120

[*] Monitor de novos hosts iniciado (Intervalo: 10s)...
[*] Verificador de integridade do Spoofing ativo (Intervalo: 8s)...
[*] Mecanismo dinâmico de Spoofing operacional.
[+] Iniciando arpspoof bidirecional contra: 192.168.1.105

=== STATUS DO ATAQUE ARP (HEALTH CHECK) ===
 Alvo: 192.168.1.105   -> Status: SUCESSO (Tráfego roteado via atacante)
 Alvo: 192.168.1.110   -> Status: SEM TRÁFEGO / INCONCLUSIVO
===========================================
```

---

## 🏗️ Arquitetura

```
dos_lan/
├── main.py          # Script principal
├── ips.txt          # Log dos IPs alvo (gerado em tempo de execução)
└── README.md        # Este arquivo
```

### Threads em execução

| Thread                   | Função                                                    | Intervalo |
|--------------------------|-----------------------------------------------------------|-----------|
| `monitor_new_hosts`      | Escaneia a rede por novos dispositivos                   | 10s       |
| `health_check_spoofing`  | Valida se o envenenamento ARP está ativo em cada alvo    | 8s        |
| `dynamic_arp_spoofing`   | Gerencia processos `arpspoof` bidirecionais (loop principal) | 2s    |

---

## ⚙️ Detalhes Técnicos

- **Descoberta de hosts:** pacotes ARP broadcast (`ff:ff:ff:ff:ff:ff`) via Scapy `srp()`
- **Verificação de eficácia:** sniff passivo filtrando pacotes IP cujo MAC de destino seja o do atacante
- **Spoofing bidirecional:** dois processos `arpspoof` por alvo — um para a vítima, um para o gateway
- **Thread safety:** `threading.Lock()` protege o conjunto `active_spoof_ips` e o dicionário de processos
- **Encerramento limpo:** `CTRL+C` termina todos os processos `arpspoof` ativos antes de sair

---

## ⚠️ Avisos de Segurança

- ❌ **NÃO** utilize em redes públicas ou corporativas sem autorização
- ❌ **NÃO** utilize contra sistemas de terceiros
- ✅ Use apenas em laboratório próprio ou com permissão explícita por escrito
- ✅ Prefira ambientes isolados (VMs, redes NAT internas)

---

## 📝 Licença

Desenvolvido para fins educacionais. Use por sua conta e risco.

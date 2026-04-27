"""
shared/crypto.py — Módulo de criptografia compartilhado
Usa cifração simétrica com HMAC-SHA256 para autenticidade e confidencialidade.
Sem dependências externas — apenas biblioteca padrão do Python.

NOTA EDUCACIONAL: Em produção, use bibliotecas como 'cryptography' ou
'PyCryptodome' para cifração AES real. Este módulo usa PBKDF2+XOR como
stream cipher para fins didáticos sem dependências externas.
"""

import os
import hmac
import hashlib
import struct


# ─── Constantes ───────────────────────────────────────────────────────────────

KEY_SIZE  = 32   # 256 bits
HMAC_SIZE = 32   # SHA-256
BLOCK     = 64   # tamanho do bloco do stream cipher


# ─── Derivação de chaves ──────────────────────────────────────────────────────

def derive_keys(password: str) -> tuple:
    """
    Deriva duas chaves a partir de uma senha compartilhada:
      enc_key — chave de cifração
      mac_key — chave de autenticação (HMAC)
    Usa PBKDF2-HMAC-SHA256 com 100.000 iterações.
    """
    salt = b"mini-c2-edu-salt-v1"
    material = hashlib.pbkdf2_hmac(
        "sha256", password.encode(), salt, 100_000, dklen=KEY_SIZE * 2
    )
    return material[:KEY_SIZE], material[KEY_SIZE:]


# ─── Stream cipher baseado em PBKDF2 ─────────────────────────────────────────

def _keystream(key: bytes, nonce: bytes, length: int) -> bytes:
    """Gera keystream determinístico a partir de key+nonce."""
    stream = b""
    counter = 0
    while len(stream) < length:
        block = hashlib.pbkdf2_hmac(
            "sha256", key, nonce + counter.to_bytes(4, "big"), 1, dklen=BLOCK
        )
        stream += block
        counter += 1
    return stream[:length]


def _xor_cipher(data: bytes, key: bytes, nonce: bytes) -> bytes:
    """Cifra/decifra via XOR com keystream."""
    ks = _keystream(key, nonce, len(data))
    return bytes(a ^ b for a, b in zip(data, ks))


# ─── API pública ──────────────────────────────────────────────────────────────

def encrypt(data: bytes, enc_key: bytes, mac_key: bytes) -> bytes:
    """
    Cifra e autentica dados.
    Formato do pacote: NONCE(16) | CIPHERTEXT | HMAC(32)
    """
    nonce      = os.urandom(16)
    ciphertext = _xor_cipher(data, enc_key, nonce)
    tag        = hmac.new(mac_key, nonce + ciphertext, hashlib.sha256).digest()
    return nonce + ciphertext + tag


def decrypt(data: bytes, enc_key: bytes, mac_key: bytes) -> bytes:
    """
    Verifica HMAC e decifra dados.
    Lança ValueError se a autenticação falhar (pacote adulterado).
    """
    if len(data) < 16 + HMAC_SIZE:
        raise ValueError("Pacote muito curto")
    nonce      = data[:16]
    ciphertext = data[16:-HMAC_SIZE]
    tag_recv   = data[-HMAC_SIZE:]
    tag_calc   = hmac.new(mac_key, nonce + ciphertext, hashlib.sha256).digest()
    if not hmac.compare_digest(tag_recv, tag_calc):
        raise ValueError("Autenticação falhou — pacote inválido ou adulterado")
    return _xor_cipher(ciphertext, enc_key, nonce)


# ─── Framing de pacotes ───────────────────────────────────────────────────────

def encode_packet(payload: bytes) -> bytes:
    """Serializa pacote com length-prefix de 4 bytes (big-endian)."""
    return struct.pack(">I", len(payload)) + payload


def recv_packet(sock) -> bytes:
    """Lê exatamente um pacote do socket (bloqueante)."""
    raw_len = _recv_exact(sock, 4)
    length  = struct.unpack(">I", raw_len)[0]
    if length > 10 * 1024 * 1024:  # limite de 10 MB
        raise ValueError(f"Pacote muito grande: {length} bytes")
    return _recv_exact(sock, length)


def _recv_exact(sock, n: int) -> bytes:
    """Lê exatamente n bytes do socket."""
    buf = b""
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise ConnectionError("Conexão encerrada pelo par")
        buf += chunk
    return buf

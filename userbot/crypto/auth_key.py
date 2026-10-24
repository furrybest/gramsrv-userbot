"""auth_key / msg_key / AES key & IV для MTProto 2.0.

Формулы взяты из официальной спеку (core.telegram.org/mtproto/description):

    msg_key_large = SHA256(substr(auth_key, 88+x, 32) + plaintext + random_padding)
    msg_key       = substr(msg_key_large, 8, 16)
    sha256_a      = SHA256(msg_key + substr(auth_key, x, 36))
    sha256_b      = SHA256(substr(auth_key, 40+x, 36) + msg_key)
    aes_key       = substr(sha256_a, 0, 8) + substr(sha256_b, 8, 16) + substr(sha256_a, 24, 8)
    aes_iv        = substr(sha256_b, 0, 8) + substr(sha256_a, 8, 16) + substr(sha256_b, 24, 8)

где x = 0 для клиент->сервер и x = 8 для сервер->клиент.

auth_key_id = младшие 8 байт SHA1(auth_key), little-endian.
"""

import struct
from hashlib import sha1, sha256

AUTH_KEY_LEN = 256


def auth_key_id(auth_key: bytes) -> bytes:
    """key_id - последние 8 байт SHA1(auth_key) (little-endian, 8 байт)."""
    if len(auth_key) != AUTH_KEY_LEN:
        raise ValueError("auth_key must be 256 bytes")
    return sha1(auth_key).digest()[-8:]


def compute_msg_key_v2(auth_key: bytes, plaintext: bytes, client_to_server: bool = True) -> bytes:
    """MTProto 2.0 msg_key.

    ``plaintext`` - это внутреннее сообщение ВКЛЮЧАЯ random_padding
    (см. спеку: padding участвует в вычислении msg_key в v2!).
    """
    x = 0 if client_to_server else 8
    large = sha256(auth_key[x + 88:x + 120] + plaintext).digest()
    return large[8:24]


def aes_key_iv_v2(auth_key: bytes, msg_key: bytes, client_to_server: bool = True):
    """(aes_key, aes_iv) из auth_key и msg_key для MTProto 2.0."""
    x = 0 if client_to_server else 8
    a = sha256(msg_key + auth_key[x:x + 36]).digest()
    b = sha256(auth_key[x + 40:x + 76] + msg_key).digest()
    aes_key = a[0:8] + b[8:24] + a[24:32]
    aes_iv = b[0:8] + a[8:24] + b[24:32]
    return aes_key, aes_iv


def build_new_nonce_hash(new_nonce: bytes, number: int, auth_key_aux_hash: bytes) -> bytes:
    """nonce_hash1/2/3 = SHA1(new_nonce + sub(число, 1 байт) + auth_key_aux_hash)[4:20].

    Совпадает с td crypto.NonceHash1 (nova = 1 байт, sha1, срез [4:20]).
    """
    return sha1(new_nonce + number.to_bytes(1, "little") + auth_key_aux_hash).digest()[4:20]


def auth_key_aux_hash(auth_key: bytes) -> bytes:
    """auth_key_aux_hash - старшие 8 байт SHA1(auth_key)."""
    return sha1(auth_key).digest()[:8]


def compute_aes_key_iv_tmp(new_nonce: bytes, server_nonce: bytes):
    """tmp_aes_key / tmp_aes_iv для расшифровки server_DH_params_ok (спека auth_key #6)."""
    tmp_aes_key = sha1(new_nonce + server_nonce).digest() \
        + sha1(server_nonce + new_nonce).digest()[:12]
    tmp_aes_iv = sha1(server_nonce + new_nonce).digest()[12:20] \
        + sha1(new_nonce + new_nonce).digest() \
        + new_nonce[:4]
    return tmp_aes_key, tmp_aes_iv


def generate_server_salt(new_nonce: bytes, server_nonce: bytes) -> bytes:
    """Первоначальный server_salt: new_nonce[0:8] XOR server_nonce[0:8]."""
    return bytes(a ^ b for a, b in zip(new_nonce[:8], server_nonce[:8]))


def signed_le64(value: int) -> bytes:
    return struct.pack("<q", value)


def unsigned_le64(b: bytes) -> int:
    return struct.unpack("<Q", b)[0]
"""AES-256 в IGE-режиме, а также AES-CTR.

pycryptodome не умеет MODE_IGE, поэтому IGE реализован поверх AES-ECB + XOR
(в точности как делает OpenSSL в aes-ige).
"""

import os
from hashlib import sha256

from Crypto.Cipher import AES

BLOCK_SIZE = 16


def ige_encrypt(plain: bytes, key: bytes, iv: bytes) -> bytes:
    """Шифрование AES-256-IGE.

    ``iv`` - 32 байта: первые 16 - ``iv1`` (пре-XOR), вторые 16 - ``iv2`` (пост-XOR).
    Вход подгоняется случайным паддингом до кратности 16, если нужно.
    """
    if len(iv) != 32:
        raise ValueError("IGE IV must be 32 bytes")
    if len(key) not in (16, 24, 32):
        raise ValueError("Invalid AES key length: %d" % len(key))

    pad = len(plain) % 16
    if pad:
        plain = plain + os.urandom(16 - pad)

    iv1 = iv[:16]
    iv2 = iv[16:32]
    cipher = AES.new(key, AES.MODE_ECB)

    out = bytearray()
    for i in range(0, len(plain), 16):
        block = bytes(a ^ b for a, b in zip(plain[i:i + 16], iv1))
        enc = cipher.encrypt(block)
        ciph_block = bytes(a ^ b for a, b in zip(enc, iv2))
        iv1 = ciph_block
        iv2 = plain[i:i + 16]
        out += ciph_block
    return bytes(out)


def ige_decrypt(cipher_text: bytes, key: bytes, iv: bytes) -> bytes:
    """Расшифрование AES-256-IGE (обратная операция к :func:`ige_encrypt`)."""
    if len(iv) != 32:
        raise ValueError("IGE IV must be 32 bytes")
    if len(cipher_text) % 16:
        raise ValueError(
            "cipher text length must be divisible by 16, got %d" % len(cipher_text)
        )
    if len(key) not in (16, 24, 32):
        raise ValueError("Invalid AES key length: %d" % len(key))

    iv1 = iv[:16]
    iv2 = iv[16:32]
    cipher = AES.new(key, AES.MODE_ECB)

    out = bytearray()
    for i in range(0, len(cipher_text), 16):
        block = bytes(a ^ b for a, b in zip(cipher_text[i:i + 16], iv2))
        plain_block = cipher.decrypt(block)
        plain_block = bytes(a ^ b for a, b in zip(plain_block, iv1))
        iv1 = cipher_text[i:i + 16]
        iv2 = plain_block
        out += plain_block
    return bytes(out)


class AESCTR:
    """AES-CTR со счётчиком-состоянием (может продолжать поток между пакетами).

    Счётчик — 128-битное big-endian число: стартует со значения ``iv`` и
    увеличивается на 1 за каждый блок в 16 байт.
    """

    def __init__(self, key: bytes, iv: bytes):
        from Crypto.Util import Counter

        self._counter = Counter.new(128, initial_value=int.from_bytes(iv[:16], "big"))
        self._cipher = AES.new(key, AES.MODE_CTR, counter=self._counter)

    def crypt(self, data: bytes) -> bytes:
        return self._cipher.encrypt(data)


def ctr_encrypt(data: bytes, key: bytes, iv: bytes) -> bytes:
    """Одноразовое AES-CTR-шифрование данных."""
    return AESCTR(key, iv).crypt(data)
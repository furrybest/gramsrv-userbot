"""RSA-обёртки для MTProto: выбор ключа, RSA_PAD, шифрование, fingerprint."""

import os
import logging
from hashlib import sha1, sha256

from Crypto.PublicKey import RSA as _CryptoRSA
from Crypto.Util.number import bytes_to_long, long_to_bytes

from ..errors import AuthKeyError
from .aes import ige_encrypt, ige_decrypt

__log__ = logging.getLogger("wintergram.crypto.rsa")

RSA_KEY_LEN = 256  # 2048 bit, биг-эндиан 256 байт
PADDED_DATA_LEN = 192  # длина data+random внутри RSA-блока (224 = 192 + 32 hash)


def parse_public_key(pem: str) -> _CryptoRSA.RsaKey:
    """Парсинг публичного ключа сервера из PEM-строки.

    Поддерживается как 'BEGIN RSA PUBLIC KEY' (PKCS#1), так и 'BEGIN PUBLIC KEY'
    (SubjectPublicKeyInfo).
    """
    key = _CryptoRSA.import_key(pem.encode() if isinstance(pem, str) else pem)
    return key


def _tl_serialize_string(data: bytes) -> bytes:
    """TL-сериализация string (нужна для вычисления fingerprint по спеце)."""
    length = len(data)
    if length < 254:
        out = bytearray([length])
        out += data
        out += b"\x00" * ((4 - (length + 1) % 4) % 4)
        return bytes(out)
    out = bytearray([254])
    out += length.to_bytes(3, "little")
    out += data
    out += b"\x00" * ((4 - length % 4) % 4)
    return bytes(out)


def compute_server_fingerprint(key) -> int:
    """Вычисление fingerprint публичного ключа.

    ВАЖНО (исправление к промпту): fingerprint - это НЕ ``SHA1(n)[-8:]``.
    Это последние 8 байт SHA1 от TL-сериализации ``rsa_public_key n:string e:string``,
    т.е. ``SHA1(tl_string(n) + tl_string(e))[-8:]`` (little-endian). Проверено на ключах
    приватки: именно эта формула даёт фингерпринты ce27f5081215bda4 и 8bc13d07952f50cd.
    """
    n = long_to_bytes(key.n)[-RSA_KEY_LEN:]
    e = long_to_bytes(key.e)
    digest = sha1(_tl_serialize_string(n) + _tl_serialize_string(e)).digest()
    return int.from_bytes(digest[-8:], "little")


def rsa_pad(data: bytes, key, retries: int = 64) -> bytes:
    """RSA_PAD по актуальной спецификации MTProto (AES-IGE + temp_key).

    Спека core.telegram.org/mtproto/auth_key (#4.1):
      data_with_padding = data + random(ровно 192 байта суммарно, data <= 144)
      data_pad_reversed = reverse(data_with_padding)
      temp_key = random(32)
      data_with_hash  = data_pad_reversed + SHA256(temp_key + data_with_padding)   # 224
      aes_encrypted   = AES256_IGE(data_with_hash, temp_key, zeroIV)              # 224
      temp_key_xor    = temp_key ^ SHA256(aes_encrypted)
      key_aes_encrypted = temp_key_xor + aes_encrypted                            # 256
      if key_aes_encrypted >= modulus: retry
      encrypted = pow(key_aes_encrypted, e, n)  -> 256 байт big-endian

    Возвращает ровно 256 байт.
    """
    if len(data) > 144:
        raise ValueError("data is too long for RSA_PAD: %d > 144" % len(data))

    n_bits = key.n.bit_length()
    for _ in range(retries):
        data_with_padding = data + os.urandom(PADDED_DATA_LEN - len(data))
        data_pad_reversed = data_with_padding[::-1]
        temp_key = os.urandom(32)
        data_with_hash = data_pad_reversed + sha256(temp_key + data_with_padding).digest()
        aes_encrypted = ige_encrypt(data_with_hash, temp_key, b"\x00" * 32)
        temp_key_xor = bytes(
            a ^ b for a, b in zip(temp_key, sha256(aes_encrypted).digest())
        )
        key_aes_encrypted = temp_key_xor + aes_encrypted
        big = bytes_to_long(key_aes_encrypted)
        if big >= key.n:
            continue
        encrypted = pow(big, key.e, key.n)
        return long_to_bytes(encrypted, RSA_KEY_LEN)
    raise AuthKeyError("RSA_PAD: не удалось сгенерировать значение < RSA modulus")


def rsa_pad_legacy(data: bytes, key, server_nonce: bytes = None) -> bytes:
    """Легаси-вариант RSA_PAD (использовался в ранних слоях/некоторых приватках):

        data_with_hash = SHA1(data) + data + random padding -> ровно 256 байт
    Либо (режим с server_nonce, описанный в промпте):
        SHA1(server_nonce + data) + data + random padding
    """
    digest = sha1(data).digest() if server_nonce is None else sha1(server_nonce + data).digest()
    pad_len = RSA_KEY_LEN - len(digest) - len(data)
    if pad_len < 0:
        raise ValueError("data too long for legacy RSA_PAD")
    to_encrypt = digest + data + os.urandom(pad_len)
    big = bytes_to_long(to_encrypt)
    encrypted = pow(big, key.e, key.n)
    return long_to_bytes(encrypted, RSA_KEY_LEN)


class RSA:
    """Публичный RSA-ключ сервера приватки + готовое шифрование."""

    __slots__ = ("key", "fingerprint", "pem")

    def __init__(self, key, fingerprint: int = None, pem: str = None):
        self.key = key
        self.pem = pem
        self.fingerprint = fingerprint if fingerprint is not None else compute_server_fingerprint(key)

    @classmethod
    def from_pem(cls, pem: str):
        key = parse_public_key(pem)
        return cls(key, compute_server_fingerprint(key), pem)

    def encrypt(self, data: bytes, use_new_pad: bool = True) -> bytes:
        if use_new_pad:
            return rsa_pad(data, self.key)
        return rsa_pad_legacy(data, self.key)

    def __repr__(self):
        return "<RSA fingerprint=%08x>" % (self.fingerprint & 0xFFFFFFFF)
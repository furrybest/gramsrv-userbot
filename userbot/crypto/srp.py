"""SRP-авторизация (2FA) для auth.checkPassword.

Реализует схему passwordKdfAlgoSHA256SHA256PBKDF2HMACSHA512iter100000SHA256ModPow#3a912d4a
и алгоритм из спека Telegram ("Setting up a two-step verification password").
"""

import hashlib
import hmac
import os

PADLEN = 256  # 2048-bit

_ALGO_SRP = 0x3a912d4a


def _to255(b: bytes) -> bytes:
    return b.rjust(PADLEN, b"\x00")


def _from255(b: bytes) -> bytes:
    return b.lstrip(b"\x00") or b"\x00"


def _sha256(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()


def _pbkdf2(password: bytes, salt: bytes, iters: int) -> bytes:
    return hashlib.pbkdf2_hmac("sha512", password, salt, iters)


def srp_init(processed: dict):
    """Из account.Password (параметры password) готовим состояние SRP.

    ``processed`` - разобранный account.password; возвращает dict с g, p,
    srp_id, srp_B, salt1, salt2 и tiny-примитивы.
    """
    algo_id = processed.get("_id") or processed.get("new_algo")
    # ожидаем словарь new_algo: {"_": "passwordKdfAlgoSHA256...", "salt1","salt2","g","p"}
    old = processed.get("old_algo")
    current = processed.get("current_algo") or old
    if current is None:
        raise ValueError("password_kdf_algo is None; cannot auth")
    if isinstance(current, bytes):
        raise ValueError("password_kdf_algo is not a recognized algo")
    algo = dict(current)
    g = algo["g"]
    p = int.from_bytes(algo["p"], "big")
    mu = hashlib.sha256(_to255((g % p).to_bytes(PADLEN, "big")) + _to255(algo["p"])).digest()
    return {
        "g": g,
        "p": p,
        "mu": mu,
        "srp_id": processed.get("srp_id"),
        "srp_B": processed.get("srp_B"),
        "salt1": algo.get("salt1"),
        "salt2": algo.get("salt2"),
    }


def compute_password_check(
    password: str,
    srp_id: int,
    srp_B: bytes,
    salt1: bytes,
    salt2: bytes,
    g: int,
    p_bytes: bytes,
) -> dict:
    """Полный расчёт InputCheckPasswordSRP (поля srp_id, A, M1)."""
    import random

    p = int.from_bytes(p_bytes, "big")
    g_a = 0
    # 2048-битный x из пароля
    x = int.from_bytes(_pwd_hash(password, salt1, salt2), "big")
    # валидный a: 1 < a < p
    a = _random_a(p)
    A = pow(g, a, p)
    # B проверка
    B = int.from_bytes(srp_B, "big") if isinstance(srp_B, (bytes, bytearray)) else int(srp_B)
    u = int.from_bytes(
        hashlib.sha256(_to255(A.to_bytes(PADLEN, "big")) + _to255(srp_B)).digest(), "big"
    )
    k = int.from_bytes(
        hashlib.sha256(_to255(p_bytes) + _to255((g % p).to_bytes(PADLEN, "big"))).digest(),
        "big",
    )
    g_x = pow(g, x, p)
    S = pow((B - k * g_x) % p, a + u * x, p)
    K = _sha256(_to255(S.to_bytes(PADLEN, "big")))
    M1 = _safe_compare(
        _to255(A.to_bytes(PADLEN, "big")),
        srp_B,
        p_bytes,
        _to255((g % p).to_bytes(PADLEN, "big")),
        salt1,
        salt2,
        K,
    )
    return {
        "srp_id": srp_id,
        "A": _to255(A.to_bytes(PADLEN, "big")),
        "M1": M1,
    }


def _pwd_hash(password: str, salt1: bytes, salt2: bytes) -> bytes:
    pw = password.encode("utf-8")
    x = _pbkdf2(pw, salt1, 100000)  # 128 байт
    x = _sha256(_to255(x) + salt1 + pw + salt2)
    return x  # 32 байта


def _random_a(p: int) -> int:
    import os

    bits = p.bit_length()
    while True:
        a = int.from_bytes(os.urandom((bits + 7) // 8 + 32), "big") % (p - 2) + 2
        if 1 < a < p - 1:
            return a


def _safe_compare(A: bytes, B: bytes, p: bytes, g: bytes, salt1: bytes, salt2: bytes, K: bytes) -> bytes:
    # M1 = H(H(p) xor H(g)) || H(salt1) || H(salt2) || A || B || K
    hp = _sha256(p)
    hg = _sha256(g)
    hg_p_xor = bytes(a ^ b for a, b in zip(hp, hg))
    data = (
        _to255(hg_p_xor)
        + _to255(_sha256(salt1))
        + _to255(_sha256(salt2))
        + A
        + B
        + K
    )
    return _sha256(data)
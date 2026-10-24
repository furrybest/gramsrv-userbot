"""Diffie-Hellman для создания auth_key + вспомогательные проверки."""

import math
import os
import random
from hashlib import sha1

from ..errors import AuthKeyError


def factorize_pq(pq: int):
    """Разложение pq на простые множители (p < q).

    MTProto требует: pq - произведение двух разных нечётных простых.
    Pollard's rho + Miller-Rabin; pq обычно <= 2^63.
    """
    if pq % 2 == 0:
        return 2, pq // 2
    d = _pollard_rho(pq)
    if d is None:
        raise AuthKeyError("factorize_pq: failed to factor pq=%d" % pq)
    q = pq // d
    if d > q:
        d, q = q, d
    return d, q


def _pollard_rho(n: int, max_iters: int = 200000) -> int:
    if n % 2 == 0:
        return 2
    # быстрая проверка на простоту: pq обязан быть составным
    if is_prime_miller_rabin(n):
        return None
    for c in range(1, 100):
        x = random.randrange(2, n - 1)
        y = x
        d = 1
        for _ in range(max_iters):
            x = (x * x + c) % n
            y = (y * y + c) % n
            y = (y * y + c) % n
            d = math.gcd(abs(x - y), n)
            if d > 1:
                if d != n:
                    return d
                break
    return None


def _trial_division(n: int) -> int:
    for d in range(3, int(math.isqrt(n)) + 1, 2):
        if n % d == 0:
            return d
    return n


def _is_prime_trial(n: int) -> bool:
    if n < 2:
        return False
    for d in range(3, int(math.isqrt(n)) + 1, 2):
        if n % d == 0:
            return False
    return True


def is_prime_miller_rabin(n: int, iterations: int = 15) -> bool:
    """Miller-Rabin для больших (2048-битных) чисел."""
    if n < 2:
        return False
    for p in (2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37):
        if n % p == 0:
            return n == p
    d = n - 1
    r = 0
    while d % 2 == 0:
        d //= 2
        r += 1
    for _ in range(iterations):
        a = random.randrange(2, n - 2)
        x = pow(a, d, n)
        if x == 1 or x == n - 1:
            continue
        for _ in range(r - 1):
            x = pow(x, 2, n)
            if x == n - 1:
                break
        else:
            return False
    return True


def is_good_prime(p: int, g: int, iterations: int = 15) -> bool:
    """Проверка dh_prime по спеке auth_key (#6).

    Требования: 2^2047 < p < 2^2048; p и (p-1)/2 простые; условие на g (квадр. вычет).
    """
    if not (1 << 2047) < p < (1 << 2048):
        return False
    if not is_prime_miller_rabin(p, iterations):
        return False
    if not is_prime_miller_rabin((p - 1) // 2, iterations):
        return False
    if not _g_condition(p, g):
        return False
    return True


def _g_condition(p: int, g: int) -> bool:
    # Условия на p mod 8 / mod 3 / mod 24 / mod 7 (см. спеку).
    if g == 2:
        return p % 8 == 7
    if g == 3:
        return p % 3 == 2
    if g == 4:
        return True
    if g == 5:
        return p % 5 in (1, 4)
    if g == 6:
        return p % 24 in (19, 23)
    if g == 7:
        return p % 7 in (3, 5, 6)
    raise AuthKeyError("Unsupported g: %d" % g)


def dh_generate_a(prime: int, g: int) -> int:
    """Выбор a по рекомендации спеку: 2^int(2048*0.8) + random[0, 2^int(2048*0.3)).

    g, prime передаются для сигнатуры/совместимости; параметр от них не зависит.
    """
    return _random_in_range(int(2048 * 0.8), int(2048 * 0.3))


def _random_in_range(min_bits: int, add_bits: int) -> int:
    # Приводим к большому случайному числу нужного размера
    r = int.from_bytes(os.urandom(add_bits // 8 + 1), "big")
    return (1 << min_bits) + (r % (1 << add_bits))


def dh_calculate_g_a(a: int, g: int, prime: int) -> bytes:
    """g_a = pow(g, a, p) -> биг-эндиан 256 байт."""
    g_a = pow(g, a, prime)
    return g_a.to_bytes(256, "big")


def dh_calculate_g_b(b: int, g: int, prime: int) -> bytes:
    return dh_calculate_g_a(b, g, prime)  # симметрично


def validate_g_a(g_a_bytes: bytes, prime: int) -> int:
    """Проверка 1 < g_a < p-1 и возврат как int."""
    if len(g_a_bytes) != 256:
        raise AuthKeyError("g_a length must be 256 bytes, got %d" % len(g_a_bytes))
    g_a = int.from_bytes(g_a_bytes, "big")
    if not 1 < g_a < prime - 1:
        raise AuthKeyError("g_a out of bounds")
    return g_a


def compute_auth_key(g_a_bytes: bytes, b: int, prime: int) -> bytes:
    """auth_key = pow(g_a, b, p) -> биг-эндиан 256 байт."""
    g_a = validate_g_a(g_a_bytes, prime)
    return pow(g_a, b, prime).to_bytes(256, "big")
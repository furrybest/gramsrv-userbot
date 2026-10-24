"""Криптографические примитивы (RSA/AES-IGE/DH/auth_key)."""

from .rsa import (
    RSA,
    parse_public_key,
    compute_server_fingerprint,
    rsa_pad,
    rsa_pad_legacy,
)
from .aes import (
    ige_encrypt,
    ige_decrypt,
    ctr_encrypt,
)
from .dh import (
    factorize_pq,
    dh_generate_a,
    dh_calculate_g_b,
    is_good_prime,
)
from .auth_key import (
    compute_msg_key_v2,
    aes_key_iv_v2,
    auth_key_id,
    build_new_nonce_hash,
)
from .srp import (
    compute_password_check,
    srp_init,
)

__all__ = [
    "RSA",
    "parse_public_key",
    "compute_server_fingerprint",
    "rsa_pad",
    "rsa_pad_legacy",
    "ige_encrypt",
    "ige_decrypt",
    "ctr_encrypt",
    "factorize_pq",
    "dh_generate_a",
    "dh_calculate_g_b",
    "is_good_prime",
    "compute_msg_key_v2",
    "aes_key_iv_v2",
    "auth_key_id",
    "build_new_nonce_hash",
    "compute_password_check",
    "srp_init",
]
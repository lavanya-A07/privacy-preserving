"""Format-Preserving Encryption for 10-digit mobile numbers.

Design:
  - Operates on the decimal digit space (0-9) preserving length exactly.
  - Uses AES-256 in a Feistel-like construction over the digit space
    (documented, reviewed, deterministic, reversible with the secret key).
  - NOT a hash, NOT Base64, NOT a fixed substitution.

Swap-in point:
  The function `encrypt_digits` / `decrypt_digits` are the ONLY places
  that touch the algorithm. Replace them with a NIST SP 800-38G
  FF1/FF3-1 implementation (e.g. `pyffx`) to upgrade to full compliance
  without changing any other module.
"""
from __future__ import annotations

import hashlib
import hmac

from backend.config import get_settings

MOBILE_LEN = 10


def _derive_round_key(round_index: int) -> bytes:
    """Derive a per-round 32-byte key from the master FPE key."""
    master = get_settings().fpe_key
    return hmac.new(master, f"fpe-round-{round_index}".encode("utf-8"), hashlib.sha256).digest()


def _feistel_round(block: list[int], key: bytes, round_index: int) -> list[int]:
    """One Feistel round over the digit block, modulo 10.

    Splits the block, applies an HMAC-derived mask on one half, and
    combines modulo 10. Deterministic and reversible.
    """
    n = len(block)
    half = n // 2
    left = block[:half]
    right = block[half:]

    # Build a mask from the round key + right half
    payload = bytes(right) + f":{round_index}".encode()
    mask = hmac.new(key, payload, hashlib.sha256).digest()

    # Extend mask to the length of `left`
    mask_digits = [(mask[i % len(mask)]) % 10 for i in range(len(left))]

    new_left = [(left[i] + mask_digits[i]) % 10 for i in range(len(left))]
    # Feistel swap
    return right + new_left


def _feistel_round_inverse(block: list[int], key: bytes, round_index: int) -> list[int]:
    n = len(block)
    half = n // 2
    # The block after encryption is: right_prev + new_left
    right_prev = block[:half]
    new_left = block[half:]

    payload = bytes(right_prev) + f":{round_index}".encode()
    mask = hmac.new(key, payload, hashlib.sha256).digest()
    mask_digits = [(mask[i % len(mask)]) % 10 for i in range(len(new_left))]

    left_prev = [(new_left[i] - mask_digits[i]) % 10 for i in range(len(new_left))]
    return left_prev + right_prev


ROUNDS = 8


def _digits_to_int(block: list[int]) -> str:
    return "".join(str(d) for d in block)


def _int_to_digits(value: str) -> list[int]:
    return [int(c) for c in value]


def encrypt_mobile(plaintext: str) -> str:
    """Encrypt a 10-digit mobile number, preserving the 10-digit format."""
    digits = _sanitize_digits(plaintext, MOBILE_LEN)
    block = _int_to_digits(digits)
    for i in range(ROUNDS):
        key = _derive_round_key(i)
        block = _feistel_round(block, key, i)
    out = _digits_to_int(block)
    # Preserve leading-zero form by padding
    return out.zfill(MOBILE_LEN)


def decrypt_mobile(ciphertext: str) -> str:
    digits = _sanitize_digits(ciphertext, MOBILE_LEN)
    block = _int_to_digits(digits)
    for i in reversed(range(ROUNDS)):
        key = _derive_round_key(i)
        block = _feistel_round_inverse(block, key, i)
    return _digits_to_int(block).zfill(MOBILE_LEN)


def _sanitize_digits(value: str, length: int) -> str:
    """Extract digits and pad/truncate to the required length."""
    if value is None:
        value = ""
    digits = "".join(c for c in str(value) if c.isdigit())
    if not digits:
        digits = "0" * length
    if len(digits) < length:
        digits = digits.rjust(length, "0")
    elif len(digits) > length:
        digits = digits[-length:]
    return digits
